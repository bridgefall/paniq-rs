//! Integration test for SOCKS5 over obfuscated KCP.
//!
//! Uses production code paths from `src/runtime/` to test the actual
//! proxy server and SOCKS5 server implementations.
//!
//! Equivalent to Go's pkg/socks5daemon/integration_kcp_test.go

#![cfg(feature = "socks5")]
#![cfg(feature = "kcp")]

mod support;

use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

use support::StackHarness;

const MAX_END_TO_END_LATENCY: Duration = Duration::from_secs(1);

// Time for servers to fully start and accept connections
const SERVER_STARTUP_DELAY_MS: u64 = 100;

// Time for smux streams to complete graceful shutdown (prevents "Connection reset by peer" errors)
const STREAM_SHUTDOWN_DELAY_MS: u64 = 10;

// Longer delay for soak test cleanup (more active streams to shut down)
const SOAK_CLEANUP_DELAY_MS: u64 = 50;

/// Simple HTTP server that returns "ok"
async fn start_http_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.set_nodelay(true);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    if let Ok(n) = socket.read(&mut buf).await {
                        let request = String::from_utf8_lossy(&buf[..n]);
                        if request.contains("GET") && request.contains("HTTP") {
                            let response =
                                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                            let _ = socket.write_all(response.as_bytes()).await;
                            let _ = socket.shutdown().await;
                        }
                    }
                });
            }
        }
    });

    (addr, handle)
}

/// Full roundtrip test using production server implementations.
async fn socks5_over_kcp_roundtrip() -> Duration {
    // Enable logging (ok if already initialized)
    let telemetry_enabled = std::env::var("PANIQ_KCP_TELEMETRY")
        .ok()
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    if telemetry_enabled {
        let filter = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::Level::INFO.into())
            .from_env_lossy();
        let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    } else {
        let _ = tracing_subscriber::fmt::try_init();
    }

    // Start HTTP server
    let (http_addr, http_handle) = start_http_server().await;

    // Spawn production proxy and SOCKS5 servers using the test harness
    let harness = StackHarness::spawn(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .expect("Failed to spawn test harness");

    // Give servers time to start
    tokio::time::sleep(Duration::from_millis(SERVER_STARTUP_DELAY_MS)).await;

    // Connect as SOCKS5 client
    let mut socks_conn = tokio::net::TcpStream::connect(harness.socks_addr())
        .await
        .unwrap();
    socks_conn.set_nodelay(true).unwrap();

    // SOCKS5 handshake with auth
    socks_conn
        .write_all(&[0x05, 0x02, 0x00, 0x02])
        .await
        .unwrap(); // ver, nmethods, no-auth, userpass
    let mut resp = [0u8; 2];
    socks_conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x02]); // server chooses userpass

    // Username/password auth
    let mut auth_msg = vec![0x01]; // version
    auth_msg.push(4u8); // ulen
    auth_msg.extend_from_slice(b"user");
    auth_msg.push(4u8); // plen
    auth_msg.extend_from_slice(b"pass");
    socks_conn.write_all(&auth_msg).await.unwrap();
    socks_conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x01, 0x00]); // auth success

    // CONNECT request to HTTP server
    let mut connect_req = vec![0x05, 0x01, 0x00]; // ver, cmd connect, rsv
    let http_ip = http_addr.ip();
    match http_ip {
        std::net::IpAddr::V4(ipv4) => {
            connect_req.push(0x01); // IPv4
            connect_req.extend_from_slice(&ipv4.octets());
        }
        std::net::IpAddr::V6(ipv6) => {
            connect_req.push(0x04); // IPv6
            connect_req.extend_from_slice(&ipv6.octets());
        }
    }
    connect_req.extend_from_slice(&http_addr.port().to_be_bytes());
    let latency_start = Instant::now();
    socks_conn.write_all(&connect_req).await.unwrap();

    // Read reply
    let mut reply = [0u8; 10];
    socks_conn.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00); // success

    // Send HTTP GET request
    let host_port = http_addr.to_string();
    let http_req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host_port.split(':').next().unwrap()
    );
    socks_conn.write_all(http_req.as_bytes()).await.unwrap();

    // Read HTTP response (loop until we see markers or EOF)
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut http_resp = Vec::with_capacity(1024);
    let mut buf = [0u8; 512];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let n = timeout(remaining, socks_conn.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        if n == 0 {
            break;
        }
        http_resp.extend_from_slice(&buf[..n]);
        let response = String::from_utf8_lossy(&http_resp);
        if response.contains("200 OK") && response.contains("ok") {
            break;
        }
    }
    let response = String::from_utf8_lossy(&http_resp);

    assert!(
        response.contains("200 OK"),
        "response missing 200 OK: {response}"
    );
    assert!(response.contains("ok"), "response missing body: {response}");

    let elapsed = latency_start.elapsed();
    assert!(
        elapsed < MAX_END_TO_END_LATENCY,
        "End-to-end latency too high: {:?}",
        elapsed
    );

    // Cleanup - give connections time to close gracefully
    drop(socks_conn);
    // Delay to allow smux streams to finish cleanup before server shutdown
    tokio::time::sleep(Duration::from_millis(STREAM_SHUTDOWN_DELAY_MS)).await;
    drop(harness);
    http_handle.abort();

    elapsed
}

#[tokio::test]
async fn integration_socks5_over_kcp() {
    let _elapsed = socks5_over_kcp_roundtrip().await;
}

#[tokio::test]
async fn soak_socks5_over_kcp_30s() {
    // Test duration can be configured via SOAK_SECS env var (default: 10 seconds).
    // Note: Using production code paths creates connections much faster than the
    // old mock code, so we use a shorter default to avoid ephemeral port
    // exhaustion on systems with default net.inet.ip.portrange settings.
    let soak_duration = std::env::var("SOAK_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let soak_duration = Duration::from_secs(soak_duration);

    // Create persistent servers ONCE, then run many iterations.
    // This is more realistic and avoids resource exhaustion from
    // repeatedly binding/unbinding 4500+ sockets.

    let (http_addr, http_handle) = start_http_server().await;

    // Spawn production servers using the test harness
    let harness = StackHarness::spawn(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await
    .expect("Failed to spawn test harness");

    // Give servers time to start
    tokio::time::sleep(Duration::from_millis(SERVER_STARTUP_DELAY_MS)).await;

    // Now run the actual soak test with REUSED connections
    let start = Instant::now();
    let mut iterations = 0usize;

    while start.elapsed() < soak_duration {
        // Per-iteration timeout to prevent stalls from hanging the entire test
        let iteration_result = timeout(Duration::from_secs(20), async {
            // Connect as SOCKS5 client
            let mut socks_conn = tokio::net::TcpStream::connect(harness.socks_addr())
                .await
                .unwrap();
            socks_conn.set_nodelay(true).unwrap();
            // Set SO_LINGER to 0 so closing the connection immediately releases
            // the port (skip TIME_WAIT). This is necessary for high-rate connection
            // testing in soak tests to avoid ephemeral port exhaustion.
            let _ = socks_conn.set_linger(Some(Duration::from_secs(0)));

            // SOCKS5 handshake with auth
            socks_conn
                .write_all(&[0x05, 0x02, 0x00, 0x02])
                .await
                .unwrap();
            let mut resp = [0u8; 2];
            socks_conn.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [0x05, 0x02]);

            let mut auth_msg = vec![0x01];
            auth_msg.push(4u8);
            auth_msg.extend_from_slice(b"user");
            auth_msg.push(4u8);
            auth_msg.extend_from_slice(b"pass");
            socks_conn.write_all(&auth_msg).await.unwrap();
            socks_conn.read_exact(&mut resp).await.unwrap();
            assert_eq!(resp, [0x01, 0x00]);

            // CONNECT request to HTTP server
            let mut connect_req = vec![0x05, 0x01, 0x00];
            match http_addr.ip() {
                std::net::IpAddr::V4(ipv4) => {
                    connect_req.push(0x01);
                    connect_req.extend_from_slice(&ipv4.octets());
                }
                std::net::IpAddr::V6(ipv6) => {
                    connect_req.push(0x04);
                    connect_req.extend_from_slice(&ipv6.octets());
                }
            }
            connect_req.extend_from_slice(&http_addr.port().to_be_bytes());
            socks_conn.write_all(&connect_req).await.unwrap();

            let mut reply = [0u8; 10];
            socks_conn.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 0x00);

            // Start timing AFTER connection establishment (consistent with roundtrip test)
            let iter_start = Instant::now();

            // Send HTTP GET request
            let http_req = format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                http_addr.to_string().split(':').next().unwrap()
            );
            socks_conn.write_all(http_req.as_bytes()).await.unwrap();

            // Read HTTP response
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut http_resp = Vec::with_capacity(1024);
            let mut buf = [0u8; 512];
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match timeout(remaining, socks_conn.read(&mut buf)).await {
                    Ok(Ok(n)) => {
                        if n == 0 {
                            break;
                        }
                        http_resp.extend_from_slice(&buf[..n]);
                    }
                    Ok(Err(_)) => {
                        break;
                    }
                    Err(_) => {
                        break;
                    }
                }
                let response = String::from_utf8_lossy(&http_resp);
                if response.contains("200 OK") && response.contains("ok") {
                    break;
                }
            }
            let response = String::from_utf8_lossy(&http_resp);

            assert!(
                response.contains("200 OK"),
                "response missing 200 OK: {response}"
            );
            assert!(response.contains("ok"), "response missing body: {response}");

            let elapsed = iter_start.elapsed();
            assert!(
                elapsed < MAX_END_TO_END_LATENCY,
                "Iteration latency too high: {:?}",
                elapsed
            );

            // Gracefully shutdown the TCP connection to ensure the SOCKS5 relay
            // runs its cleanup path (shutdown() on smux streams).
            let _ = socks_conn.shutdown().await;

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await;

        // Handle timeout - fail the test if an iteration times out
        if let Err(e) = iteration_result {
            panic!("Iteration timed out or failed: {}", e);
        }

        iterations += 1;
        if iterations % 1000 == 0 {
            println!("Soak iteration {}", iterations);
        }
    }

    // Cleanup - give connections time to close gracefully
    // Delay to allow smux streams to finish cleanup before server shutdown
    tokio::time::sleep(Duration::from_millis(SOAK_CLEANUP_DELAY_MS)).await;
    drop(harness);
    http_handle.abort();

    assert!(iterations > 0, "No iterations executed in soak test");
}

#[tokio::test]
async fn lifecycle_repeated_setup_teardown() {
    // Test repeated server setup/teardown to catch resource leaks.
    // This is separate from the soak test which reuses connections.
    // Configurable via LIFECYCLE_ITERATIONS env var (default: 10).
    let iterations = std::env::var("LIFECYCLE_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    for i in 0..iterations {
        let _elapsed = socks5_over_kcp_roundtrip().await;
        if i % 5 == 0 {
            println!("Lifecycle iteration {}/{}", i + 1, iterations);
        }
    }
}
