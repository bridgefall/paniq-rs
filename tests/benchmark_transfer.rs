//! End-to-end transfer speed benchmark.
//!
//! Measures actual throughput through the full proxy stack (SOCKS5 -> KCP -> proxy -> target).
//! This is useful for validating performance optimizations and comparing with the Go implementation.

#![cfg(feature = "socks5")]
#![cfg(feature = "kcp")]

mod support;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

use support::StackHarness;

/// Test file sizes for benchmarking (in bytes)
const BYTES_PER_MB: usize = 1024 * 1024;
const TEST_SIZE_SMALL: usize = 10 * BYTES_PER_MB; // 10 MB
const TEST_SIZE_MEDIUM: usize = 50 * BYTES_PER_MB; // 50 MB
const TEST_SIZE_LARGE: usize = 100 * BYTES_PER_MB; // 100 MB

/// Connection timeout for benchmark tests
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Transfer timeout (per MB) - should complete much faster than this
const TRANSFER_TIMEOUT_PER_MB: Duration = Duration::from_secs(5);

/// Generate test data - patterned bytes to avoid compression artifacts
fn generate_test_data(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let mut byte = 0u8;
    for _ in 0..size {
        data.push(byte);
        byte = byte.wrapping_add(1);
    }
    data
}

/// HTTP server that serves a fixed-size test file
async fn start_http_server(data: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let content_len = data.len();

    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.set_nodelay(true);
                let data_clone = data.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    if let Ok(n) = socket.read(&mut buf).await {
                        let request = String::from_utf8_lossy(&buf[..n]);
                        if request.contains("GET") && request.contains("HTTP") {
                            let header = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                                content_len
                            );
                            let _ = socket.write_all(header.as_bytes()).await;
                            let _ = socket.write_all(&data_clone).await;
                            let _ = socket.shutdown().await;
                        }
                    }
                });
            }
        }
    });

    (addr, handle)
}

/// SOCKS5 client that connects through the proxy and downloads data
async fn socks5_download(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    expected_bytes: usize,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let mut socks_conn = timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(socks_addr))
        .await
        .map_err(|_| "SOCKS connect timeout")??;
    socks_conn.set_nodelay(true)?;

    // SOCKS5 handshake with auth
    socks_conn.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    let mut resp = [0u8; 2];
    socks_conn.read_exact(&mut resp).await?;
    if resp != [0x05, 0x02] {
        return Err(format!("Unexpected auth response: {:?}", resp).into());
    }

    // Username/password auth
    let mut auth_msg = vec![0x01];
    auth_msg.push(4u8);
    auth_msg.extend_from_slice(b"user");
    auth_msg.push(4u8);
    auth_msg.extend_from_slice(b"pass");
    socks_conn.write_all(&auth_msg).await?;
    socks_conn.read_exact(&mut resp).await?;
    if resp != [0x01, 0x00] {
        return Err(format!("Auth failed: {:?}", resp).into());
    }

    // CONNECT request
    let mut connect_req = vec![0x05, 0x01, 0x00];
    match target_addr.ip() {
        std::net::IpAddr::V4(ipv4) => {
            connect_req.push(0x01);
            connect_req.extend_from_slice(&ipv4.octets());
        }
        std::net::IpAddr::V6(ipv6) => {
            connect_req.push(0x04);
            connect_req.extend_from_slice(&ipv6.octets());
        }
    }
    connect_req.extend_from_slice(&target_addr.port().to_be_bytes());
    socks_conn.write_all(&connect_req).await?;

    // Read CONNECT response - first 4 bytes
    let mut connect_resp = [0u8; 4];
    socks_conn.read_exact(&mut connect_resp).await?;
    if connect_resp[1] != 0x00 {
        return Err(format!("CONNECT failed: {:?}", connect_resp).into());
    }

    // Skip the rest of the SOCKS reply (bound address)
    match connect_resp[3] {
        0x01 => {
            // IPv4: 4 bytes addr + 2 bytes port
            let mut _buf = [0u8; 6];
            socks_conn.read_exact(&mut _buf).await?;
        }
        0x03 => {
            // Domain: 1 byte length + domain + 2 bytes port
            let mut len_buf = [0u8; 1];
            socks_conn.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut _buf = vec![0u8; len + 2];
            socks_conn.read_exact(&mut _buf).await?;
        }
        0x04 => {
            // IPv6: 16 bytes addr + 2 bytes port
            let mut _buf = [0u8; 18];
            socks_conn.read_exact(&mut _buf).await?;
        }
        _ => return Err(format!("Unknown address type: {}", connect_resp[3]).into()),
    }

    // Send HTTP GET request
    let http_req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target_addr.ip()
    );
    socks_conn.write_all(http_req.as_bytes()).await?;

    // Read HTTP headers first
    let mut header_buf = vec![0u8; 8192];
    let mut header_pos = 0;
    let headers_deadline = Instant::now() + CONNECT_TIMEOUT;
    let headers_end = loop {
        let remaining = headers_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("Header timeout".into());
        }
        let n = timeout(remaining, socks_conn.read(&mut header_buf[header_pos..]))
            .await
            .map_err(|_| "Header timeout")??;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected EOF while reading headers",
            )
            .into());
        }
        header_pos += n;
        let header_text = String::from_utf8_lossy(&header_buf[..header_pos]);
        if let Some(idx) = header_text.find("\r\n\r\n") {
            break idx + 4;
        }
        if header_pos >= header_buf.len() {
            header_buf.resize(header_buf.len() * 2, 0);
        }
    };

    // Skip headers
    let mut data = Vec::with_capacity(expected_bytes);
    if headers_end < header_pos {
        data.extend_from_slice(&header_buf[headers_end..header_pos]);
    }

    // Read response body
    let mb = (expected_bytes + (BYTES_PER_MB - 1)) / BYTES_PER_MB;
    let soft_deadline = Instant::now() + TRANSFER_TIMEOUT_PER_MB * mb as u32;
    let mut warned = false;
    while data.len() < expected_bytes {
        let n = timeout(CONNECT_TIMEOUT, socks_conn.read(&mut header_buf))
            .await
            .map_err(|_| "Transfer timeout")??;

        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unexpected EOF during transfer",
            )
            .into());
        }
        data.extend_from_slice(&header_buf[..n]);
        let now = Instant::now();
        if !warned && now > soft_deadline {
            eprintln!(
                "WARNING: Transfer exceeded expected timeout of {:?}",
                TRANSFER_TIMEOUT_PER_MB * mb as u32
            );
            warned = true;
        }
    }

    Ok(data.len())
}

/// Run a single benchmark iteration
async fn benchmark_iteration(
    harness: &StackHarness,
    http_addr: SocketAddr,
    data_size: usize,
) -> Result<(Duration, usize), Box<dyn std::error::Error + Send + Sync>> {
    let start = Instant::now();
    let bytes_read = socks5_download(harness.socks_addr(), http_addr, data_size).await?;
    let elapsed = start.elapsed();

    if bytes_read != data_size {
        return Err(format!(
            "Data size mismatch: expected {}, got {}",
            data_size, bytes_read
        )
        .into());
    }

    Ok((elapsed, bytes_read))
}

/// Run benchmark with multiple iterations and report statistics
async fn run_benchmark(
    name: &str,
    data_size: usize,
    iterations: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("\n=== {} Benchmark ===", name);
    println!("Test size: {:.2} MB", data_size as f64 / 1024.0 / 1024.0);
    println!("Iterations: {}", iterations);

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

    // Start HTTP server with test data
    let test_data = generate_test_data(data_size);
    let (http_addr, http_handle) = start_http_server(test_data).await;

    // Spawn proxy stack
    let harness = StackHarness::spawn(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await?;

    // Give servers time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut results = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let result = match benchmark_iteration(&harness, http_addr, data_size).await {
            Ok((elapsed, bytes)) => {
                let throughput_mb_s = (bytes as f64 / 1024.0 / 1024.0) / elapsed.as_secs_f64();
                println!(
                    "  Iteration {}/{}: {:.2} MB in {:.2}s = {:.2} MB/s",
                    i + 1,
                    iterations,
                    bytes as f64 / 1024.0 / 1024.0,
                    elapsed.as_secs_f64(),
                    throughput_mb_s
                );
                Some((elapsed, bytes))
            }
            Err(e) => {
                eprintln!("  Iteration {}/{} FAILED: {}", i + 1, iterations, e);
                None
            }
        };
        if let Some(r) = result {
            results.push(r);
        }

        // Small delay between iterations
        if i < iterations - 1 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // Calculate statistics
    if !results.is_empty() {
        let total_bytes: usize = results.iter().map(|(_, b)| b).sum();
        let total_duration: Duration = results.iter().map(|(d, _)| *d).sum();
        let avg_throughput = (total_bytes as f64 / 1024.0 / 1024.0) / total_duration.as_secs_f64();

        let min_duration = results.iter().map(|(d, _)| d).min().unwrap();
        let max_duration = results.iter().map(|(d, _)| d).max().unwrap();

        println!("\nResults:");
        println!(
            "  Total transferred: {:.2} MB",
            total_bytes as f64 / 1024.0 / 1024.0
        );
        println!("  Average throughput: {:.2} MB/s", avg_throughput);
        println!("  Min iteration time: {:.2}s", min_duration.as_secs_f64());
        println!("  Max iteration time: {:.2}s", max_duration.as_secs_f64());

        // Performance assertions (adjust based on your expectations)
        let min_expected_throughput = 10.0; // 10 MB/s minimum
        if avg_throughput < min_expected_throughput {
            eprintln!(
                "\nWARNING: Average throughput ({:.2} MB/s) is below expected minimum ({:.2} MB/s)",
                avg_throughput, min_expected_throughput
            );
        }
    } else {
        return Err("All iterations failed".into());
    }

    // Cleanup
    drop(harness);
    http_handle.abort();

    Ok(())
}

#[tokio::test]
#[ignore] // Run this manually: cargo test --release --features kcp,socks5 benchmark_transfer_small -- --ignored
async fn benchmark_transfer_small() {
    run_benchmark("Small File Transfer", TEST_SIZE_SMALL, 3)
        .await
        .expect("Benchmark failed");
}

#[tokio::test]
async fn benchmark_transfer_medium() {
    run_benchmark("Medium File Transfer", TEST_SIZE_MEDIUM, 3)
        .await
        .expect("Benchmark failed");
}

#[tokio::test]
#[ignore] // Run this manually: cargo test --release --features kcp,socks5 benchmark_transfer_large -- --ignored
async fn benchmark_transfer_large() {
    run_benchmark("Large File Transfer", TEST_SIZE_LARGE, 3)
        .await
        .expect("Benchmark failed");
}

/// Quick smoke test - single iteration with small file
#[tokio::test]
async fn benchmark_smoke() {
    run_benchmark("Smoke Test", 1024 * 1024, 1)
        .await
        .expect("Benchmark failed");
}
