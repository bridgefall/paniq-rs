//! CPU-intensive profiling benchmark for the proxy server.
//!
//! This test is designed to be run under a profiler (flamegraph, samply, perf)
//! to identify CPU hotspots in the proxy stack.
//!
//! Run with:
//!   cargo build --release --test profile_benchmark --features kcp,socks5
//!   samply record -- ./target/release/deps/profile_benchmark-* profile_high_throughput --nocapture
//!
//! Or:
//!   cargo flamegraph --test profile_benchmark --features kcp,socks5 -- profile_high_throughput --nocapture

#![cfg(feature = "socks5")]
#![cfg(feature = "kcp")]

mod support;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use paniq::profile::Profile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use support::StackHarness;

/// Test parameters for profiling
const BYTES_PER_MB: usize = 1024 * 1024;
const PROFILE_TRANSFER_SIZE: usize = 100 * BYTES_PER_MB; // 100 MB per stream
const CONCURRENT_STREAMS: usize = 4;
const PROFILE_DURATION_SECS: u64 = 30;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

fn load_profile() -> Result<Profile, Box<dyn std::error::Error + Send + Sync>> {
    let profile_path = std::env::var("PANIQ_BENCH_PROFILE").unwrap_or_else(|_| {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("examples");
        path.push("profile.json");
        path.to_string_lossy().to_string()
    });
    Profile::from_file(profile_path)
}

/// Generate patterned test data to avoid compression artifacts
fn generate_test_data(size: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    let mut byte = 0u8;
    for _ in 0..size {
        data.push(byte);
        byte = byte.wrapping_add(1);
    }
    data
}

/// HTTP server that serves test data continuously
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
    bytes_transferred: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut socks_conn =
        tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(socks_addr))
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

    // CONNECT request (IPv4)
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x01];
    if let std::net::IpAddr::V4(ipv4) = target_addr.ip() {
        connect_req.extend_from_slice(&ipv4.octets());
    } else {
        return Err("Only IPv4 supported in this test".into());
    }
    connect_req.extend_from_slice(&target_addr.port().to_be_bytes());
    socks_conn.write_all(&connect_req).await?;

    // Read CONNECT response
    let mut connect_resp = [0u8; 10]; // VER + REP + RSV + ATYP + 4-byte addr + 2-byte port
    socks_conn.read_exact(&mut connect_resp).await?;
    if connect_resp[1] != 0x00 {
        return Err(format!("CONNECT failed: {:?}", connect_resp).into());
    }

    // Send HTTP GET request
    let http_req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target_addr.ip()
    );
    socks_conn.write_all(http_req.as_bytes()).await?;

    // Read and discard headers
    let mut buf = vec![0u8; 32 * 1024];
    let mut header_buf = Vec::new();
    let headers_end;
    loop {
        let n = socks_conn.read(&mut buf).await?;
        if n == 0 {
            return Err("EOF before headers".into());
        }
        header_buf.extend_from_slice(&buf[..n]);
        if let Some(idx) = String::from_utf8_lossy(&header_buf).find("\r\n\r\n") {
            headers_end = idx + 4;
            break;
        }
    }

    // Count remaining bytes from header_buf
    let mut total = (header_buf.len() - headers_end) as u64;
    bytes_transferred.fetch_add(total, Ordering::Relaxed);

    // Read body
    while total < expected_bytes as u64 {
        match socks_conn.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                bytes_transferred.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(_) => break,
        }
    }

    Ok(())
}

/// Run a single transfer stream in a loop
async fn transfer_loop(
    socks_addr: SocketAddr,
    http_addr: SocketAddr,
    data_size: usize,
    bytes_transferred: Arc<AtomicU64>,
    stop_signal: tokio::sync::watch::Receiver<bool>,
) {
    let stop_rx = stop_signal;
    loop {
        // Check if we should stop
        if *stop_rx.borrow() {
            break;
        }

        // Perform a transfer
        let result =
            socks5_download(socks_addr, http_addr, data_size, bytes_transferred.clone()).await;

        if let Err(e) = result {
            eprintln!("Transfer error: {}", e);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Yield to check stop signal
        tokio::task::yield_now().await;
    }
}

/// High-throughput profiling benchmark
///
/// This test runs multiple concurrent streams for a fixed duration,
/// maximizing CPU usage for profiling.
#[tokio::test]
async fn profile_high_throughput() {
    println!("\n=== High-Throughput Profiling Benchmark ===");
    println!(
        "Transfer size: {} MB per stream",
        PROFILE_TRANSFER_SIZE / BYTES_PER_MB
    );
    println!("Concurrent streams: {}", CONCURRENT_STREAMS);
    println!("Duration: {} seconds", PROFILE_DURATION_SECS);
    println!();

    // Initialize tracing (optional for profiling)
    let _ = tracing_subscriber::fmt::try_init();

    // Start HTTP server with test data
    let test_data = generate_test_data(PROFILE_TRANSFER_SIZE);
    let (http_addr, _http_handle) = start_http_server(test_data).await;

    // Spawn proxy stack
    let profile = load_profile().expect("Failed to load profile");
    let harness = StackHarness::spawn_with_profile(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        profile,
    )
    .await
    .expect("Failed to spawn harness");

    // Give servers time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    let bytes_transferred = Arc::new(AtomicU64::new(0));
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

    // Spawn concurrent transfer tasks
    let mut handles = Vec::new();
    for i in 0..CONCURRENT_STREAMS {
        let bytes = bytes_transferred.clone();
        let stop = stop_rx.clone();
        let socks_addr = harness.socks_addr();
        let http = http_addr;
        handles.push(tokio::spawn(async move {
            println!("Stream {} started", i);
            transfer_loop(socks_addr, http, PROFILE_TRANSFER_SIZE, bytes, stop).await;
            println!("Stream {} stopped", i);
        }));
    }

    // Run for specified duration
    let start = Instant::now();
    let mut last_bytes = 0u64;
    while start.elapsed() < Duration::from_secs(PROFILE_DURATION_SECS) {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let current_bytes = bytes_transferred.load(Ordering::Relaxed);
        let delta = current_bytes - last_bytes;
        let throughput = delta as f64 / BYTES_PER_MB as f64;
        println!(
            "  [{:>3}s] Throughput: {:.2} MB/s, Total: {:.2} MB",
            start.elapsed().as_secs(),
            throughput,
            current_bytes as f64 / BYTES_PER_MB as f64
        );
        last_bytes = current_bytes;
    }

    // Stop all streams
    let _ = stop_tx.send(true);

    // Wait for tasks to finish
    for handle in handles {
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }

    // Report final statistics
    let total_bytes = bytes_transferred.load(Ordering::Relaxed);
    let duration = start.elapsed();
    let avg_throughput = (total_bytes as f64 / BYTES_PER_MB as f64) / duration.as_secs_f64();

    println!();
    println!("=== Final Results ===");
    println!(
        "Total transferred: {:.2} MB",
        total_bytes as f64 / BYTES_PER_MB as f64
    );
    println!("Duration: {:.2} s", duration.as_secs_f64());
    println!("Average throughput: {:.2} MB/s", avg_throughput);

    drop(harness);
}

/// Single-stream profiling for easier analysis
#[tokio::test]
async fn profile_single_stream() {
    println!("\n=== Single-Stream Profiling Benchmark ===");
    println!("Transfer size: {} MB", PROFILE_TRANSFER_SIZE / BYTES_PER_MB);
    println!();

    let _ = tracing_subscriber::fmt::try_init();

    let test_data = generate_test_data(PROFILE_TRANSFER_SIZE);
    let (http_addr, _http_handle) = start_http_server(test_data).await;

    let profile = load_profile().expect("Failed to load profile");
    let harness = StackHarness::spawn_with_profile(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        profile,
    )
    .await
    .expect("Failed to spawn harness");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let bytes_transferred = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    // Single large transfer
    socks5_download(
        harness.socks_addr(),
        http_addr,
        PROFILE_TRANSFER_SIZE,
        bytes_transferred.clone(),
    )
    .await
    .expect("Transfer failed");

    let elapsed = start.elapsed();
    let total = bytes_transferred.load(Ordering::Relaxed);
    let throughput = (total as f64 / BYTES_PER_MB as f64) / elapsed.as_secs_f64();

    println!(
        "Transferred: {:.2} MB in {:.2}s = {:.2} MB/s",
        total as f64 / BYTES_PER_MB as f64,
        elapsed.as_secs_f64(),
        throughput
    );

    drop(harness);
}
