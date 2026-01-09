#![cfg(feature = "socks5")]
#![cfg(feature = "kcp")]

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener as AsyncTcpListener;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio::time::timeout;

fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

async fn start_http_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = AsyncTcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    if let Ok(n) = stream.read(&mut buf).await {
                        let req = String::from_utf8_lossy(&buf[..n]);
                        if req.contains("GET") {
                            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                            let _ = stream.write_all(resp.as_bytes()).await;
                        }
                    }
                });
            }
        }
    });

    (addr, handle)
}

fn write_temp_profile(proxy_port: u16) -> PathBuf {
    let profile_content = format!(
        r#"{{
  "name": "test_profile",
  "proxy_addr": "127.0.0.1:{}",
  "handshake_timeout": "5s",
  "handshake_attempts": 3,
  "obfuscation": {{
    "jc": 0, "jmin": 0, "jmax": 0,
    "s1": 0, "s2": 0, "s3": 0, "s4": 0,
    "h1": "100-100", "h2": "200-200", "h3": "300-300", "h4": "400-400",
    "i1": "", "i2": "", "i3": "", "i4": "", "i5": "",
    "server_public_key": "",
    "server_private_key": "",
    "signature_validate": false,
    "encrypted_timestamp": false,
    "require_encrypted_timestamp": false
  }}
}}"#,
        proxy_port
    );

    let filename = format!(
        "paniq_test_profile_{}_{}.json",
        std::process::id(),
        rand::random::<u64>()
    );
    let path = std::env::temp_dir().join(filename);
    std::fs::write(&path, profile_content).expect("Failed to write profile");
    path
}

async fn spawn_proxy_binary(
    proxy_port: u16,
    profile_path: &Path,
) -> Result<tokio::process::Child, Box<dyn std::error::Error + Send + Sync>> {
    let proxy_bin = env!("CARGO_BIN_EXE_proxy-server");
    let child = Command::new(proxy_bin)
        .arg("-l")
        .arg(format!("127.0.0.1:{}", proxy_port))
        .arg("-p")
        .arg(profile_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(child)
}

async fn spawn_socks_binary(
    socks_port: u16,
    profile_path: &Path,
) -> Result<tokio::process::Child, Box<dyn std::error::Error + Send + Sync>> {
    let socks_bin = env!("CARGO_BIN_EXE_socks5d");
    let child = Command::new(socks_bin)
        .arg("-l")
        .arg(format!("127.0.0.1:{}", socks_port))
        .arg("-p")
        .arg(profile_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(child)
}

async fn wait_for_socks_ready(
    socks_addr: SocketAddr,
    target_addr: SocketAddr,
    timeout_after: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deadline = Instant::now() + timeout_after;
    loop {
        match tokio::net::TcpStream::connect(socks_addr).await {
            Ok(mut stream) => {
                stream.set_nodelay(true)?;

                // Minimal no-auth handshake.
                stream.write_all(&[0x05, 0x01, 0x00]).await?;
                let mut resp = [0u8; 2];
                stream.read_exact(&mut resp).await?;
                if resp != [0x05, 0x00] {
                    return Err("unexpected method selection".into());
                }

                // CONNECT request to a real target so the proxy request is valid.
                let mut request = vec![0x05, 0x01, 0x00];
                match target_addr.ip() {
                    std::net::IpAddr::V4(ipv4) => {
                        request.push(0x01);
                        request.extend_from_slice(&ipv4.octets());
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        request.push(0x04);
                        request.extend_from_slice(&ipv6.octets());
                    }
                }
                request.extend_from_slice(&target_addr.port().to_be_bytes());
                stream.write_all(&request).await?;

                // Add timeout to prevent hanging
                timeout(Duration::from_secs(2), read_socks5_reply(&mut stream)).await??;
                return Ok(());
            }
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(err.into());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn read_socks5_reply(
    stream: &mut tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        return Err(format!("unexpected socks version: {}", header[0]).into());
    }
    if header[1] != 0x00 {
        return Err(format!("socks connect failed: {}", header[1]).into());
    }

    match header[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut addr = vec![0u8; len[0] as usize];
            stream.read_exact(&mut addr).await?;
        }
        other => return Err(format!("unexpected address type: {}", other).into()),
    }

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(())
}

async fn run_socks5_request(
    socks_addr: SocketAddr,
    target_host: &str,
    target_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;

    for _ in 0..3 {
        let attempt = async {
            let mut stream = tokio::net::TcpStream::connect(socks_addr).await?;
            stream.set_nodelay(true)?;

            stream.write_all(&[0x05, 0x01, 0x00]).await?;
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await?;
            if resp != [0x05, 0x00] {
                return Err("unexpected method selection".into());
            }

            let mut request = vec![0x05, 0x01, 0x00, 0x03];
            request.push(target_host.len() as u8);
            request.extend_from_slice(target_host.as_bytes());
            request.extend_from_slice(&target_port.to_be_bytes());
            stream.write_all(&request).await?;

            read_socks5_reply(&mut stream).await?;

            let http_req = format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                target_host
            );
            stream.write_all(http_req.as_bytes()).await?;

            let mut buf = vec![0u8; 1024];
            let n = timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
            let response = String::from_utf8_lossy(&buf[..n]);
            if !response.contains("200 OK") || !response.contains("ok") {
                return Err("unexpected http response".into());
            }

            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }
        .await;

        match attempt {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = Some(err);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }

    Err(last_err.unwrap_or_else(|| "unknown socks5 failure".into()))
}

#[tokio::test]
async fn test_real_binaries_curl() {
    let (http_addr, http_handle) = start_http_server().await;
    let proxy_port = get_free_port();
    let socks_port = get_free_port();

    let profile_path = write_temp_profile(proxy_port);

    let mut proxy = spawn_proxy_binary(proxy_port, &profile_path)
        .await
        .expect("spawn proxy-server");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut socks = spawn_socks_binary(socks_port, &profile_path)
        .await
        .expect("spawn socks5d");

    let socks_addr: SocketAddr = format!("127.0.0.1:{}", socks_port).parse().unwrap();
    let readiness = wait_for_socks_ready(socks_addr, http_addr, Duration::from_secs(5)).await;

    let test_result = match readiness {
        Ok(()) => run_socks5_request(socks_addr, "localhost", http_addr.port()).await,
        Err(err) => Err(err),
    };

    let _ = socks.kill().await;
    let _ = socks.wait().await;
    let _ = proxy.kill().await;
    let _ = proxy.wait().await;
    http_handle.abort();
    let _ = std::fs::remove_file(profile_path);

    if let Err(err) = test_result {
        panic!("SOCKS5 request failed: {err}");
    }
}
