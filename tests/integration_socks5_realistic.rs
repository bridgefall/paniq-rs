use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener as AsyncTcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use async_trait::async_trait;

use paniq::kcp::client::connect_after_handshake;
use paniq::kcp::server::listen_on_socket;
use paniq::obf::Framer;
use paniq::profile::Profile;
use paniq::socks5::{AuthConfig, RelayConnector, Socks5Server, SocksError, TargetAddr};

fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

async fn start_http_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
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

fn spawn_proxy_server(
    port: u16,
    profile_path: PathBuf,
) -> (
    JoinHandle<()>,
    oneshot::Receiver<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
) {
    let (ready_tx, ready_rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        if let Err(err) = run_proxy_server(port, profile_path, ready_tx).await {
            eprintln!("proxy-server task error: {err}");
        }
    });
    (handle, ready_rx)
}

async fn run_proxy_server(
    port: u16,
    profile_path: PathBuf,
    ready: oneshot::Sender<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let profile = Profile::from_file(&profile_path)?;
    let framer = Framer::new(profile.obf_config())?;
    let udp_sock = std::net::UdpSocket::bind(("127.0.0.1", port))?;
    let endpoint = listen_on_socket(udp_sock, framer, ()).await?;

    let _ = ready.send(Ok(()));

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await_connection().await {
                tokio::spawn(async move {
                    while let Ok((send, recv)) = conn.accept_bi().await {
                        tokio::spawn(async move {
                            let _ = handle_proxy_stream(send, recv).await;
                        });
                    }
                });
            }
        });
    }

    Ok(())
}

async fn handle_proxy_stream(
    mut send: paniq::kcp::client::SendStream,
    mut recv: paniq::kcp::client::RecvStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let target = read_proxy_target(&mut recv).await?;
    let mut target = tokio::net::TcpStream::connect(&target).await?;
    target.set_nodelay(true)?;

    let (mut target_reader, mut target_writer) = target.split();

    let client_to_target = async {
        tokio::io::copy(&mut recv, &mut target_writer).await?;
        target_writer.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };

    let target_to_client = async {
        tokio::io::copy(&mut target_reader, &mut send).await?;
        send.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };

    let _ = tokio::try_join!(client_to_target, target_to_client)?;

    Ok(())
}

async fn read_proxy_target(
    recv: &mut paniq::kcp::client::RecvStream,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut header = [0u8; 2];
    recv.read_exact(&mut header).await?;
    let version = header[0];
    let addr_type = header[1];

    if version != 0x01 {
        return Err(format!("unsupported protocol version: {}", version).into());
    }

    let target = match addr_type {
        0x01 => {
            let mut buf = [0u8; 4];
            recv.read_exact(&mut buf).await?;
            let mut port_buf = [0u8; 2];
            recv.read_exact(&mut port_buf).await?;
            let ip = std::net::Ipv4Addr::from(buf);
            format!("{}:{}", ip, u16::from_be_bytes(port_buf))
        }
        0x04 => {
            let mut buf = [0u8; 16];
            recv.read_exact(&mut buf).await?;
            let mut port_buf = [0u8; 2];
            recv.read_exact(&mut port_buf).await?;
            let ip = std::net::Ipv6Addr::from(buf);
            format!("{}:{}", ip, u16::from_be_bytes(port_buf))
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            recv.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut host = vec![0u8; len];
            recv.read_exact(&mut host).await?;
            let mut port_buf = [0u8; 2];
            recv.read_exact(&mut port_buf).await?;
            let host = String::from_utf8(host)?;
            format!("{}:{}", host, u16::from_be_bytes(port_buf))
        }
        other => return Err(format!("unsupported address type: {}", other).into()),
    };

    Ok(target)
}

fn spawn_socks5d(
    port: u16,
    profile_path: PathBuf,
) -> (
    JoinHandle<()>,
    oneshot::Receiver<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
) {
    let (ready_tx, ready_rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        if let Err(err) = run_socks5d(port, profile_path, ready_tx).await {
            eprintln!("socks5d task error: {err}");
        }
    });
    (handle, ready_rx)
}

async fn run_socks5d(
    port: u16,
    profile_path: PathBuf,
    ready: oneshot::Sender<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let profile = Profile::from_file(&profile_path)?;
    let obf_config = profile.obf_config();
    let framer = Framer::new(obf_config.clone()).expect("framer");

    let server_addr = profile.proxy_addr.parse()?;
    let client_sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let (_ep, conn) =
        connect_after_handshake(client_sock, server_addr, framer, (), "paniq").await?;
    let connector = TestKcpConnector { conn };

    let auth = AuthConfig::default();
    let server = Arc::new(Socks5Server::new(connector, auth));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let _ = ready.send(Ok(()));
    loop {
        let (stream, addr) = listener.accept().await?;
        let server = server.clone();
        eprintln!("accepted {addr}");
        tokio::spawn(async move {
            let _ = server.serve_stream(stream).await;
        });
    }
}

struct TestKcpConnector {
    conn: paniq::kcp::client::Connection,
}

#[async_trait]
impl RelayConnector for TestKcpConnector {
    async fn connect(
        &self,
        target: &TargetAddr,
    ) -> Result<Box<dyn paniq::socks5::IoStream + Send>, SocksError> {
        let mut buf = Vec::new();
        buf.push(0x01); // protocol version

        let port = match target {
            TargetAddr::Ip(addr) => {
                match addr.ip() {
                    std::net::IpAddr::V4(ipv4) => {
                        buf.push(0x01); // IPv4
                        buf.extend_from_slice(&ipv4.octets());
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        buf.push(0x04); // IPv6
                        buf.extend_from_slice(&ipv6.octets());
                    }
                }
                addr.port()
            }
            TargetAddr::Domain(host, port) => {
                buf.push(0x03); // Domain
                buf.push(host.len() as u8);
                buf.extend_from_slice(host.as_bytes());
                *port
            }
        };

        buf.extend_from_slice(&port.to_be_bytes());

        let (mut send, recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| SocksError::Connector(e.to_string()))?;
        send.write_all(&buf)
            .await
            .map_err(|e| SocksError::Connector(e.to_string()))?;
        Ok(Box::new(TestStreamWrapper {
            send: Some(send),
            recv,
        }))
    }
}

struct TestStreamWrapper {
    send: Option<paniq::kcp::client::SendStream>,
    recv: paniq::kcp::client::RecvStream,
}

impl tokio::io::AsyncRead for TestStreamWrapper {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TestStreamWrapper {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match &mut self.send {
            Some(send) => std::pin::Pin::new(send).poll_write(cx, buf),
            None => std::task::Poll::Ready(Ok(0)),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match &mut self.send {
            Some(send) => std::pin::Pin::new(send).poll_flush(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        if let Some(send) = &mut self.send {
            let poll_result = std::pin::Pin::new(send).poll_shutdown(cx);
            if poll_result.is_ready() {
                self.send = None;
            }
            poll_result
        } else {
            std::task::Poll::Ready(Ok(()))
        }
    }
}

#[tokio::test]
async fn test_real_binaries_curl() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // Start HTTP server first so we know target address
    let (http_addr, http_handle) = start_http_server().await;

    // 1. Setup ports and profile
    let proxy_port = get_free_port();
    let socks_port = get_free_port();

    // We pick a different socks port to avoid conflict if finding free port races?
    // loop until different?
    let mut socks_port_final = socks_port;
    if proxy_port == socks_port {
        socks_port_final = get_free_port();
    }
    let socks_port = socks_port_final;

    println!("Ports: Proxy={}, Socks={}", proxy_port, socks_port);

    // Create temp profile
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

    let profile_path = PathBuf::from(&manifest_dir).join("test_profile_gen.json");
    std::fs::write(&profile_path, profile_content).expect("Failed to write profile");

    // 2. Start Proxy Server inside this process (shares KCP registry)
    println!("Starting proxy-server...");
    let (proxy_handle, proxy_ready) = spawn_proxy_server(proxy_port, profile_path.clone());
    proxy_ready
        .await
        .expect("proxy startup channel")
        .expect("proxy startup failed");

    // Give it a moment to bind
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 3. Start Socks5d
    println!("Starting socks5d...");
    let (socks_handle, socks_ready) = spawn_socks5d(socks_port, profile_path.clone());
    socks_ready
        .await
        .expect("socks startup channel")
        .expect("socks startup failed");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // 5. Run SOCKS5 handshake + HTTP request manually
    println!("Running SOCKS5 client...");

    // Retry loop to account for "Listening" race or initial connect latency
    let mut success = false;
    for i in 0..3 {
        let start = std::time::Instant::now();
        let attempt = async {
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", socks_port)).await?;
            stream.set_nodelay(true)?;

            // SOCKS5 greeting: no authentication
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await?;
            if resp != [0x05, 0x00] {
                return Err("unexpected method selection".into());
            }

            // CONNECT request to HTTP server
            let mut request = vec![0x05, 0x01, 0x00];
            match http_addr.ip() {
                std::net::IpAddr::V4(ipv4) => {
                    request.push(0x01);
                    request.extend_from_slice(&ipv4.octets());
                }
                std::net::IpAddr::V6(ipv6) => {
                    request.push(0x04);
                    request.extend_from_slice(&ipv6.octets());
                }
            }
            request.extend_from_slice(&http_addr.port().to_be_bytes());
            stream.write_all(&request).await?;

            let mut reply = [0u8; 10];
            stream.read_exact(&mut reply).await?;
            if reply[1] != 0x00 {
                return Err("socks connect failed".into());
            }

            // Send HTTP GET request
            let host = match http_addr.ip() {
                std::net::IpAddr::V4(ipv4) => ipv4.to_string(),
                std::net::IpAddr::V6(ipv6) => format!("[{ipv6}]"),
            };
            let http_req = format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                host
            );
            stream.write_all(http_req.as_bytes()).await?;

            let mut buf = vec![0u8; 1024];
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await??;
            let response = String::from_utf8_lossy(&buf[..n]);
            if !response.contains("200 OK") || !response.contains("ok") {
                return Err("unexpected http response".into());
            }

            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }
        .await;

        let duration = start.elapsed();
        println!("Attempt #{} took {:?}", i, duration);

        match attempt {
            Ok(()) => {
                success = true;
                break;
            }
            Err(err) => {
                println!("SOCKS attempt failed: {err}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }

    // Cleanup profile
    let _ = std::fs::remove_file(profile_path);
    socks_handle.abort();
    proxy_handle.abort();
    http_handle.abort();

    assert!(success, "Curl failed to retrieve local response via SOCKS5");
}
