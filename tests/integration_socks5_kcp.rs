//! Integration test for SOCKS5 over obfuscated KCP (simulated)
//! Equivalent to Go's pkg/socks5daemon/integration_kcp_test.go

#![cfg(feature = "socks5")]
#![cfg(feature = "kcp")]

use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

const MAX_END_TO_END_LATENCY: Duration = Duration::from_secs(1);

use paniq::kcp::client::{connect, ClientConfigWrapper};
use paniq::kcp::server::{listen, ServerConfigWrapper};
use paniq::obf::{Config, Framer, SharedRng};
use paniq::socks5::{AuthConfig, IoStream, RelayConnector, Socks5Server, SocksError, TargetAddr};
use tokio::sync::oneshot;

fn test_obf_config() -> Config {
    Config {
        jc: 0,
        jmin: 0,
        jmax: 0,
        s1: 0,
        s2: 0,
        s3: 0,
        s4: 0,
        h1: "1".into(),
        h2: "2".into(),
        h3: "3".into(),
        h4: "4".into(),
        i1: "<d>".into(),
        i2: String::new(),
        i3: String::new(),
        i4: String::new(),
        i5: String::new(),
    }
}

fn make_framer(cfg: &Config, seed: u64) -> Framer {
    Framer::new_with_rng(cfg.clone(), SharedRng::from_seed(seed)).unwrap()
}

/// Simple HTTP server that returns "ok"
async fn start_http_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.set_nodelay(true);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096]; // Use stack-allocated buffer for common MTU
                    if let Ok(n) = socket.read(&mut buf).await {
                        let request = String::from_utf8_lossy(&buf[..n]);
                        if request.contains("GET") && request.contains("HTTP") {
                            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                            let _ = socket.write_all(response.as_bytes()).await;
                            let _ = socket.shutdown().await; // Explicitly close connection
                                                             // println!("HTTP: sent response");
                        }
                    }
                });
            }
        }
    });

    (addr, handle)
}

async fn socks5_over_kcp_roundtrip() -> Duration {
    // Enable logging (ok if already initialized)
    let _ = tracing_subscriber::fmt::try_init();

    // Start HTTP server
    let (http_addr, http_handle) = start_http_server().await;

    // Start proxy server
    let server_framer = make_framer(&test_obf_config(), 456);
    let server_config = ServerConfigWrapper::default();
    let client_config = ClientConfigWrapper::default();
    let server_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let (ready_tx, ready_rx) = oneshot::channel();

    let server_task = tokio::spawn(async move {
        let endpoint = listen(server_addr, server_framer, server_config)
            .await
            .unwrap();

        let _ = ready_tx.send(endpoint.local_addr());

        while let Some(incoming) = endpoint.accept().await {
            if let Ok(mut conn) = incoming.await_connection().await {
                tokio::spawn(async move {
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        tokio::spawn(async move {
                            // Read proxy request
                            let mut header = [0u8; 2];
                            if recv.read_exact(&mut header).await.is_err() {
                                return;
                            }
                            if header[0] != 0x01 {
                                return;
                            }

                            let addr_type = header[1];
                            let target_str: String = match addr_type {
                                0x01 => {
                                    let mut addr_bytes = [0u8; 4];
                                    if recv.read_exact(&mut addr_bytes).await.is_err() {
                                        return;
                                    }
                                    let mut port_bytes = [0u8; 2];
                                    if recv.read_exact(&mut port_bytes).await.is_err() {
                                        return;
                                    }
                                    let port = u16::from_be_bytes(port_bytes);
                                    format!("{}:{}", std::net::Ipv4Addr::from(addr_bytes), port)
                                }
                                0x03 => {
                                    let mut len_bytes = [0u8; 1];
                                    if recv.read_exact(&mut len_bytes).await.is_err() {
                                        return;
                                    }
                                    let len = len_bytes[0] as usize;
                                    let mut domain_bytes = vec![0u8; len];
                                    if recv.read_exact(&mut domain_bytes).await.is_err() {
                                        return;
                                    }
                                    let mut port_bytes = [0u8; 2];
                                    if recv.read_exact(&mut port_bytes).await.is_err() {
                                        return;
                                    }
                                    let port = u16::from_be_bytes(port_bytes);
                                    let domain = String::from_utf8_lossy(&domain_bytes).to_string();
                                    format!("{}:{}", domain, port)
                                }
                                _ => return,
                            };

                            // Connect to target
                            let mut target_stream =
                                match tokio::net::TcpStream::connect(&target_str).await {
                                    Ok(s) => s,
                                    Err(_) => return,
                                };

                            // Relay bidirectionally - both directions run concurrently
                            let (mut target_read, mut target_write) = target_stream.split();
                            let mut recv_buf = vec![0u8; 8192];
                            let mut send_buf = vec![0u8; 8192];

                            // KCP → Target (client_to_target)
                            let client_to_target = async {
                                loop {
                                    let n = recv.read(&mut recv_buf).await.map_err(|_| ())?;
                                    if n == 0 {
                                        break; // EOF
                                    }
                                    target_write
                                        .write_all(&recv_buf[..n])
                                        .await
                                        .map_err(|_| ())?;
                                }
                                drop(target_write);
                                Ok::<(), ()>(())
                            };

                            // Target → KCP (target_to_client)
                            let target_to_client = async {
                                loop {
                                    let n =
                                        target_read.read(&mut send_buf).await.map_err(|_| ())?;
                                    if n == 0 {
                                        break; // EOF from target
                                    }
                                    send.write_all(&send_buf[..n]).await.map_err(|_| ())?;
                                    tokio::task::yield_now().await; // Allow other tasks to run
                                }
                                // Flush buffered data before finishing
                                let _ = send.flush().await;
                                // Gracefully shutdown the send half; client_to_target continues until it drains
                                let _ = send.shutdown().await;
                                Ok::<(), ()>(())
                            };

                            // Run both concurrently until BOTH complete
                            let _ = tokio::try_join!(client_to_target, target_to_client);
                        });
                    }
                });
            }
        }
    });

    let server_addr = ready_rx.await.unwrap();

    // Start SOCKS5 server
    let client_framer = make_framer(&test_obf_config(), 123);
    let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

    let (_endpoint, kcp_conn) = connect(
        client_sock,
        server_addr,
        client_framer,
        client_config,
        b"paniq",
        "paniq",
    )
    .await
    .unwrap();

    let connector = TestKcpConnector {
        conn: Arc::new(kcp_conn),
    };

    let mut users = std::collections::HashMap::new();
    users.insert("user".to_string(), "pass".to_string());
    let auth = AuthConfig { users };

    let socks_server = Arc::new(Socks5Server::new(connector, auth));
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();

    let socks_handle = tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = socks_listener.accept().await {
                let server = socks_server.clone();
                tokio::spawn(async move {
                    let _ = server.serve_stream(stream).await;
                });
            }
        }
    });

    // Give servers time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect as SOCKS5 client
    let mut socks_conn = tokio::net::TcpStream::connect(socks_addr).await.unwrap();
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

    assert!(response.contains("200 OK"), "response missing 200 OK: {response}");
    assert!(response.contains("ok"), "response missing body: {response}");

    let elapsed = latency_start.elapsed();
    assert!(
        elapsed < MAX_END_TO_END_LATENCY,
        "End-to-end latency too high: {:?}",
        elapsed
    );

    // Cleanup
    drop(socks_conn);
    socks_handle.abort();
    server_task.abort();
    http_handle.abort();

    elapsed
}

// Test KCP connector for SOCKS5 - similar to the one in socks5d.rs
struct TestKcpConnector {
    conn: Arc<paniq::kcp::client::Connection>,
}

impl TestKcpConnector {
    async fn connect(&self, target: &TargetAddr) -> Result<Box<dyn IoStream + Send>, String> {
        let conn = &self.conn;

        // Open a new bidirectional stream
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| format!("open_bi failed: {}", e))?;

        // Send target address to proxy (version 1, address type, address, port)
        let mut request = vec![0x01u8]; // version
        match target {
            TargetAddr::Ip(addr) => {
                match addr.ip() {
                    std::net::IpAddr::V4(ipv4) => {
                        request.push(0x01); // IPv4
                        request.extend_from_slice(&ipv4.octets());
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        request.push(0x04); // IPv6
                        request.extend_from_slice(&ipv6.octets());
                    }
                }
                request.extend_from_slice(&addr.port().to_be_bytes());
            }
            TargetAddr::Domain(host, port) => {
                request.push(0x03); // Domain
                request.push(host.len() as u8);
                request.extend_from_slice(host.as_bytes());
                request.extend_from_slice(&port.to_be_bytes());
            }
        }

        send.write_all(&request)
            .await
            .map_err(|e| format!("write failed: {}", e))?;
        // println!("Test connector: request sent");

        // Return a bidirectional wrapper
        Ok(Box::new(TestBiStreamWrapper::new(send, recv)))
    }
}

#[async_trait]
impl RelayConnector for TestKcpConnector {
    async fn connect(&self, target: &TargetAddr) -> Result<Box<dyn IoStream + Send>, SocksError> {
        self.connect(target)
            .await
            .map_err(|e| SocksError::Connector(e))
    }
}

struct TestBiStreamWrapper {
    send: Option<paniq::kcp::client::SendStream>,
    recv: paniq::kcp::client::RecvStream,
}

impl TestBiStreamWrapper {
    fn new(send: paniq::kcp::client::SendStream, recv: paniq::kcp::client::RecvStream) -> Self {
        Self {
            send: Some(send),
            recv,
        }
    }
}

impl tokio::io::AsyncRead for TestBiStreamWrapper {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TestBiStreamWrapper {
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
async fn integration_socks5_over_kcp() {
    let _elapsed = socks5_over_kcp_roundtrip().await;
}

#[tokio::test]
async fn soak_socks5_over_kcp_30s() {
    // Warm up once to avoid startup noise skewing the soak run
    let _ = socks5_over_kcp_roundtrip().await;

    let start = Instant::now();
    let mut iterations = 0usize;

    while start.elapsed() < Duration::from_secs(30) {
        let elapsed = socks5_over_kcp_roundtrip().await;
        assert!(
            elapsed < MAX_END_TO_END_LATENCY,
            "Iteration latency too high: {:?}",
            elapsed
        );
        iterations += 1;
        if iterations % 10 == 0 {
            println!("Soak iteration {}", iterations);
        }
    }

    assert!(iterations > 0, "No iterations executed in soak test");
}
