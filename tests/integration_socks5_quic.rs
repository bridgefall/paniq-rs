//! Integration test for SOCKS5 over obfuscated QUIC
//! Equivalent to Go's pkg/socks5daemon/integration_quic_test.go

#![cfg(feature = "socks5")]
#![cfg(feature = "quic")]

use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

const MAX_END_TO_END_LATENCY: Duration = Duration::from_millis(300);

use paniq::obf::{Config, Framer, SharedRng};
use paniq::quic::client::connect_after_handshake;
use paniq::quic::server::listen_on_socket;
use paniq::socks5::{AuthConfig, IoStream, RelayConnector, Socks5Server, SocksError, TargetAddr};

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

fn get_test_certs() -> (quinn::ServerConfig, quinn::ClientConfig) {
    use rustls::{Certificate, PrivateKey, RootCertStore};

    let cert = rcgen::generate_simple_self_signed(["paniq".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let key_der = cert.serialize_private_key_der();
    let cert = Certificate(cert_der.to_vec());
    let key = PrivateKey(key_der);

    // Server config
    let server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));

    // Client config
    let mut roots = RootCertStore::empty();
    roots.add(&cert).unwrap();
    let client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));

    (server_config, client_config)
}

/// Simple HTTP server that returns "ok"
async fn start_http_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = socket.read(&mut buf).await {
                        let request = String::from_utf8_lossy(&buf[..n]);
                        if request.contains("GET") && request.contains("HTTP") {
                            let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                            let _ = socket.write_all(response.as_bytes()).await;
                        }
                    }
                });
            }
        }
    });

    (addr, handle)
}

async fn socks5_over_quic_roundtrip() -> Duration {
    // Enable logging (ok if already initialized)
    let _ = tracing_subscriber::fmt::try_init();

    // Start HTTP server
    let (http_addr, http_handle) = start_http_server().await;

    // Start proxy server
    let server_framer = make_framer(&test_obf_config(), 456);
    let (server_config, client_config) = get_test_certs();
    let server_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let server_addr = server_sock.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let endpoint = listen_on_socket(server_sock, server_framer, server_config)
            .await
            .unwrap();

        while let Some(incoming) = endpoint.accept().await {
            if let Ok(conn) = incoming.await {
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
                            if let Ok(mut target_stream) =
                                tokio::net::TcpStream::connect(&target_str).await
                            {
                                let (mut target_read, mut target_write) = target_stream.split();
                                let mut recv_buf = vec![0u8; 8192];
                                let mut send_buf = vec![0u8; 8192];

                                let recv_task = async move {
                                    loop {
                                        let n = match recv.read(&mut recv_buf).await {
                                            Ok(Some(n)) => n,
                                            Ok(None) => return,
                                            Err(_) => return,
                                        };
                                        if target_write.write_all(&recv_buf[..n]).await.is_err() {
                                            return;
                                        }
                                    }
                                };

                                let send_task = async move {
                                    loop {
                                        let n = match target_read.read(&mut send_buf).await {
                                            Ok(n) if n > 0 => n,
                                            Ok(_) => return,
                                            Err(_) => return,
                                        };
                                        if send.write_all(&send_buf[..n]).await.is_err() {
                                            return;
                                        }
                                    }
                                };

                                tokio::select! {
                                    _ = recv_task => {}
                                    _ = send_task => {}
                                }
                            }
                        });
                    }
                });
            }
        }
    });

    // Start SOCKS5 server
    let client_framer = make_framer(&test_obf_config(), 123);
    let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

    let (endpoint, quinn_conn) = connect_after_handshake(
        client_sock,
        server_addr,
        client_framer,
        client_config,
        "paniq",
    )
    .await
    .unwrap();

    let connector = TestQuicConnector {
        conn: Arc::new(tokio::sync::Mutex::new(quinn_conn)),
        _endpoint: Arc::new(endpoint),
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

    // Read HTTP response
    let mut http_resp = vec![0u8; 1024];
    let n = timeout(Duration::from_secs(5), socks_conn.read(&mut http_resp))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8_lossy(&http_resp[..n]);

    assert!(response.contains("200 OK"));
    assert!(response.contains("ok"));

    let elapsed = latency_start.elapsed();
    assert!(elapsed < MAX_END_TO_END_LATENCY, "End-to-end latency too high: {:?}", elapsed);

    // Cleanup
    drop(socks_conn);
    socks_handle.abort();
    server_task.abort();
    http_handle.abort();

    elapsed
}

// Test QUIC connector for SOCKS5 - similar to the one in socks5d.rs
struct TestQuicConnector {
    conn: Arc<tokio::sync::Mutex<quinn::Connection>>,
    _endpoint: Arc<quinn::Endpoint>,
}

impl TestQuicConnector {
    async fn connect(&self, target: &TargetAddr) -> Result<Box<dyn IoStream + Send>, String> {
        let conn = self.conn.lock().await;

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

        // Return a bidirectional wrapper
        Ok(Box::new(TestBiStreamWrapper::new(send, recv)))
    }
}

#[async_trait]
impl RelayConnector for TestQuicConnector {
    async fn connect(&self, target: &TargetAddr) -> Result<Box<dyn IoStream + Send>, SocksError> {
        self.connect(target)
            .await
            .map_err(|e| SocksError::Connector(e))
    }
}

struct TestBiStreamWrapper {
    send: Option<quinn::SendStream>,
    recv: quinn::RecvStream,
}

impl TestBiStreamWrapper {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
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
async fn integration_socks5_over_quic() {
    let _elapsed = socks5_over_quic_roundtrip().await;
}

#[tokio::test]
async fn soak_socks5_over_quic_30s() {
    // Warm up once to avoid startup noise skewing the soak run
    let _ = socks5_over_quic_roundtrip().await;

    let start = Instant::now();
    let mut iterations = 0usize;

    while start.elapsed() < Duration::from_secs(30) {
        let elapsed = socks5_over_quic_roundtrip().await;
        assert!(
            elapsed < MAX_END_TO_END_LATENCY,
            "Iteration latency too high: {:?}",
            elapsed
        );
        iterations += 1;
    }

    assert!(iterations > 0, "No iterations executed in soak test");
}
