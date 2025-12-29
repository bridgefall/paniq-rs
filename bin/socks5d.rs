// SOCKS5 Daemon - listens locally and forwards through obfuscated QUIC
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use paniq::obf::{Framer, Config as ObfConfig};
use paniq::profile::Profile;
use paniq::quic::common::configure_transport;
use paniq::quic::client::connect_after_handshake;
use paniq::socks5::{AuthConfig, IoStream, RelayConnector, Socks5Server, SocksError, TargetAddr};

mod shared_cert;

const QUIC_ALPN: &str = "bridgefall-paniq";
const PROXY_VERSION: u8 = 0x01;
const STATUS_SUCCESS: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;



fn log(msg: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    eprintln!(
        "[{}.{:03}] socks5d: {}",
        now.as_secs(),
        now.subsec_millis(),
        msg
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;

    // Load profile from file
    let profile = if let Some(profile_path) = &args.profile {
        Profile::from_file(profile_path)?
    } else {
        return Err("--profile is required".into());
    };

    let obf_config = profile.obf_config();

    // Removed unused _rng

    // Prepare for connection
    let proxy_addr = profile.proxy_addr.parse()?;

    // Create connector that manages the connection state
    let connector = QuicConnector::new(
        proxy_addr,
        obf_config.clone(),
        args.quic_client_config,
    );

    // Initial connection attempt
    log(&format!("Connecting to proxy at {}", proxy_addr));
    if let Err(e) = connector.ensure_connected().await {
        log(&format!("Warning: Initial connection failed: {}", e));
        // We continue, as it might just be temporary unavailability
    } else {
        log(&format!("Connected to proxy at {}", proxy_addr));
    }

    log(&format!("Listening on {}", args.listen_addr));

    let listener = TcpListener::bind(&args.listen_addr).await?;

    let auth = if let Some((user, pass)) = args.auth {
        let mut users = std::collections::HashMap::new();
        users.insert(user, pass);
        AuthConfig { users }
    } else {
        AuthConfig::default()
    };

    let server = Arc::new(Socks5Server::new(connector, auth));

    // Graceful shutdown handling
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, addr)) => {
                        let _ = stream.set_nodelay(true);
                        log(&format!("Connection from {}", addr));
                        let server = server.clone();
                        tokio::spawn(async move {
                            if let Err(e) = server.serve_stream(stream).await {
                                log(&format!("Error serving {}: {}", addr, e));
                            }
                        });
                    }
                    Err(e) => {
                         log(&format!("Accept error: {}", e));
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                log("Shutting down gracefully...");
                break;
            }
        }
    }

    Ok(())
}

struct Args {
    listen_addr: String,
    profile: Option<PathBuf>,
    auth: Option<(String, String)>,
    quic_client_config: quinn::ClientConfig,
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut listen_addr = "127.0.0.1:1080".to_string();
    let mut profile = None;
    let mut username = None;
    let mut password = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                if i + 1 >= args.len() {
                    return Err("Missing value for --listen".into());
                }
                listen_addr = args[i + 1].clone();
                i += 2;
            }
            "--profile" => {
                if i + 1 >= args.len() {
                    return Err("Missing value for --profile".into());
                }
                profile = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--username" => {
                 if i + 1 >= args.len() {
                    return Err("Missing value for --username".into());
                }
                username = Some(args[i + 1].clone());
                i += 2;
            }
            "--password" => {
                 if i + 1 >= args.len() {
                    return Err("Missing value for --password".into());
                }
                password = Some(args[i + 1].clone());
                i += 2;
            }
            _ => {
                eprintln!("Usage: socks5d --profile <file> [--listen <addr>] [--username <user> --password <pass>]");
                std::process::exit(1);
            }
        }
    }

    // Load proper certificates from profile or use test certs
    let client_config = if let Some(profile_path) = &profile {
        let profile = Profile::from_file(profile_path)?;
        build_client_config_from_profile(&profile)?
    } else {
        eprintln!("Warning: Using test certificates - use --profile for production");
        build_test_client_config()?
    };

    Ok(Args {
        listen_addr,
        profile,
        auth: username.zip(password),
        quic_client_config: client_config,
    })
}

fn build_test_client_config() -> Result<quinn::ClientConfig, Box<dyn std::error::Error>> {
    let test_cert = shared_cert::get_test_certificate();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(&test_cert.cert)?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto
        .alpn_protocols
        .push(QUIC_ALPN.as_bytes().to_vec());

    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    let mut transport = quinn::TransportConfig::default();
    configure_transport(&mut transport, None);
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

// For now, use the same test cert approach. In production, this would load
// certificates from the profile or from files specified in the profile.
fn build_client_config_from_profile(
    profile: &Profile,
) -> Result<quinn::ClientConfig, Box<dyn std::error::Error>> {
    // Note: In a real app we'd load certs from profile. For now we use test certs but ENSURE transport config is right.
    let test_cert = shared_cert::get_test_certificate();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(&test_cert.cert)?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto
        .alpn_protocols
        .push(QUIC_ALPN.as_bytes().to_vec());

    let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    let mut transport_config = quinn::TransportConfig::default();
    configure_transport(&mut transport_config, profile.quic.as_ref());
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}



struct QuicConnector {
    state: tokio::sync::RwLock<ConnectorState>,
    proxy_addr: std::net::SocketAddr,
    obf_config: ObfConfig,
    client_config: quinn::ClientConfig,
}

struct ConnectorState {
    conn: Option<quinn::Connection>,
    _endpoint: Option<Arc<quinn::Endpoint>>,
}

impl QuicConnector {
    fn new(
        proxy_addr: std::net::SocketAddr,
        obf_config: ObfConfig,
        client_config: quinn::ClientConfig,
    ) -> Self {
        Self {
            state: tokio::sync::RwLock::new(ConnectorState {
                conn: None,
                _endpoint: None,
            }),
            proxy_addr,
            obf_config,
            client_config,
        }
    }

    async fn ensure_connected(&self) -> Result<quinn::Connection, String> {
        // Fast path: check if existing connection is alive
        {
            let state = self.state.read().await;
            if let Some(conn) = &state.conn {
                if conn.close_reason().is_none() {
                    return Ok(conn.clone());
                }
            }
        }

        // Slow path: reconnect
        let mut state = self.state.write().await;

        // Check again in case someone else connected while we waited for write lock
        if let Some(conn) = &state.conn {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }

        log("Reconnecting to proxy...");

        // We bind a fresh socket for the new connection
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")
            .map_err(|e| format!("Failed to bind socket: {}", e))?;

        // Create fresh framer
        let framer = Framer::new(self.obf_config.clone()).map_err(|e| format!("Framer error: {}", e))?;

        let (endpoint, conn) = connect_after_handshake(
            socket,
            self.proxy_addr,
            framer,
            self.client_config.clone(),
            "paniq",
        )
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

        state.conn = Some(conn.clone());
        state._endpoint = Some(Arc::new(endpoint));

        log("Reconnected successfully");
        Ok(conn)
    }

    async fn connect(&self, target: &TargetAddr) -> Result<Box<dyn IoStream + Send>, String> {
        let conn = self.ensure_connected().await?;

        let start = std::time::Instant::now();
        // Open a new bidirectional stream
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| {
            log(&format!("[QuicConnector] connect: open_bi failed: {}", e));
            format!("open_bi failed: {}", e)
        })?;

        // Log if open_bi takes too long
        let elapsed = start.elapsed();
        if elapsed > std::time::Duration::from_millis(100) {
            log(&format!(
                "[QuicConnector] connect: open_bi took slow: {:?}",
                elapsed
            ));
        }

        eprintln!("[QuicConnector] connect: Stream opened, sending proxy request");

        // Send target address to proxy (version 1, address type, address, port)
        let mut request = vec![PROXY_VERSION]; // version
        match target {
            TargetAddr::Ip(addr) => {
                match addr.ip() {
                    std::net::IpAddr::V4(ipv4) => {
                        request.push(ATYP_IPV4); // IPv4
                        request.extend_from_slice(&ipv4.octets());
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        request.push(ATYP_IPV6); // IPv6
                        request.extend_from_slice(&ipv6.octets());
                    }
                }
                request.extend_from_slice(&addr.port().to_be_bytes());
            }
            TargetAddr::Domain(host, port) => {
                request.push(ATYP_DOMAIN); // Domain
                request.push(host.len() as u8);
                request.extend_from_slice(host.as_bytes());
                request.extend_from_slice(&port.to_be_bytes());
            }
        }

        send.write_all(&request).await.map_err(|e| {
            log(&format!("[QuicConnector] connect: write failed: {}", e));
            format!("write failed: {}", e)
        })?;

        send.flush().await.map_err(|e| {
            log(&format!("[QuicConnector] connect: flush failed: {}", e));
            format!("flush failed: {}", e)
        })?;

        log("[QuicConnector] connect: Waiting for proxy reply...");
        read_proxy_reply(&mut recv).await?;
        log("[QuicConnector] connect: Proxy reply received");

        log(&format!(
            "[QuicConnector] connect: Proxy request accepted for {:?}",
            target
        ));
        // Note: Don't finish the send stream yet, we need it for writing data
        // The stream will be half-closed when dropped

        // Return a bidirectional wrapper that can both read and write
        Ok(Box::new(BiStreamWrapper::new(send, recv)))
    }
}

async fn read_proxy_reply(recv: &mut quinn::RecvStream) -> Result<(), String> {
    let start = std::time::Instant::now();
    let mut header = [0u8; 3];
    recv.read_exact(&mut header)
        .await
        .map_err(|e| format!("proxy reply header: {}", e))?;
    log(&format!(
        "[read_proxy_reply] Header read in {:?}",
        start.elapsed()
    ));

    if header[0] != PROXY_VERSION {
        return Err(format!("unsupported proxy reply version: {}", header[0]));
    }
    if header[1] != STATUS_SUCCESS {
        return Err(format!("proxy rejected request with status {}", header[1]));
    }

    let atyp = header[2];
    match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 4];
            recv.read_exact(&mut buf)
                .await
                .map_err(|e| format!("proxy reply IPv4: {}", e))?;
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            recv.read_exact(&mut buf)
                .await
                .map_err(|e| format!("proxy reply IPv6: {}", e))?;
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            recv.read_exact(&mut len)
                .await
                .map_err(|e| format!("proxy reply domain len: {}", e))?;
            let mut buf = vec![0u8; len[0] as usize];
            recv.read_exact(&mut buf)
                .await
                .map_err(|e| format!("proxy reply domain: {}", e))?;
        }
        _ => return Err(format!("unsupported proxy reply address type: {}", atyp)),
    }

    let mut port = [0u8; 2];
    recv.read_exact(&mut port)
        .await
        .map_err(|e| format!("proxy reply port: {}", e))?;
    Ok(())
}

struct BiStreamWrapper {
    send: Option<quinn::SendStream>,
    recv: quinn::RecvStream,
}

impl BiStreamWrapper {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            send: Some(send),
            recv,
        }
    }
}

impl tokio::io::AsyncRead for BiStreamWrapper {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for BiStreamWrapper {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match &mut self.send {
            Some(send) => std::pin::Pin::new(send).poll_write(cx, buf),
            None => std::task::Poll::Ready(Ok(0)), // Stream was closed
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
        match &mut self.send {
            Some(send) => std::pin::Pin::new(send).poll_shutdown(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}

#[async_trait]
impl RelayConnector for QuicConnector {
    async fn connect(&self, target: &TargetAddr) -> Result<Box<dyn IoStream + Send>, SocksError> {
        self.connect(target)
            .await
            .map_err(|e| SocksError::Connector(e))
    }
}
