// SOCKS5 Daemon - listens locally and forwards through obfuscated QUIC
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use paniq::obf::{Framer, SharedRng};
use paniq::profile::{Profile, QuicConfig as ProfileQuicConfig};
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
    let framer = Framer::new(obf_config)?;
    let _rng = SharedRng::from_seed(12345);

    // Connect to proxy server
    let std_sock = std::net::UdpSocket::bind("127.0.0.1:0")?;

    let proxy_addr = profile.proxy_addr.parse()?;
    log(&format!("Connecting to proxy at {}", proxy_addr));
    let (endpoint, quinn_conn) = connect_after_handshake(
        std_sock,
        proxy_addr,
        framer,
        args.quic_client_config,
        "paniq",
    )
    .await?;

    log(&format!("Listening on {}", args.listen_addr));
    log(&format!("Connected to proxy at {}", proxy_addr));

    let listener = TcpListener::bind(&args.listen_addr).await?;

    // Create connector that uses QUIC streams
    let connector = QuicConnector {
        conn: quinn_conn,
        _endpoint: Arc::new(endpoint),
    };

    let auth = if let Some((user, pass)) = args.auth {
        let mut users = std::collections::HashMap::new();
        users.insert(user, pass);
        AuthConfig { users }
    } else {
        AuthConfig::default()
    };

    let server = Arc::new(Socks5Server::new(connector, auth));

    loop {
        let (stream, addr) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        log(&format!("Connection from {}", addr));
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(e) = server.serve_stream(stream).await {
                log(&format!("Error serving {}: {}", addr, e));
            }
        });
    }
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
                listen_addr = args[i + 1].clone();
                i += 2;
            }
            "--profile" => {
                profile = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--username" => {
                username = Some(args[i + 1].clone());
                i += 2;
            }
            "--password" => {
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

fn configure_transport(config: &mut quinn::TransportConfig, quic_cfg: Option<&ProfileQuicConfig>) {
    let defaults = (
        std::time::Duration::from_secs(20),
        std::time::Duration::from_secs(120),
    );
    let (keep_alive, idle_timeout) = quic_cfg
        .map(|cfg| (cfg.keepalive, cfg.idle_timeout))
        .unwrap_or(defaults);

    let keep_alive = if keep_alive.is_zero() {
        defaults.0
    } else {
        keep_alive
    };
    let idle_timeout = if idle_timeout.is_zero() {
        defaults.1
    } else {
        idle_timeout
    };

    config.max_idle_timeout(Some(idle_timeout.try_into().unwrap()));
    config.keep_alive_interval(Some(keep_alive));
    config.initial_rtt(std::time::Duration::from_millis(10));
    let max_streams = quic_cfg
        .map(|cfg| {
            if cfg.max_streams == 0 {
                256
            } else {
                cfg.max_streams
            }
        })
        .unwrap_or(256) as u32;
    config.max_concurrent_bidi_streams(quinn::VarInt::from_u32(max_streams));
}

struct QuicConnector {
    conn: quinn::Connection,
    _endpoint: Arc<quinn::Endpoint>,
}

impl QuicConnector {
    async fn connect(&self, target: &TargetAddr) -> Result<Box<dyn IoStream + Send>, String> {
        let conn = &self.conn;

        let start = std::time::Instant::now();
        // Open a new bidirectional stream
        let (mut send, recv) = conn.open_bi().await.map_err(|e| {
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

        read_proxy_reply(&mut recv).await?;

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
    let mut header = [0u8; 3];
    recv.read_exact(&mut header)
        .await
        .map_err(|e| format!("proxy reply header: {}", e))?;

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
