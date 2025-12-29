// Proxy Server - accepts obfuscated QUIC connections and forwards to destinations
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use paniq::obf::Framer;
use paniq::profile::Profile;
use paniq::quic::common::configure_transport;
use paniq::quic::server::listen_on_socket;

mod shared_cert;

const QUIC_ALPN: &str = "bridgefall-paniq";
const PROXY_VERSION: u8 = 0x01;
const STATUS_SUCCESS: u8 = 0x00;
const STATUS_FAILURE: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;

const ATYP_IPV6: u8 = 0x04;

fn log(msg: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    eprintln!(
        "[{}.{:03}] proxy-server: {}",
        now.as_secs(),
        now.subsec_millis(),
        msg
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;

    // Load profile from file (for server, needs private key)
    let profile = if let Some(profile_path) = &args.profile {
        Profile::from_file(profile_path)?
    } else {
        return Err("--profile is required".into());
    };

    let obf_config = profile.obf_config();
    let framer = Framer::new(obf_config)?;

    let server_sock = std::net::UdpSocket::bind(&args.listen_addr)?;
    let endpoint = listen_on_socket(server_sock, framer, args.server_config).await?;

    log(&format!("Listening on {}", args.listen_addr));

    // Accept incoming QUIC connections
    // Accept incoming QUIC connections
    loop {
        tokio::select! {
            accept_res = endpoint.accept() => {
               if let Some(incoming) = accept_res {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            log(&format!("Accept error: {}", e));
                            continue;
                        }
                    };

                    log(&format!("New connection from {}", conn.remote_address()));

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(conn).await {
                            log(&format!("Connection error: {}", e));
                        }
                    });
               } else {
                   break;
               }
            }
             _ = tokio::signal::ctrl_c() => {
                log("Shutting down gracefully...");
                endpoint.close(0u8.into(), b"shutting down");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_connection(conn: quinn::Connection) -> Result<(), Box<dyn std::error::Error>> {
    log(&format!(
        "handle_connection: Starting for {}",
        conn.remote_address()
    ));
    // Handle bidirectional streams from the client
    let mut stream_count = 0;
    loop {
        log(&format!(
            "handle_connection: Waiting for stream (count: {})",
            stream_count
        ));
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                stream_count += 1;
                log("handle_connection: Accepting new bidirectional stream");
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(send, recv).await {
                        log(&format!("Stream error: {}", e));
                    }
                });
            }
            Err(quinn::ConnectionError::LocallyClosed) => {
                log("handle_connection: Connection locally closed");
                break;
            }
            Err(quinn::ConnectionError::TimedOut) => {
                log("handle_connection: Connection timed out");
                break;
            }
            Err(e) => {
                log(&format!("handle_connection: Error accepting stream: {}", e));
                break;
            }
        }
    }
    log("handle_connection: Connection ended");
    Ok(())
}

async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let start = std::time::Instant::now();
    // Read proxy request (version 1, address type, address, port)
    let mut header = [0u8; 2];
    recv.read_exact(&mut header).await?;
    log(&format!(
        "handle_stream: Header read in {:?}",
        start.elapsed()
    ));

    if header[0] != PROXY_VERSION {
        return Err(format!("Unsupported version: {}", header[0]).into());
    }

    let addr_type = header[1];
    let target = match addr_type {
        0x01 => {
            let mut addr_bytes = [0u8; 4];
            recv.read_exact(&mut addr_bytes).await?;
            let mut port_bytes = [0u8; 2];
            recv.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            TargetRequest::Socket(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(addr_bytes)),
                port,
            ))
        }
        0x03 => {
            let mut len_bytes = [0u8; 1];
            recv.read_exact(&mut len_bytes).await?;
            let len = len_bytes[0] as usize;
            let mut domain_bytes = vec![0u8; len];
            recv.read_exact(&mut domain_bytes).await?;
            let mut port_bytes = [0u8; 2];
            recv.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            let domain = String::from_utf8_lossy(&domain_bytes).to_string();
            TargetRequest::Domain(domain, port)
        }
        0x04 => {
            let mut addr_bytes = [0u8; 16];
            recv.read_exact(&mut addr_bytes).await?;
            let mut port_bytes = [0u8; 2];
            recv.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            TargetRequest::Socket(SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr_bytes)),
                port,
            ))
        }
        _ => return Err(format!("Unsupported address type: {}", addr_type).into()),
    };

    log(&format!("Connecting to {}", target.description()));

    let addrs = match resolve_addresses(&target).await {
        Ok(addrs) => addrs,
        Err(e) => {
            let _ = send_proxy_reply(&mut send, STATUS_FAILURE, None).await;
            return Err(e);
        }
    };

    let target_stream = match race_connect(addrs).await {
        Ok(stream) => stream,
        Err(e) => {
            let _ = send_proxy_reply(&mut send, STATUS_FAILURE, None).await;
            return Err(e);
        }
    };

    target_stream.set_nodelay(true)?;

    let reply_addr = target_stream.local_addr().ok();
    send_proxy_reply(&mut send, STATUS_SUCCESS, reply_addr.as_ref()).await?;

    // Client -> Target
    let (mut target_read, mut target_write) = target_stream.into_split();
    let mut send = send;

    let client_to_target = async {
        let mut buf = [0u8; 4096];
        loop {
            // Quinn's read() returns Result<Option<usize>>
            // Some(0) = EOF, None = current stream finished
            let n_opt = recv.read(&mut buf).await?;
            match n_opt {
                Some(0) | None => break, // EOF or stream finished
                Some(n) => {
                    target_write.write_all(&buf[..n]).await?;
                }
            }
        }
        drop(target_write);
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };

    // Target -> Client
    let target_to_client = async {
        let mut buf = [0u8; 4096];
        loop {
            let n = target_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n]).await?;
        }
        // Finish the QUIC stream gracefully to send proper FIN to client
        let _ = send.finish().await;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };

    // Run both directions until BOTH complete - both must finish
    let _ = tokio::try_join!(client_to_target, target_to_client)?;

    log("Stream finished");
    Ok(())
}

#[derive(Clone)]
enum TargetRequest {
    Socket(SocketAddr),
    Domain(String, u16),
}

impl TargetRequest {
    fn description(&self) -> String {
        match self {
            TargetRequest::Socket(addr) => addr.to_string(),
            TargetRequest::Domain(domain, port) => format!("{}:{}", domain, port),
        }
    }
}

static DNS_CACHE: OnceLock<RwLock<HashMap<String, (std::time::Instant, Vec<SocketAddr>)>>> =
    OnceLock::new();
const DNS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

fn dns_cache() -> &'static RwLock<HashMap<String, (std::time::Instant, Vec<SocketAddr>)>> {
    DNS_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

async fn resolve_addresses(
    target: &TargetRequest,
) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    match target {
        TargetRequest::Socket(addr) => Ok(vec![*addr]),
        TargetRequest::Domain(domain, port) => {
            let addrs = resolve_domain(domain, *port).await?;
            if addrs.is_empty() {
                Err("No addresses resolved".into())
            } else {
                Ok(addrs)
            }
        }
    }
}

async fn resolve_domain(
    domain: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    let cache_key = format!("{}:{}", domain, port);
    {
        let cache = dns_cache().read().await;
        if let Some((cached_at, addrs)) = cache.get(&cache_key) {
            if cached_at.elapsed() < DNS_CACHE_TTL {
                return Ok(addrs.clone());
            }
        }
    }

    let resolved = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host((domain, port)),
    )
    .await
    {
        Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
        Ok(Err(e)) => return Err(format!("DNS lookup failed: {}", e).into()),
        Err(_) => return Err("DNS lookup timed out".into()),
    };

    // Simple bounds check: clear cache if it gets too large
    // In a real implementation this should be an LRU
    let mut cache = dns_cache().write().await;
    if cache.len() > 1000 {
        cache.clear();
    }
    cache.insert(cache_key, (std::time::Instant::now(), resolved.clone()));

    Ok(resolved)
}

async fn race_connect(
    addrs: Vec<SocketAddr>,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    if addrs.len() == 1 {
        let addr = addrs[0];
        let start = std::time::Instant::now();
        return match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                log(&format!("Connected to {} in {:?}", addr, start.elapsed()));
                Ok(stream)
            }
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out").into()),
        };
    }

    let mut tasks = tokio::task::JoinSet::new();
    for addr in addrs {
        tasks.spawn(async move {
            let start = std::time::Instant::now();
            match tokio::time::timeout(std::time::Duration::from_secs(10), TcpStream::connect(addr))
                .await
            {
                Ok(Ok(stream)) => Ok((addr, stream, start.elapsed())),
                Ok(Err(e)) => Err((addr, e, start.elapsed())),
                Err(_) => Err((
                    addr,
                    io::Error::new(io::ErrorKind::TimedOut, "connect timed out"),
                    start.elapsed(),
                )),
            }
        });
    }

    let mut last_err = None;

    while let Some(res) = tasks.join_next().await {
        match res {
             Ok(Ok((addr, stream, dur))) => {
                log(&format!("Connected to {} in {:?}", addr, dur));
                return Ok(stream);
            }
            Ok(Err((addr, e, dur))) => {
                log(&format!(
                    "Failed to connect to {} in {:?}: {}",
                    addr, dur, e
                ));
                last_err = Some(e);
            }
            Err(e) => {
                 log(&format!("Join error in race_connect: {}", e));
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "all racing attempts failed"))
        .into())
}

async fn send_proxy_reply(
    send: &mut quinn::SendStream,
    status: u8,
    addr: Option<&SocketAddr>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (atyp, addr_bytes, port) =
        addr.map(reply_address)
            .unwrap_or((ATYP_IPV4, vec![0, 0, 0, 0], 0));

    let mut buf = Vec::with_capacity(6 + addr_bytes.len());
    buf.push(PROXY_VERSION);
    buf.push(status);
    buf.push(atyp);
    buf.extend_from_slice(&addr_bytes);
    buf.extend_from_slice(&port.to_be_bytes());
    send.write_all(&buf).await?;
    send.flush().await?;
    Ok(())
}

fn reply_address(addr: &SocketAddr) -> (u8, Vec<u8>, u16) {
    match addr {
        SocketAddr::V4(v4) => (ATYP_IPV4, v4.ip().octets().to_vec(), v4.port()),
        SocketAddr::V6(v6) => (ATYP_IPV6, v6.ip().octets().to_vec(), v6.port()),
    }
}

struct Args {
    listen_addr: std::net::SocketAddr,
    profile: Option<PathBuf>,
    server_config: quinn::ServerConfig,
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let mut listen_addr = "0.0.0.0:9000".to_string();
    let mut profile = None;

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
            _ => {
                eprintln!("Usage: proxy-server --profile <file> [--listen <addr>]");
                std::process::exit(1);
            }
        }
    }

    // Load server config from profile or use test certs
    let server_config = if let Some(profile_path) = &profile {
        let profile = Profile::from_file(profile_path)?;
        build_server_config_from_profile(&profile)?
    } else {
        eprintln!("Warning: Using test certificates - use --profile for production");
        build_server_config()?
    };

    Ok(Args {
        listen_addr: listen_addr.parse()?,
        profile,
        server_config,
    })
}

fn build_server_config() -> Result<quinn::ServerConfig, Box<dyn std::error::Error>> {
    let test_cert = shared_cert::get_test_certificate();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![test_cert.cert.clone()], test_cert.key.clone())?;
    server_crypto
        .alpn_protocols
        .push(QUIC_ALPN.as_bytes().to_vec());

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    let mut transport = quinn::TransportConfig::default();
    configure_transport(&mut transport, None);
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

// For now, use the same test cert approach. In production, this would load
// certificates from the profile's server_private_key or from cert files.
fn build_server_config_from_profile(
    profile: &Profile,
) -> Result<quinn::ServerConfig, Box<dyn std::error::Error>> {
    let test_cert = shared_cert::get_test_certificate();

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![test_cert.cert.clone()], test_cert.key.clone())?;
    server_crypto
        .alpn_protocols
        .push(QUIC_ALPN.as_bytes().to_vec());

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    let mut transport = quinn::TransportConfig::default();
    configure_transport(&mut transport, profile.quic.as_ref());
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}
