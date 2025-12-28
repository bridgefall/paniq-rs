// Proxy Server - accepts obfuscated QUIC connections and forwards to destinations
use std::sync::Arc;
use std::path::PathBuf;

// use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use paniq::quic::server::listen_on_socket;
use paniq::obf::Framer;
use paniq::profile::Profile;

mod shared_cert;

fn log(msg: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    eprintln!("[{}.{:03}] proxy-server: {}", now.as_secs(), now.subsec_millis(), msg);
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
    while let Some(incoming) = endpoint.accept().await {
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
    }

    Ok(())
}

async fn handle_connection(conn: quinn::Connection) -> Result<(), Box<dyn std::error::Error>> {
    log(&format!("handle_connection: Starting for {}", conn.remote_address()));
    // Handle bidirectional streams from the client
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
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
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read proxy request (version 1, address type, address, port)
    let mut header = [0u8; 2];
    recv.read_exact(&mut header).await?;

    if header[0] != 0x01 {
        return Err(format!("Unsupported version: {}", header[0]).into());
    }

    let addr_type = header[1];
    let target_str: String = match addr_type {
        0x01 => {
            // IPv4
            let mut addr_bytes = [0u8; 4];
            recv.read_exact(&mut addr_bytes).await?;
            let mut port_bytes = [0u8; 2];
            recv.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            format!("{}:{}", std::net::Ipv4Addr::from(addr_bytes), port)
        }
        0x03 => {
            // Domain
            let mut len_bytes = [0u8; 1];
            recv.read_exact(&mut len_bytes).await?;
            let len = len_bytes[0] as usize;
            let mut domain_bytes = vec![0u8; len];
            recv.read_exact(&mut domain_bytes).await?;
            let mut port_bytes = [0u8; 2];
            recv.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            let domain = String::from_utf8_lossy(&domain_bytes).to_string();
            format!("{}:{}", domain, port)
        }
        0x04 => {
            // IPv6
            let mut addr_bytes = [0u8; 16];
            recv.read_exact(&mut addr_bytes).await?;
            let mut port_bytes = [0u8; 2];
            recv.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);
            format!("{}:{}", std::net::Ipv6Addr::from(addr_bytes), port)
        }
        _ => return Err(format!("Unsupported address type: {}", addr_type).into()),
    };

    log(&format!("Connecting to {}", target_str));

    // Connect to the target using Happy Eyeballs (Race connections)
    let addrs = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host(&target_str)
    ).await {
        Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
        Ok(Err(e)) => return Err(format!("DNS lookup failed: {}", e).into()),
        Err(_) => return Err("DNS lookup timed out".into()),
    };

    if addrs.is_empty() {
        return Err("No addresses resolved".into());
    }

    let target_stream = {
        let mut tasks = tokio::task::JoinSet::new();
        for addr in addrs {
            tasks.spawn(async move {
                let start = std::time::Instant::now();
                match tokio::time::timeout(std::time::Duration::from_secs(10), tokio::net::TcpStream::connect(addr)).await {
                    Ok(Ok(stream)) => Ok((addr, stream, start.elapsed())),
                    Ok(Err(e)) => Err((addr, e, start.elapsed())),
                    Err(_) => Err((addr, std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"), start.elapsed())),
                }
            });
        }

        let mut success = None;
        let mut last_err = None;

        while let Some(res) = tasks.join_next().await {
             match res.unwrap() {
                 Ok((addr, stream, dur)) => {
                     log(&format!("Connected to {} in {:?}", addr, dur));
                     success = Some(stream);
                     break;
                 }
                 Err((addr, e, dur)) => {
                     log(&format!("Failed to connect to {} in {:?}: {}", addr, dur, e));
                     last_err = Some(e);
                 }
             }
        }

        match success {
            Some(s) => s,
            None => return Err(last_err.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "all racing attempts failed")).into()),
        }
    };

    target_stream.set_nodelay(true)?;

    // Client -> Target
    let (mut target_read, mut target_write) = target_stream.into_split();
    let mut send = send;

    let client_to_target = async {
        let mut buf = [0u8; 4096];
        loop {
            let n = recv.read(&mut buf).await?;
            match n {
                Some(0) | None => break,
                Some(n) => {
                    target_write.write_all(&buf[..n]).await?;
                    target_write.flush().await?;
                }
            }
        }
        target_write.shutdown().await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };

    // Target -> Client
    let target_to_client = async {
        let mut buf = [0u8; 4096];
        loop {
            let n = target_read.read(&mut buf).await?;
            if n == 0 { break; }
            send.write_all(&buf[..n]).await?;
            send.flush().await?;
        }
        send.finish().await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    };

    // Wait for either direction to complete
    let _ = tokio::select! {
        res = client_to_target => res,
        res = target_to_client => res,
    };

    log("Stream finished");
    Ok(())
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
                listen_addr = args[i + 1].clone();
                i += 2;
            }
            "--profile" => {
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

    let server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![test_cert.cert.clone()], test_cert.key.clone())?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(quinn::VarInt::from_u32(30_000).into()));
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(1)));
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

// For now, use the same test cert approach. In production, this would load
// certificates from the profile's server_private_key or from cert files.
fn build_server_config_from_profile(_profile: &Profile) -> Result<quinn::ServerConfig, Box<dyn std::error::Error>> {
    build_server_config()
}
