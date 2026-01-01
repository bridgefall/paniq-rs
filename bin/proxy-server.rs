use std::net::SocketAddr;
use std::path::PathBuf;

use tokio::io::AsyncReadExt;
use paniq::kcp::server::listen;
use paniq::kcp::server::ServerConfigWrapper;
use paniq::profile::Profile;
use paniq::obf::Framer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = parse_args()?;
    let profile = Profile::from_file(&args.profile)?;
    let framer = Framer::new(profile.obf_config())?;

    // Map profile config to server config
    let config = ServerConfigWrapper {
        max_packet_size: profile.kcp.as_ref().map(|k| k.max_packet_size).unwrap_or(1350),
        max_payload: profile.kcp.as_ref().map(|k| k.max_payload).unwrap_or(1200),
        transport_replay: profile.obfuscation.transport_replay,
        idle_timeout_secs: 120,
        handshake_timeout_secs: 5,
        handshake_attempts: 3,
        preamble_delay_ms: 5,
    };

    let endpoint = listen(args.listen, framer, config).await?;
    eprintln!("proxy-server listening on {}", endpoint.local_addr());

    // Accept incoming connections and handle them
    loop {
        if let Some(conn) = endpoint.accept().await {
            eprintln!("Accepted connection from {}", conn.peer_addr());
            let peer_addr = conn.peer_addr();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(conn).await {
                    eprintln!("Error handling connection from {}: {:?}", peer_addr, e);
                }
            });
        }
    }
}

async fn handle_connection(conn: paniq::kcp::server::IncomingConnection) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Convert to server connection
    let mut server_conn = conn.await_connection().await?;

    loop {
        // Accept new bidirectional stream
        match server_conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                eprintln!("Accepted stream from {}", server_conn.peer_addr());

                tokio::spawn(async move {
                    if let Err(e) = handle_stream(&mut send, &mut recv).await {
                        eprintln!("Error handling stream: {:?}", e);
                    }
                });
            }
            Err(_) => {
                // No more streams
                break;
            }
        }
    }
    Ok(())
}

async fn handle_stream(
    send: &mut paniq::kcp::client::SendStream,
    recv: &mut paniq::kcp::client::RecvStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read protocol version and target address
    let mut buf = [0u8; 1];
    recv.read_exact(&mut buf).await?;
    let version = buf[0];

    if version != 0x01 {
        return Err(format!("Unsupported protocol version: {}", version).into());
    }

    // Read address type
    let mut addr_type_buf = [0u8; 1];
    recv.read_exact(&mut addr_type_buf).await?;
    let addr_type = addr_type_buf[0];

    let target = match addr_type {
        0x01 => {
            // IPv4
            let mut addr_buf = [0u8; 4];
            recv.read_exact(&mut addr_buf).await?;
            let mut port_buf = [0u8; 2];
            recv.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            SocketAddr::new(std::net::IpAddr::V4(addr_buf.into()), port)
        }
        0x03 => {
            // Domain
            let mut len_buf = [0u8; 1];
            recv.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut domain_buf = vec![0u8; len];
            recv.read_exact(&mut domain_buf).await?;
            let domain = String::from_utf8(domain_buf)?;
            let mut port_buf = [0u8; 2];
            recv.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            // Resolve domain
            let addr = tokio::net::lookup_host((&domain[..], port)).await?
                .next()
                .ok_or_else(|| format!("No addresses found for {}", domain))?;
            addr
        }
        0x04 => {
            // IPv6
            let mut addr_buf = [0u8; 16];
            recv.read_exact(&mut addr_buf).await?;
            let mut port_buf = [0u8; 2];
            recv.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            SocketAddr::new(std::net::IpAddr::V6(addr_buf.into()), port)
        }
        _ => return Err(format!("Unknown address type: {}", addr_type).into()),
    };

    eprintln!("Connecting to {}", target);

    // Connect to target
    let mut target_stream = tokio::net::TcpStream::connect(target).await?;

    // Relay data bidirectionally
    let (mut target_read, mut target_write) = tokio::io::split(&mut target_stream);

    let (res1, res2) = tokio::join!(
        tokio::io::copy(recv, &mut target_write),
        tokio::io::copy(&mut target_read, send)
    );

    let sent = res1.unwrap_or(0);
    let recv = res2.unwrap_or(0);
    eprintln!("Relay finished: {} bytes sent, {} bytes received", sent, recv);

    Ok(())
}

struct Args {
    listen: SocketAddr,
    profile: PathBuf,
}

fn parse_args() -> Result<Args, pico_args::Error> {
    let mut pargs = pico_args::Arguments::from_env();
    let listen = pargs.value_from_str(["-l", "--listen"])?;
    let profile: PathBuf = pargs.value_from_str(["-p", "--profile"])?;

    Ok(Args { listen, profile })
}
