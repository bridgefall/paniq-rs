use std::net::SocketAddr;
use std::path::PathBuf;

use paniq::kcp::server::listen;
use paniq::kcp::server::ServerConfigWrapper;
use paniq::obf::Framer;
use paniq::profile::Profile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info_span;
use tracing::Instrument;
use tracing_subscriber::EnvFilter;

const RELAY_BUFFER_SIZE: usize = 32 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize tracing subscriber with environment filter
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = parse_args()?;
    let profile = Profile::from_file(&args.profile)?;
    let framer = Framer::new(profile.obf_config())?;

    // Map profile config to server config
    let config = ServerConfigWrapper {
        max_packet_size: profile.effective_kcp_max_packet_size(),
        max_payload: profile.effective_kcp_max_payload(),
        send_window: None,
        recv_window: None,
        target_bps: None,
        rtt_ms: None,
        max_snd_queue: None,
        transport_replay: profile.obfuscation.transport_replay,
        padding_policy: profile.transport_padding_policy(),
        idle_timeout_secs: 120,
        handshake_timeout_secs: 5,
        handshake_attempts: 3,
        preamble_delay_ms: 5,
    };

    let endpoint = listen(args.listen, framer, config).await?;
    tracing::info!(listen_addr = %endpoint.local_addr(), "proxy-server listening");

    // Accept incoming connections and handle them
    loop {
        if let Some(conn) = endpoint.accept().await {
            let peer_addr = conn.peer_addr();
            tracing::info!(peer_addr = %peer_addr, "Accepted connection");

            let span = info_span!("conn", peer_addr = %peer_addr);
            tokio::spawn(
                async move {
                    if let Err(e) = handle_connection(conn).await {
                        tracing::error!(
                            error = %e,
                            peer_addr = %peer_addr,
                            "Error handling connection"
                        );
                    }
                }
                .instrument(span),
            );
        }
    }
}

async fn handle_connection(
    conn: paniq::kcp::server::IncomingConnection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Convert to server connection
    let mut server_conn = conn.await_connection().await?;

    loop {
        // Accept new bidirectional stream
        match server_conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                tracing::info!("Accepted stream");

                tokio::spawn(async move {
                    if let Err(e) = handle_stream(&mut send, &mut recv).await {
                        tracing::error!(error = %e, "Error handling stream");
                    }
                });
            }
            Err(e) => {
                tracing::debug!(error = %e, "accept_bi error, closing connection");
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
            TargetSpec::Addr(SocketAddr::new(std::net::IpAddr::V4(addr_buf.into()), port))
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
            TargetSpec::Domain(domain, port)
        }
        0x04 => {
            // IPv6
            let mut addr_buf = [0u8; 16];
            recv.read_exact(&mut addr_buf).await?;
            let mut port_buf = [0u8; 2];
            recv.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            TargetSpec::Addr(SocketAddr::new(std::net::IpAddr::V6(addr_buf.into()), port))
        }
        _ => return Err(format!("Unknown address type: {}", addr_type).into()),
    };

    let mut target_stream = connect_target(target).await?;

    // Manual relay instead of tokio::io::copy to handle half-close properly
    tracing::info!("Starting bidirectional relay");
    let (mut target_read, mut target_write) = target_stream.split();

    // Helper function to check if an error is expected when closing a stream
    // TODO: This is a bit of a hack, but it works for now. Make sure to reimplement this properly
    fn is_expected_close_error(e: &std::io::Error) -> bool {
        if matches!(
            e.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::ConnectionAborted
        ) {
            return true;
        }
        let error_msg = e.to_string().to_lowercase();
        error_msg.contains("tx is already closed")
            || error_msg.contains("rx is already closed")
            || error_msg.contains("stream is closed")
            || error_msg.contains("connection closed")
    }

    let client_to_target = async {
        tracing::debug!("client_to_target: Starting");
        let mut buf = vec![0u8; RELAY_BUFFER_SIZE];
        let mut total = 0u64;
        loop {
            match recv.read(&mut buf).await {
                Ok(0) => {
                    tracing::debug!(bytes_in = total, "client_to_target: Got EOF from KCP recv");
                    break;
                }
                Ok(n) => {
                    tracing::trace!(bytes = n, direction = "client_to_target", "Read from KCP");
                    if let Err(e) = target_write.write_all(&buf[..n]).await {
                        if is_expected_close_error(&e) {
                            break;
                        }
                        return Err(e);
                    }
                    total += n as u64;
                }
                Err(e) => {
                    if is_expected_close_error(&e) {
                        break;
                    }
                    tracing::error!(error = %e, "client_to_target: Read error");
                    return Err(e);
                }
            }
        }
        tracing::debug!("client_to_target: Shutting down TCP write");
        target_write.shutdown().await?;
        tracing::debug!("client_to_target: Complete");
        Ok::<u64, std::io::Error>(total)
    };

    let target_to_client = async {
        tracing::debug!("target_to_client: Starting");
        let mut buf = vec![0u8; RELAY_BUFFER_SIZE];
        let mut total = 0u64;
        loop {
            match target_read.read(&mut buf).await {
                Ok(0) => {
                    tracing::debug!(bytes_out = total, "target_to_client: Got EOF from TCP read");
                    break;
                }
                Ok(n) => {
                    tracing::trace!(bytes = n, direction = "target_to_client", "Read from TCP");
                    if send.write_all(&buf[..n]).await.is_err() {
                        // KCP/smux may close send side at any time; treat as clean shutdown.
                        break;
                    }
                    total += n as u64;
                }
                Err(e) => {
                    if is_expected_close_error(&e) {
                        break;
                    }
                    tracing::error!(error = %e, "target_to_client: Read error");
                    return Err(e);
                }
            }
        }
        tracing::debug!("target_to_client: NOT shutting down KCP send (avoid smux full close)");
        tracing::debug!("target_to_client: Complete");
        Ok::<u64, std::io::Error>(total)
    };

    tracing::debug!("Launching both relay tasks");
    let result = tokio::try_join!(client_to_target, target_to_client);

    match result {
        Ok((sent, received)) => {
            tracing::info!(bytes_out = sent, bytes_in = received, "Relay complete");
        }
        Err(e) => {
            tracing::error!(error = %e, "Relay error");
            return Err(e.into());
        }
    }

    Ok(())
}

enum TargetSpec {
    Addr(SocketAddr),
    Domain(String, u16),
}

async fn connect_target(
    target: TargetSpec,
) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    match target {
        TargetSpec::Addr(addr) => {
            tracing::debug!(target_addr = %addr, "Connecting to target");
            Ok(tokio::net::TcpStream::connect(addr).await?)
        }
        TargetSpec::Domain(domain, port) => {
            tracing::debug!(target_addr = %format!("{}:{}", domain, port), "Connecting to target");
            let addrs = tokio::net::lookup_host((domain.as_str(), port)).await?;
            Ok(connect_any(addrs).await?)
        }
    }
}

async fn connect_any<I>(addrs: I) -> Result<tokio::net::TcpStream, std::io::Error>
where
    I: IntoIterator<Item = SocketAddr>,
{
    let mut last_err = None;
    let mut found = false;
    for addr in addrs {
        found = true;
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            if found {
                "all connection attempts failed"
            } else {
                "no addresses found"
            },
        )
    }))
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
