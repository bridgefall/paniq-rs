use clap::Parser;
use paniq::config::{FileConfig, ProxyFileConfig};
use std::net::SocketAddr;
use std::path::PathBuf;

use paniq::kcp::server::listen;
use paniq::kcp::server::ServerConfigWrapper;
use paniq::obf::Framer;
use paniq::profile::Profile;
use paniq::proxy_protocol::{
    ADDR_TYPE_DOMAIN, ADDR_TYPE_IPV4, ADDR_TYPE_IPV6, DOMAIN_LEN_SIZE, IPV4_ADDR_SIZE,
    IPV6_ADDR_SIZE, PORT_SIZE, PROTOCOL_VERSION, REPLY_GENERAL_FAILURE, REPLY_SUCCESS,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info_span;
use tracing::Instrument;
use tracing_subscriber::EnvFilter;

const RELAY_BUFFER_SIZE: usize = 32 * 1024;

const DRAIN_BUFFER_SIZE: usize = 1024;
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    // Load daemon config if provided
    let daemon_config = if let Some(config_path) = &args.config {
        ProxyFileConfig::load_from_file(config_path)?
    } else {
        ProxyFileConfig::default()
    };

    // Initialize tracing with config log level
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(daemon_config.log_level_as_tracing().into())
                .from_env_lossy(),
        )
        .init();

    // CLI args override config file values
    let profile_path = args.profile.clone();

    let profile = Profile::from_file(&profile_path)?;
    let framer = Framer::new(profile.obf_config())?;

    // Map profile config to server config
    let kcp_profile = profile.kcp.clone().unwrap_or_default();
    let config = ServerConfigWrapper {
        max_packet_size: profile.effective_kcp_max_packet_size(),
        max_payload: profile.effective_kcp_max_payload(),
        send_window: kcp_profile.send_window,
        recv_window: kcp_profile.recv_window,
        target_bps: kcp_profile.target_bps,
        rtt_ms: kcp_profile.rtt_ms,
        max_snd_queue: kcp_profile.max_snd_queue,
        transport_replay: profile.obfuscation.transport_replay,
        padding_policy: profile.transport_padding_policy(),
        idle_timeout_secs: 120,
        handshake_timeout_secs: profile.handshake_timeout_or_default().as_secs(),
        handshake_attempts: profile.handshake_attempts,
        preamble_delay_ms: profile.preamble_delay_ms_or_default(),
        flush_interval_ms: kcp_profile.flush_interval_ms,
    };

    let listen_addr: SocketAddr = args.listen.unwrap_or_else(|| {
        daemon_config
            .listen_addr
            .parse()
            .expect("invalid listen_addr in config")
    });

    let endpoint = listen(listen_addr, framer, config).await?;
    tracing::info!(listen_addr = %endpoint.local_addr(), "proxy-server listening");

    // Start control server if control socket is provided
    let control_socket: Option<PathBuf> = args
        .control_socket
        .clone()
        .or_else(|| daemon_config.control_socket.clone().map(PathBuf::from))
        .or_else(|| {
            // Try to get control socket from environment if not provided via config/CLI
            std::env::var("PANIQ_CONTROL_SOCKET")
                .ok()
                .map(PathBuf::from)
        });

    if let Some(control_socket) = &control_socket {
        let control_server = paniq::control::ControlServer::bind(control_socket)?;
        tracing::info!(socket = %control_socket.display(), "Control server listening");
        tokio::spawn(async move {
            if let Err(e) = control_server.run().await {
                tracing::error!(error = %e, "Control server error");
            }
        });
    }

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
    // Read protocol version and command
    let mut buf = [0u8; 2];
    recv.read_exact(&mut buf).await?;
    let version = buf[0];
    let _cmd = buf[1]; // Command byte (currently unused but required by protocol)

    if version != PROTOCOL_VERSION {
        return Err(format!("Unsupported protocol version: {}", version).into());
    }

    // Read address type
    let mut addr_type_buf = [0u8; 1];
    recv.read_exact(&mut addr_type_buf).await?;
    let addr_type = addr_type_buf[0];

    let target = match addr_type {
        ADDR_TYPE_IPV4 => {
            // IPv4
            let mut addr_buf = [0u8; IPV4_ADDR_SIZE];
            recv.read_exact(&mut addr_buf).await?;
            let mut port_buf = [0u8; PORT_SIZE];
            recv.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            TargetSpec::Addr(SocketAddr::new(std::net::IpAddr::V4(addr_buf.into()), port))
        }
        ADDR_TYPE_DOMAIN => {
            // Domain
            let mut len_buf = [0u8; DOMAIN_LEN_SIZE];
            recv.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut domain_buf = vec![0u8; len];
            recv.read_exact(&mut domain_buf).await?;
            let domain = String::from_utf8(domain_buf)?;
            let mut port_buf = [0u8; PORT_SIZE];
            recv.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            TargetSpec::Domain(domain, port)
        }
        ADDR_TYPE_IPV6 => {
            // IPv6
            let mut addr_buf = [0u8; IPV6_ADDR_SIZE];
            recv.read_exact(&mut addr_buf).await?;
            let mut port_buf = [0u8; PORT_SIZE];
            recv.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            TargetSpec::Addr(SocketAddr::new(std::net::IpAddr::V6(addr_buf.into()), port))
        }
        _ => return Err(format!("Unknown address type: {}", addr_type).into()),
    };

    let target_str = format!("{:?}", target);

    let mut target_stream = match connect_target(target).await {
        Ok(stream) => {
            send.write_all(&[REPLY_SUCCESS]).await?;
            stream
        }
        Err(e) => {
            tracing::warn!(target = %target_str, error = %e, "Failed to connect to target");
            let _ = send.write_all(&[REPLY_GENERAL_FAILURE]).await;

            // Drain unread data from recv to avoid "bytes remaining on stream" error
            // which kills the whole session in async_smux.
            let mut drain_buf = [0u8; DRAIN_BUFFER_SIZE];
            let _ = tokio::time::timeout(DRAIN_TIMEOUT, async {
                loop {
                    match recv.read(&mut drain_buf).await {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
            })
            .await;

            return Err(e);
        }
    };

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

#[derive(Debug, Clone)]
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

#[derive(Parser, Debug)]
#[command(author, version, about = "Paniq proxy server", long_about = None)]
struct Args {
    #[arg(short, long, help = "Path to daemon config JSON file")]
    config: Option<PathBuf>,

    #[arg(short, long, help = "Listen address (e.g. 0.0.0.0:9000)")]
    listen: Option<SocketAddr>,

    #[arg(short, long, help = "Path to profile JSON file")]
    profile: PathBuf,

    #[arg(long, help = "Path to control Unix domain socket")]
    control_socket: Option<PathBuf>,
}
