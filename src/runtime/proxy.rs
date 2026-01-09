//! Spawnable proxy server for integration testing.
//!
//! Provides a test-friendly wrapper around the production proxy-server logic,
//! allowing the server to be started and stopped programmatically.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::kcp::server::{listen, ServerConfigWrapper};
use crate::obf::Framer;
use crate::profile::Profile;
use crate::proxy_protocol::{
    ADDR_TYPE_DOMAIN, ADDR_TYPE_IPV4, ADDR_TYPE_IPV6, DOMAIN_LEN_SIZE, IPV4_ADDR_SIZE,
    IPV6_ADDR_SIZE, PORT_SIZE, PROTOCOL_VERSION, REPLY_GENERAL_FAILURE, REPLY_SUCCESS,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

// ===== Protocol Constants =====

// ===== Buffer Sizes =====

/// Relay buffer size for bidirectional data transfer (32 KB).
/// Chosen to balance throughput vs memory per stream.
use crate::io::{is_expected_close_error, DEFAULT_RELAY_BUFFER_SIZE as RELAY_BUFFER_SIZE};

// ===== Default Configuration Values =====

/// Default connection idle timeout in seconds
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 120;

/// Default handshake timeout in seconds
const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 5;

/// Default number of handshake attempts
const DEFAULT_HANDSHAKE_ATTEMPTS: usize = 3;

/// Default preamble delay in milliseconds
const DEFAULT_PREAMBLE_DELAY_MS: u64 = 5;

/// Configuration for spawning a proxy server.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to listen on (e.g., "127.0.0.1:0" for automatic port assignment)
    pub listen_addr: SocketAddr,
    /// Profile configuration (can be loaded from file or constructed for tests)
    pub profile: Profile,
}

impl ProxyConfig {
    /// Create a new proxy config with a test profile.
    pub fn new_test(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            profile: Profile::test_profile(),
        }
    }
}

/// Handle to a running proxy server.
///
/// When dropped, the server will be gracefully shut down via cancellation token.
/// Note: Drop cannot wait for async shutdown to complete, so the server task
/// is cancelled but may not finish before the handle is dropped. For clean
/// shutdown in tests, call `wait()` explicitly before dropping.
pub struct ProxyHandle {
    /// The address the server is listening on.
    pub addr: SocketAddr,

    shutdown: CancellationToken,
    task: Option<JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>>,
}

impl ProxyHandle {
    /// Spawn a new proxy server with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Proxy configuration
    ///
    /// # Returns
    ///
    /// A `ProxyHandle` that can be used to manage the server's lifecycle.
    pub async fn spawn(
        config: ProxyConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let framer = Framer::new(config.profile.obf_config())?;

        // Map profile config to server config
        let server_config = ServerConfigWrapper {
            max_packet_size: config.profile.effective_kcp_max_packet_size(),
            max_payload: config.profile.effective_kcp_max_payload(),
            send_window: config.profile.kcp.as_ref().and_then(|k| k.send_window),
            recv_window: config.profile.kcp.as_ref().and_then(|k| k.recv_window),
            target_bps: config.profile.kcp.as_ref().and_then(|k| k.target_bps),
            rtt_ms: config.profile.kcp.as_ref().and_then(|k| k.rtt_ms),
            max_snd_queue: config.profile.kcp.as_ref().and_then(|k| k.max_snd_queue),
            transport_replay: config.profile.obfuscation.transport_replay,
            padding_policy: config.profile.transport_padding_policy(),
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
            handshake_timeout_secs: DEFAULT_HANDSHAKE_TIMEOUT_SECS,
            handshake_attempts: DEFAULT_HANDSHAKE_ATTEMPTS,
            preamble_delay_ms: DEFAULT_PREAMBLE_DELAY_MS,
            flush_interval_ms: config
                .profile
                .kcp
                .as_ref()
                .map(|k| k.flush_interval_ms)
                .unwrap_or(10),
        };

        let endpoint = listen(config.listen_addr, framer, server_config).await?;
        let addr = endpoint.local_addr();
        let shutdown = CancellationToken::new();

        let task = tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                // Accept incoming connections until shutdown is requested
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => {
                            info!("Proxy server shutdown requested");
                            endpoint.shutdown();
                            break;
                        }
                        maybe = endpoint.accept() => {
                            if let Some(conn) = maybe {
                                let peer_addr = conn.peer_addr();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_connection(conn).await {
                                        warn!(error = %e, peer_addr = %peer_addr, "Error handling connection");
                                    }
                                });
                            }
                        }
                    }
                }
                Ok(())
            }
        });

        info!(listen_addr = %addr, "Proxy server started");

        Ok(Self {
            addr,
            shutdown,
            task: Some(task),
        })
    }

    /// Request graceful shutdown of the proxy server.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    /// Wait for the proxy server task to complete.
    ///
    /// This is useful for ensuring clean shutdown in tests.
    pub async fn wait(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Take the task so Drop doesn't try to cancel it
        if let Some(task) = self.task.take() {
            return task.await?;
        }
        Ok(())
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        // Only cancel if the task hasn't been taken (e.g., by wait())
        if self.task.is_some() {
            self.shutdown();
        }
    }
}

/// Handle a single KCP connection from the proxy server.
///
/// This is the production code path from `bin/proxy-server.rs`, extracted
/// for reuse in tests and the binary.
async fn handle_connection(
    conn: crate::kcp::server::IncomingConnection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut server_conn = conn.await_connection().await?;

    loop {
        // Accept new bidirectional stream
        match server_conn.accept_bi().await {
            Ok((send, recv)) => {
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(send, recv).await {
                        warn!(error = %e, "Error handling stream");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "accept_bi error, closing connection");
                break;
            }
        }
    }
    Ok(())
}

/// Handle a single bidirectional stream (proxy protocol).
///
/// This implements the custom proxy protocol used between socks5d and proxy-server.
async fn handle_stream(
    mut send: crate::kcp::client::SendStream,
    mut recv: crate::kcp::client::RecvStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read protocol version and command
    let mut buf = [0u8; 2];
    recv.read_exact(&mut buf).await?;
    let version = buf[0];
    let cmd = buf[1];

    if version != PROTOCOL_VERSION {
        return Err(format!("Unsupported protocol version: {}", version).into());
    }

    // Read address type
    let mut addr_type_buf = [0u8; DOMAIN_LEN_SIZE];
    recv.read_exact(&mut addr_type_buf).await?;
    let addr_type = addr_type_buf[0];

    let target = match addr_type {
        ADDR_TYPE_IPV4 => {
            let mut addr_buf = [0u8; IPV4_ADDR_SIZE];
            recv.read_exact(&mut addr_buf).await?;
            let mut port_buf = [0u8; PORT_SIZE];
            recv.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            TargetSpec::Addr(SocketAddr::new(std::net::IpAddr::V4(addr_buf.into()), port))
        }
        ADDR_TYPE_DOMAIN => {
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
            let mut addr_buf = [0u8; IPV6_ADDR_SIZE];
            recv.read_exact(&mut addr_buf).await?;
            let mut port_buf = [0u8; PORT_SIZE];
            recv.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            TargetSpec::Addr(SocketAddr::new(std::net::IpAddr::V6(addr_buf.into()), port))
        }
        _ => return Err(format!("Unknown address type: {}", addr_type).into()),
    };

    if cmd == crate::proxy_protocol::CMD_UDP_ASSOCIATE {
        return handle_udp_associate(send, recv, target).await;
    }

    let mut target_stream = match connect_target(target).await {
        Ok(stream) => {
            if let Err(e) = send.write_all(&[REPLY_SUCCESS]).await {
                return Err(e.into());
            }
            stream
        }
        Err(e) => {
            let _ = send.write_all(&[REPLY_GENERAL_FAILURE]).await;
            return Err(e);
        }
    };

    let (mut target_read, mut target_write) = target_stream.split();

    // Bidirectional relay with optimized buffer sizes for high throughput.

    let client_to_target = async {
        let mut buf = vec![0u8; RELAY_BUFFER_SIZE];
        loop {
            match recv.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = target_write.write_all(&buf[..n]).await {
                        // Treat expected close errors as clean shutdown
                        if is_expected_close_error(&e) {
                            break;
                        }
                        return Err(e);
                    }
                }
                Err(e) => {
                    // Treat expected close errors as clean shutdown
                    if is_expected_close_error(&e) {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        // Best-effort shutdown of target write side
        let _ = target_write.shutdown().await;
        Ok::<(), std::io::Error>(())
    };

    let target_to_client = async {
        let mut buf = vec![0u8; RELAY_BUFFER_SIZE];
        loop {
            match target_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if send.write_all(&buf[..n]).await.is_err() {
                        // Treat ALL KCP write errors as expected - the smux layer
                        // manages stream lifecycle and may close streams at any time.
                        // We don't want write errors to fail the entire relay.
                        break;
                    }
                }
                Err(e) => {
                    // Treat expected close errors as clean shutdown
                    if is_expected_close_error(&e) {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        // Do NOT shutdown KCP send side - let smux manage stream lifecycle
        Ok::<(), std::io::Error>(())
    };

    tokio::try_join!(client_to_target, target_to_client)?;
    Ok(())
}

async fn handle_udp_associate(
    mut send: crate::kcp::client::SendStream,
    recv: crate::kcp::client::RecvStream,
    _target: TargetSpec,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    // Send success reply
    send.write_all(&[REPLY_SUCCESS]).await?;

    let socket_send = socket.clone();

    // Stream to UDP
    let mut recv_udp = recv;
    let stream_to_udp = async move {
        let mut len_buf = [0u8; 2];
        loop {
            if let Err(e) = recv_udp.read_exact(&mut len_buf).await {
                if is_expected_close_error(&e) {
                    break;
                }
                return Err(e);
            }
            let len = u16::from_be_bytes(len_buf) as usize;

            // Security: Enforce maximum packet size (RELAY_BUFFER_SIZE + SOCKS5 overhead)
            if len > RELAY_BUFFER_SIZE + 512 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "UDP packet too large",
                ));
            }

            let mut packet = vec![0u8; len];
            recv_udp.read_exact(&mut packet).await?;

            // Packet contains SOCKS5 UDP header + payload
            match fast_socks5::parse_udp_request(&packet).await {
                Ok((_frag, target_addr, payload)) => {
                    let addr = match target_addr {
                        fast_socks5::util::target_addr::TargetAddr::Ip(addr) => addr,
                        fast_socks5::util::target_addr::TargetAddr::Domain(domain, port) => {
                            match tokio::net::lookup_host((domain.as_str(), port)).await {
                                Ok(mut addrs) => addrs.next().unwrap_or(SocketAddr::new(
                                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                                    0,
                                )),
                                Err(_) => continue,
                            }
                        }
                    };
                    let _ = socket_send.send_to(payload, addr).await;
                }
                Err(_) => continue,
            }
        }
        Ok::<(), std::io::Error>(())
    };

    // UDP to Stream
    let mut send_udp = send;
    let socket_recv = socket.clone();
    let udp_to_stream = async move {
        let mut buf = vec![0u8; RELAY_BUFFER_SIZE];
        loop {
            match socket_recv.recv_from(&mut buf).await {
                Ok((n, peer)) => {
                    // Create SOCKS5 UDP header
                    let header =
                        fast_socks5::new_udp_header(peer).map_err(std::io::Error::other)?;
                    let total_len = header.len() + n;
                    send_udp
                        .write_all(&(total_len as u16).to_be_bytes())
                        .await?;
                    send_udp.write_all(&header).await?;
                    send_udp.write_all(&buf[..n]).await?;
                }
                Err(e) => return Err(e),
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    };

    tokio::try_join!(stream_to_udp, udp_to_stream)?;
    Ok(())
}

#[derive(Debug)]
enum TargetSpec {
    Addr(SocketAddr),
    Domain(String, u16),
}

async fn connect_target(
    target: TargetSpec,
) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    match target {
        TargetSpec::Addr(addr) => {
            let stream = tokio::net::TcpStream::connect(addr).await?;
            Ok(optimize_tcp_stream(stream)?)
        }
        TargetSpec::Domain(domain, port) => {
            let addrs = tokio::net::lookup_host((domain.as_str(), port)).await?;
            // connect_any already applies optimize_tcp_stream
            connect_any(addrs).await
        }
    }
}

async fn connect_any<I>(
    addrs: I,
) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error + Send + Sync>>
where
    I: IntoIterator<Item = SocketAddr>,
{
    // Collect addresses so we can include them in error messages
    let addrs: Vec<_> = addrs.into_iter().collect();

    for addr in &addrs {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => return Ok(optimize_tcp_stream(stream)?),
            Err(_) => continue,
        }
    }

    Err(Box::new(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        if addrs.is_empty() {
            "no addresses found".to_string()
        } else {
            format!("all connection attempts failed for addresses: {:?}", addrs)
        },
    )))
}

/// Apply TCP optimizations for high-throughput proxy connections.
///
/// These optimizations match Go's net.Dialer behavior and are critical
/// for achieving comparable throughput:
/// - TCP_NODELAY disables Nagle's algorithm (200ms delay for small packets)
fn optimize_tcp_stream(
    stream: tokio::net::TcpStream,
) -> Result<tokio::net::TcpStream, std::io::Error> {
    // Disable Nagle's algorithm - critical for low-latency proxy traffic
    stream.set_nodelay(true)?;
    Ok(stream)
}
