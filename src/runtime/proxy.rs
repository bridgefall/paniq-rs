//! Spawnable proxy server for integration testing.
//!
//! Provides a test-friendly wrapper around the production proxy-server logic,
//! allowing the server to be started and stopped programmatically.

use std::net::SocketAddr;

use crate::kcp::server::{listen, ServerConfigWrapper};
use crate::obf::Framer;
use crate::profile::Profile;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

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
/// When dropped, the server will be gracefully shut down.
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
    pub async fn spawn(config: ProxyConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let framer = Framer::new(config.profile.obf_config())?;

        // Map profile config to server config
        let server_config = ServerConfigWrapper {
            max_packet_size: config
                .profile
                .kcp
                .as_ref()
                .map(|k| k.max_packet_size)
                .unwrap_or(1350),
            max_payload: config
                .profile
                .kcp
                .as_ref()
                .map(|k| k.max_payload)
                .unwrap_or(1200),
            transport_replay: config.profile.obfuscation.transport_replay,
            idle_timeout_secs: 120,
            handshake_timeout_secs: 5,
            handshake_attempts: 3,
            preamble_delay_ms: 5,
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
            Ok((mut send, mut recv)) => {
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(&mut send, &mut recv).await {
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
    send: &mut crate::kcp::client::SendStream,
    recv: &mut crate::kcp::client::RecvStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    // Bidirectional relay - same logic as production proxy-server
    let (mut target_read, mut target_write) = target_stream.split();

    let client_to_target = async {
        let mut buf = vec![0u8; 8192];
        loop {
            match recv.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    target_write.write_all(&buf[..n]).await?;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        target_write.shutdown().await?;
        Ok::<u64, std::io::Error>(0)
    };

    let target_to_client = async {
        let mut buf = vec![0u8; 8192];
        loop {
            match target_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    send.write_all(&buf[..n]).await?;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        // NOTE: We do NOT shutdown the KCP send side to avoid smux full close
        Ok::<u64, std::io::Error>(0)
    };

    tokio::try_join!(client_to_target, target_to_client)?;
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
        TargetSpec::Addr(addr) => Ok(tokio::net::TcpStream::connect(addr).await?),
        TargetSpec::Domain(domain, port) => {
            let addrs = tokio::net::lookup_host((domain.as_str(), port)).await?;
            Ok(connect_any(addrs).await?)
        }
    }
}

async fn connect_any<I>(
    addrs: I,
) -> Result<tokio::net::TcpStream, Box<dyn std::error::Error + Send + Sync>>
where
    I: IntoIterator<Item = SocketAddr>,
{
    let mut found = false;
    for addr in addrs {
        found = true;
        match tokio::net::TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(_) => continue,
        }
    }

    Err(Box::new(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        if found {
            "all connection attempts failed"
        } else {
            "no addresses found"
        },
    )))
}
