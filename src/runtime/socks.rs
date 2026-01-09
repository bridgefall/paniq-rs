//! Spawnable SOCKS5 server for integration testing.
//!
//! Provides a test-friendly wrapper around the production socks5d logic,
//! allowing the server to be started and stopped programmatically.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::client::PaniqClient;
// use crate::io::PaniqStream; // unused in this module
use crate::kcp::client::ClientConfigWrapper;
use crate::profile::Profile;
use crate::proxy_protocol::{
    ADDR_TYPE_DOMAIN, ADDR_TYPE_IPV4, ADDR_TYPE_IPV6, PROTOCOL_VERSION, REPLY_SUCCESS,
};
use crate::socks5::{AuthConfig, IoStream, RelayConnector, Socks5Server, SocksError, TargetAddr};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Configuration for spawning a SOCKS5 server.
#[derive(Debug, Clone)]
pub struct SocksConfig {
    /// Address to listen on (e.g., "127.0.0.1:0" for automatic port assignment)
    pub listen_addr: SocketAddr,
    /// Profile configuration (used to get proxy_addr and KCP settings)
    pub profile: Profile,
    /// Optional authentication credentials (username, password)
    pub auth: Option<(String, String)>,
}

impl SocksConfig {
    /// Create a new SOCKS5 config with test defaults.
    pub fn new_test(listen_addr: SocketAddr, proxy_addr: SocketAddr) -> Self {
        let mut profile = Profile::test_profile();
        profile.proxy_addr = proxy_addr.to_string();
        Self {
            listen_addr,
            profile,
            auth: Some(("user".to_string(), "pass".to_string())),
        }
    }
}

/// Handle to a running SOCKS5 server.
pub struct SocksHandle {
    /// The address the server is listening on.
    pub addr: SocketAddr,

    shutdown: CancellationToken,
    task: Option<JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>>,
}

impl SocksHandle {
    /// Spawn a new SOCKS5 server with the given configuration.
    pub async fn spawn(
        config: SocksConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let obf_config = config.profile.obf_config();
        let server_addr = config.profile.proxy_addr.parse()?;

        // Map profile config to client config
        let client_config = ClientConfigWrapper {
            max_packet_size: config.profile.effective_kcp_max_packet_size(),
            max_payload: config.profile.effective_kcp_max_payload(),
            send_window: config.profile.kcp.as_ref().and_then(|k| k.send_window),
            recv_window: config.profile.kcp.as_ref().and_then(|k| k.recv_window),
            target_bps: config.profile.kcp.as_ref().and_then(|k| k.target_bps),
            rtt_ms: config.profile.kcp.as_ref().and_then(|k| k.rtt_ms),
            max_snd_queue: config.profile.kcp.as_ref().and_then(|k| k.max_snd_queue),
            transport_replay: config.profile.obfuscation.transport_replay,
            padding_policy: config.profile.transport_padding_policy(),
            handshake_timeout_secs: 5,
            handshake_attempts: 3,
            preamble_delay_ms: 5,
            flush_interval_ms: config
                .profile
                .kcp
                .as_ref()
                .map(|k| k.flush_interval_ms)
                .unwrap_or(10),
        };
        let relay_buffer_size = client_config.max_payload;

        let client = Arc::new(PaniqClient::new(server_addr, obf_config, client_config));
        let connector = PaniqConnector::new(client.clone());

        let auth = config
            .auth
            .map(|(user, pass)| {
                let mut users = std::collections::HashMap::new();
                users.insert(user, pass);
                AuthConfig { users }
            })
            .unwrap_or_default();

        let server = Arc::new(Socks5Server::new_with_relay_buffer(
            connector,
            auth,
            relay_buffer_size,
        ));
        let listener = TcpListener::bind(&config.listen_addr).await?;
        let addr = listener.local_addr()?;

        let shutdown = CancellationToken::new();

        let task = tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => {
                            info!("SOCKS5 server shutdown requested");
                            // Explicitly close the client to release the UDP socket
                            client.close().await;
                            break;
                        }
                        result = listener.accept() => {
                            match result {
                                Ok((stream, _addr)) => {
                                    let server = server.clone();
                                    tokio::spawn(async move {
                                        let _ = server.serve_stream(stream).await;
                                    });
                                }
                                Err(e) => {
                                    return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
                                }
                            }
                        }
                    }
                }
                Ok(())
            }
        });

        info!(listen_addr = %addr, proxy_addr = %server_addr, "SOCKS5 server started");

        Ok(Self {
            addr,
            shutdown,
            task: Some(task),
        })
    }

    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    pub async fn wait(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(task) = self.task.take() {
            return task.await?;
        }
        Ok(())
    }
}

impl Drop for SocksHandle {
    fn drop(&mut self) {
        if self.task.is_some() {
            self.shutdown();
        }
    }
}

struct PaniqConnector {
    client: Arc<PaniqClient>,
}

impl PaniqConnector {
    fn new(client: Arc<PaniqClient>) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl RelayConnector for PaniqConnector {
    async fn connect(&self, target: &TargetAddr) -> Result<Box<dyn IoStream + Send>, SocksError> {
        let mut buf = Vec::new();
        buf.push(PROTOCOL_VERSION);

        let port = match target {
            TargetAddr::Ip(addr) => {
                match addr.ip() {
                    std::net::IpAddr::V4(ipv4) => {
                        buf.push(ADDR_TYPE_IPV4);
                        buf.extend_from_slice(&ipv4.octets());
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        buf.push(ADDR_TYPE_IPV6);
                        buf.extend_from_slice(&ipv6.octets());
                    }
                }
                addr.port()
            }
            TargetAddr::Domain(host, port) => {
                buf.push(ADDR_TYPE_DOMAIN);
                buf.push(host.len() as u8);
                buf.extend_from_slice(host.as_bytes());
                *port
            }
        };

        buf.extend_from_slice(&port.to_be_bytes());

        let mut stream = self
            .client
            .open_stream()
            .await
            .map_err(|e| SocksError::Connector(e.to_string()))?;

        stream
            .write_all(&buf)
            .await
            .map_err(|e| SocksError::Connector(e.to_string()))?;

        let mut reply = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut reply)
            .await
            .map_err(|e| SocksError::Connector(format!("handshake read failed: {}", e)))?;

        if reply[0] != REPLY_SUCCESS {
            return Err(SocksError::Connector(format!(
                "proxy rejected request: {}",
                reply[0]
            )));
        }

        Ok(Box::new(stream))
    }
}
