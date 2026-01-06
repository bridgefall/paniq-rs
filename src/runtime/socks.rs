//! Spawnable SOCKS5 server for integration testing.
//!
//! Provides a test-friendly wrapper around the production socks5d logic,
//! allowing the server to be started and stopped programmatically.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::kcp::client::{connect, ClientConfigWrapper};
use crate::obf::Framer;
use crate::profile::Profile;
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
///
/// When dropped, the server will be gracefully shut down via cancellation token.
/// Note: Drop cannot wait for async shutdown to complete, so the server task
/// is cancelled but may not finish before the handle is dropped. For clean
/// shutdown in tests, call `wait()` explicitly before dropping.
pub struct SocksHandle {
    /// The address the server is listening on.
    pub addr: SocketAddr,

    shutdown: CancellationToken,
    task: Option<JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>>,
}

impl SocksHandle {
    /// Spawn a new SOCKS5 server with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - SOCKS5 configuration
    ///
    /// # Returns
    ///
    /// A `SocksHandle` that can be used to manage the server's lifecycle.
    pub async fn spawn(config: SocksConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
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
        };
        let relay_buffer_size = client_config.max_payload;
        let connector = KcpConnector::new(server_addr, obf_config, client_config);

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
                // Accept incoming connections until shutdown is requested
                loop {
                    tokio::select! {
                        _ = shutdown.cancelled() => {
                            info!("SOCKS5 server shutdown requested");
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

    /// Request graceful shutdown of the SOCKS5 server.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    /// Wait for the SOCKS5 server task to complete.
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

impl Drop for SocksHandle {
    fn drop(&mut self) {
        // Only cancel if the task hasn't been taken (e.g., by wait())
        if self.task.is_some() {
            self.shutdown();
        }
    }
}

/// KCP connector that implements the RelayConnector trait for SOCKS5.
///
/// This uses the production code path from `bin/socks5d.rs`.
struct KcpConnector {
    server_addr: SocketAddr,
    obf_config: crate::obf::Config,
    client_config: ClientConfigWrapper,
    conn: tokio::sync::Mutex<Option<crate::kcp::client::Connection>>,
}

impl KcpConnector {
    fn new(
        server_addr: SocketAddr,
        obf_config: crate::obf::Config,
        client_config: ClientConfigWrapper,
    ) -> Self {
        Self {
            server_addr,
            obf_config,
            client_config,
            conn: tokio::sync::Mutex::new(None),
        }
    }

    async fn connect_session(
        &self,
    ) -> Result<crate::kcp::client::Connection, SocksError> {
        let framer = Framer::new(self.obf_config.clone())
            .map_err(|e| SocksError::Connector(e.to_string()))?;
        let (_ep, conn) = connect(
            std::net::UdpSocket::bind("0.0.0.0:0")
                .map_err(|e| SocksError::Connector(e.to_string()))?,
            self.server_addr,
            framer,
            self.client_config.clone(),
            &[],
            "paniq",
        )
        .await
        .map_err(|e| SocksError::Connector(e.to_string()))?;
        Ok(conn)
    }

    async fn get_connection(&self) -> Result<crate::kcp::client::Connection, SocksError> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref() {
            return Ok(conn.clone());
        }
        let conn = self.connect_session().await?;
        *guard = Some(conn.clone());
        Ok(conn)
    }

    async fn reset_connection(&self) {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.take() {
            conn.shutdown().await;
        }
    }

    async fn open_stream_with_retry(
        &self,
        buf: &[u8],
    ) -> Result<(crate::kcp::client::SendStream, crate::kcp::client::RecvStream), SocksError> {
        let conn = self.get_connection().await?;
        if let Ok(stream) = Self::open_stream(&conn, buf).await {
            return Ok(stream);
        }
        self.reset_connection().await;
        let conn = self.get_connection().await?;
        Self::open_stream(&conn, buf).await
    }

    async fn open_stream(
        conn: &crate::kcp::client::Connection,
        buf: &[u8],
    ) -> Result<(crate::kcp::client::SendStream, crate::kcp::client::RecvStream), SocksError> {
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| SocksError::Connector(e.to_string()))?;
        send.write_all(buf)
            .await
            .map_err(|e| SocksError::Connector(e.to_string()))?;
        Ok((send, recv))
    }
}

#[async_trait::async_trait]
impl RelayConnector for KcpConnector {
    async fn connect(&self, target: &TargetAddr) -> Result<Box<dyn IoStream + Send>, SocksError> {
        let mut buf = Vec::new();
        buf.push(0x01); // protocol version

        let port = match target {
            TargetAddr::Ip(addr) => {
                match addr.ip() {
                    std::net::IpAddr::V4(ipv4) => {
                        buf.push(0x01); // IPv4
                        buf.extend_from_slice(&ipv4.octets());
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        buf.push(0x04); // IPv6
                        buf.extend_from_slice(&ipv6.octets());
                    }
                }
                addr.port()
            }
            TargetAddr::Domain(host, port) => {
                buf.push(0x03); // Domain
                buf.push(host.len() as u8);
                buf.extend_from_slice(host.as_bytes());
                *port
            }
        };

        buf.extend_from_slice(&port.to_be_bytes());

        let (send, recv) = self.open_stream_with_retry(&buf).await?;
        Ok(Box::new(StreamWrapper {
            send: Some(send),
            recv,
        }))
    }
}

/// Stream wrapper that implements AsyncRead/AsyncWrite for KCP streams.
///
/// This is the production implementation from `bin/socks5d.rs`, with
/// critical shutdown semantics for smux cleanup.
struct StreamWrapper {
    // Option lets shutdown be idempotent and avoid closing the smux stream early.
    send: Option<crate::kcp::client::SendStream>,
    recv: crate::kcp::client::RecvStream,
}

impl tokio::io::AsyncRead for StreamWrapper {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for StreamWrapper {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut self.send {
            Some(send) => std::pin::Pin::new(send).poll_write(cx, buf),
            None => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "kcp send is closed",
            ))),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut self.send {
            Some(send) => std::pin::Pin::new(send).poll_flush(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Send FIN frame to signal graceful shutdown of the KCP/smux stream.
        // This is critical for smux stream cleanup; without it, the session
        // state becomes corrupted when opening subsequent streams.
        if let Some(send) = &mut self.send {
            let poll_result = std::pin::Pin::new(send).poll_shutdown(cx);
            if poll_result.is_ready() {
                self.send = None;
            }
            poll_result
        } else {
            std::task::Poll::Ready(Ok(()))
        }
    }
}
