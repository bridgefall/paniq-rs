use crate::io::PaniqStream;
use crate::kcp::client::{connect, ClientConfigWrapper, Connection};
use crate::obf::{Config as ObfConfig, Framer};
use std::net::SocketAddr;
use tokio::sync::Mutex;

/// High-level client for the Paniq protocol SDK.
///
/// `PaniqClient` is the primary entry point for establishing obfuscated KCP connections.
/// It provides high-level session management, including automatic reconnection and multiplexed stream creation.
///
/// ### Invariants
/// - **Connection Persistence**: The client keeps a single active [`Connection`] under a [`Mutex`].
/// - **Automatic Reconnection**: If the current connection is lost or fails during [`Self::open_stream`],
///   the client will transparently establish a new handshake using the provided configuration.
/// - **Multiplexing**: All streams opened via the same `PaniqClient` instance share the same underlying
///   KCP/UDP session until it is explicitly closed or a network error occurs.
pub struct PaniqClient {
    server_addr: SocketAddr,
    obf_config: ObfConfig,
    client_config: ClientConfigWrapper,
    connection: Mutex<Option<Connection>>,
    server_name: String,
}

impl PaniqClient {
    /// Create a new `PaniqClient` with the specified addressing and obfuscation policies.
    ///
    /// The client does not establish a connection immediately; the handshake is performed
    /// on-demand when the first stream is opened.
    pub fn new(
        server_addr: SocketAddr,
        obf_config: ObfConfig,
        client_config: ClientConfigWrapper,
    ) -> Self {
        Self {
            server_addr,
            obf_config,
            client_config,
            connection: Mutex::new(None),
            server_name: "paniq".to_string(),
        }
    }

    /// Set the server name used during handshake (default: "paniq").
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = name.into();
        self
    }

    /// Open a new bidirectional stream.
    ///
    /// If the underlying connection is closed or fails to open a stream,
    /// a new connection will be established.
    pub async fn open_stream(
        &self,
    ) -> Result<PaniqStream, Box<dyn std::error::Error + Send + Sync>> {
        let mut guard = self.connection.lock().await;

        if let Some(conn) = guard.as_ref() {
            if let Ok((send, recv)) = conn.open_bi().await {
                return Ok(PaniqStream::new(send, recv));
            }
            // If open_bi fails, the connection might be dead.
            tracing::debug!("Cached connection failed to open stream, reconnecting...");
            *guard = None;
        }

        // Establish new connection
        let conn = self.establish_connection().await?;
        let (send, recv) = conn.open_bi().await?;
        *guard = Some(conn);

        Ok(PaniqStream::new(send, recv))
    }

    /// Explicitly close the active connection.
    pub async fn close(&self) {
        let mut guard = self.connection.lock().await;
        if let Some(conn) = guard.take() {
            conn.shutdown().await;
        }
    }

    async fn establish_connection(
        &self,
    ) -> Result<Connection, Box<dyn std::error::Error + Send + Sync>> {
        let framer = Framer::new(self.obf_config.clone())
            .map_err(|e| format!("failed to create framer: {}", e))?;

        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;

        let (_endpoint, conn) = connect(
            socket,
            self.server_addr,
            framer,
            self.client_config.clone(),
            &[],
            &self.server_name,
        )
        .await
        .map_err(|e| format!("failed to connect: {}", e))?;

        Ok(conn)
    }
}
