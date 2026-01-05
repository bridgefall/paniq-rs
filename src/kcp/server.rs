//! KCP server implementation using real UDP networking.
//!
//! This module provides the server-side API for accepting incoming KCP connections.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::info;

use crate::envelope::padding::PaddingPolicy;
use crate::kcp::kcp_tokio::{ServerConfig, KcpServer};
use crate::kcp::mux::KcpStreamAdapter;
use crate::obf::Framer;

#[derive(Debug, thiserror::Error)]
pub enum KcpServerError {
    #[error("kcp server setup failed: {0}")]
    Setup(String),
    #[error("kcp server io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("kcp server error: {0}")]
    Other(String),
}

/// Multiplexed stream over KCP using async_smux.
pub type MuxStream = async_smux::MuxStream<KcpStreamAdapter>;

/// Server endpoint that receives incoming connections.
pub struct Endpoint {
    /// The underlying KCP server
    server: Arc<KcpServer>,
    /// Accepted connections channel
    incoming: Arc<Mutex<tokio::sync::mpsc::Receiver<IncomingConnection>>>,
}

impl Endpoint {
    /// Accept a new incoming connection.
    pub async fn accept(&self) -> Option<IncomingConnection> {
        self.incoming.lock().await.recv().await
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.server.local_addr()
    }
}

/// Represents an accepted incoming connection.
pub struct IncomingConnection {
    /// The peer address
    peer_addr: SocketAddr,
    /// Smux acceptor for accepting streams from this connection
    pub acceptor: async_smux::MuxAcceptor<KcpStreamAdapter>,
}

impl IncomingConnection {
    pub(crate) fn new(peer_addr: SocketAddr, acceptor: async_smux::MuxAcceptor<KcpStreamAdapter>) -> Self {
        Self { peer_addr, acceptor }
    }

    /// Get the peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Convert to a server-side connection (for test compatibility).
    pub async fn await_connection(self) -> Result<ServerConnection, KcpServerError> {
        Ok(ServerConnection {
            peer_addr: self.peer_addr,
            acceptor: self.acceptor,
        })
    }
}

/// Server-side connection for accepting bidirectional streams.
pub struct ServerConnection {
    peer_addr: SocketAddr,
    acceptor: async_smux::MuxAcceptor<KcpStreamAdapter>,
}

impl ServerConnection {
    /// Get the peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Accept a bidirectional stream.
    /// Returns (SendStream, RecvStream) halves for backward compatibility.
    pub async fn accept_bi(&mut self) -> Result<(crate::kcp::client::SendStream, crate::kcp::client::RecvStream), KcpServerError> {
        let stream = self.acceptor.accept().await
            .ok_or_else(|| KcpServerError::Other("No incoming stream".into()))?;
        let (read, write) = tokio::io::split(stream);
        Ok((write, read))
    }
}

/// Server configuration.
pub struct ServerConfigWrapper {
    /// Maximum packet size for transport payloads
    pub max_packet_size: usize,
    /// Maximum payload size
    pub max_payload: usize,
    /// Transport replay protection enabled
    pub transport_replay: bool,
    /// Idle timeout in seconds
    pub idle_timeout_secs: u64,
    /// Handshake timeout in seconds
    pub handshake_timeout_secs: u64,
    /// Maximum handshake attempts
    pub handshake_attempts: usize,
    /// Preamble delay in milliseconds
    pub preamble_delay_ms: u64,
}

impl Default for ServerConfigWrapper {
    fn default() -> Self {
        Self {
            max_packet_size: 1350,
            max_payload: 1200,
            transport_replay: false,
            idle_timeout_secs: 120,
            handshake_timeout_secs: 5,
            handshake_attempts: 3,
            preamble_delay_ms: 5,
        }
    }
}

/// Listen for incoming KCP connections on the given address.
pub async fn listen(
    addr: SocketAddr,
    framer: Framer,
    config: ServerConfigWrapper,
) -> Result<Endpoint, KcpServerError> {
    let max_payload = config.max_payload.min(config.max_packet_size);
    let rng = framer.rng().clone();
    let server_config = ServerConfig {
        max_packet_size: config.max_packet_size,
        max_payload,
        transport_replay: config.transport_replay,
        padding_policy: PaddingPolicy {
            enabled: false,
            min: 0,
            max: 0,
            burst_min: 0,
            burst_max: 0,
            burst_prob: 0.0,
        },
        idle_timeout: std::time::Duration::from_secs(config.idle_timeout_secs),
        handshake_timeout: std::time::Duration::from_secs(config.handshake_timeout_secs),
        handshake_attempts: config.handshake_attempts,
        preamble_delay: std::time::Duration::from_millis(config.preamble_delay_ms),
    };

    let server = KcpServer::bind(addr, framer, rng, server_config).await?;

    info!("KCP server listening on {}", server.local_addr());

    // Create a channel for incoming connections
    let (tx, rx) = tokio::sync::mpsc::channel(128);

    // Set the channel sender before starting the run loop
    server.set_connection_sender(tx).await;

    let endpoint = Endpoint {
        server: Arc::new(server),
        incoming: Arc::new(Mutex::new(rx)),
    };

    // Spawn the server run loop
    let server_clone = endpoint.server.clone();
    tokio::spawn(async move {
        if let Err(e) = server_clone.run().await {
            tracing::error!("Server run loop error: {}", e);
        }
    });

    Ok(endpoint)
}
