//! KCP client implementation using real UDP networking.
//!
//! This module provides the client-side API for connecting to a KCP server.

use std::net::SocketAddr;
use std::sync::Arc;

use tracing::info;

use crate::envelope::padding::PaddingPolicy;
use crate::kcp::kcp_tokio::{ClientConfig, KcpClient};
use crate::kcp::mux::KcpStreamAdapter;
use crate::obf::Framer;

#[derive(Debug, thiserror::Error)]
pub enum KcpError {
    #[error("kcp setup failed: {0}")]
    Setup(String),
    #[error("handshake failed: {0}")]
    Handshake(String),
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("error: {0}")]
    BoxError(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Bidirectional stream halves (for compatibility with existing API).
pub type SendStream = tokio::io::WriteHalf<async_smux::MuxStream<KcpStreamAdapter>>;
pub type RecvStream = tokio::io::ReadHalf<async_smux::MuxStream<KcpStreamAdapter>>;

/// Multiplexed stream over KCP using async_smux.
pub type MuxStream = async_smux::MuxStream<KcpStreamAdapter>;

/// Represents a KCP connection.
pub struct Connection {
    /// The underlying KCP client
    client: Arc<KcpClient>,
    /// Local endpoint
    endpoint: Endpoint,
}

impl Connection {
    /// Open a new bidirectional stream via async_smux.
    /// Returns (SendStream, RecvStream) halves for backward compatibility.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), KcpError> {
        let stream = self
            .client
            .open_stream()
            .await
            .map_err(|e| KcpError::Connection(e.to_string()))?;
        let (read, write) = tokio::io::split(stream);
        Ok((write, read))
    }

    /// Accept a bidirectional stream (for client compatibility - not used in client mode).
    /// Returns (SendStream, RecvStream) halves for backward compatibility.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), KcpError> {
        let mut acceptor_guard = self.client.acceptor.lock().await;
        let acceptor = acceptor_guard
            .as_mut()
            .ok_or_else(|| KcpError::Connection("Mux not initialized".into()))?;

        let stream = acceptor
            .accept()
            .await
            .ok_or_else(|| KcpError::Connection("No incoming stream".into()))?;
        let (read, write) = tokio::io::split(stream);
        Ok((write, read))
    }

    /// Close the connection.
    pub fn close(&self, _code: u32, _reason: &[u8]) {
        let _ = (_code, _reason);
        // TODO: Implement proper close via async_smux
    }

    /// Get the endpoint.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}

/// Client endpoint placeholder.
pub struct Endpoint;

/// Client configuration.
pub struct ClientConfigWrapper {
    /// Maximum packet size for transport payloads
    pub max_packet_size: usize,
    /// Maximum payload size
    pub max_payload: usize,
    /// Optional explicit KCP send window size (in segments)
    pub send_window: Option<u32>,
    /// Optional explicit KCP receive window size (in segments)
    pub recv_window: Option<u32>,
    /// Optional target throughput in bits per second for BDP-based window sizing
    pub target_bps: Option<u64>,
    /// Optional RTT estimate in milliseconds for BDP-based window sizing
    pub rtt_ms: Option<u64>,
    /// Optional maximum KCP send queue size (in segments)
    pub max_snd_queue: Option<u32>,
    /// Transport replay protection enabled
    pub transport_replay: bool,
    /// Handshake timeout in seconds
    pub handshake_timeout_secs: u64,
    /// Maximum handshake attempts
    pub handshake_attempts: usize,
    /// Preamble delay in milliseconds
    pub preamble_delay_ms: u64,
}

impl Default for ClientConfigWrapper {
    fn default() -> Self {
        Self {
            max_packet_size: 1350,
            max_payload: 1200,
            send_window: None,
            recv_window: None,
            target_bps: None,
            rtt_ms: None,
            max_snd_queue: None,
            transport_replay: false,
            handshake_timeout_secs: 5,
            handshake_attempts: 3,
            preamble_delay_ms: 5,
        }
    }
}

/// Connect to a KCP server at the given address.
pub async fn connect(
    _socket: std::net::UdpSocket,
    server_addr: SocketAddr,
    framer: Framer,
    config: ClientConfigWrapper,
    _initiation_payload: &[u8],
    _server_name: &str,
) -> Result<(Endpoint, Connection), KcpError> {
    let max_payload = config.max_payload.min(config.max_packet_size);
    let client_config = ClientConfig {
        max_packet_size: config.max_packet_size,
        max_payload,
        send_window: config.send_window,
        recv_window: config.recv_window,
        target_bps: config.target_bps,
        rtt_ms: config.rtt_ms,
        max_snd_queue: config.max_snd_queue,
        transport_replay: config.transport_replay,
        padding_policy: PaddingPolicy {
            enabled: false,
            min: 0,
            max: 0,
            burst_min: 0,
            burst_max: 0,
            burst_prob: 0.0,
        },
        handshake_timeout: std::time::Duration::from_secs(config.handshake_timeout_secs),
        handshake_attempts: config.handshake_attempts,
        preamble_delay: std::time::Duration::from_millis(config.preamble_delay_ms),
    };

    let client = KcpClient::connect(server_addr, framer, client_config)
        .await
        .map_err(|e| KcpError::Setup(e.to_string()))?;

    info!("Connected to KCP server at {}", server_addr);

    let connection = Connection {
        client: Arc::new(client),
        endpoint: Endpoint,
    };

    Ok((Endpoint, connection))
}
