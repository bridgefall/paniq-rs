use std::net::SocketAddr;
use std::sync::Arc;

use rand::thread_rng;
use thiserror::Error;
use tokio::io::{DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::envelope::client::{client_handshake, UdpPacketConn};
use crate::kcp::common::REGISTRY;
use crate::obf::Framer;

#[derive(Debug, Error)]
pub enum KcpError {
    #[error("kcp setup failed: {0}")]
    Setup(String),
    #[error("handshake failed: {0}")]
    Handshake(String),
    #[error("connection failed: {0}")]
    Connection(String),
}

/// Bidirectional stream halves.
pub type SendStream = WriteHalf<DuplexStream>;
pub type RecvStream = ReadHalf<DuplexStream>;

/// Represents a simulated KCP connection.
pub struct Connection {
    outbound: mpsc::Sender<(SendStream, RecvStream)>,
    inbound: Arc<Mutex<mpsc::Receiver<(SendStream, RecvStream)>>>,
}

impl Connection {
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), KcpError> {
        let (a, b) = tokio::io::duplex(16 * 1024);
        let (client_recv, client_send) = tokio::io::split(a);
        let (server_recv, server_send) = tokio::io::split(b);
        self.outbound
            .send((server_send, server_recv))
            .await
            .map_err(|e| KcpError::Connection(e.to_string()))?;
        Ok((client_send, client_recv))
    }

    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), KcpError> {
        let mut rx = self.inbound.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| KcpError::Connection("connection closed".into()))
    }

    pub fn close(&self, _code: u32, _reason: &[u8]) {
        let _ = (_code, _reason);
    }
}

/// Client endpoint placeholder.
pub struct Endpoint;

pub async fn connect(
    socket: std::net::UdpSocket,
    server_addr: SocketAddr,
    framer: Framer,
    _config: (),
    initiation_payload: &[u8],
    _server_name: &str,
) -> Result<(Endpoint, Connection), KcpError> {
    let mut handshake_conn = UdpPacketConn::new(
        socket
            .try_clone()
            .map_err(|e| KcpError::Setup(e.to_string()))?,
        server_addr,
    )
    .map_err(|e| KcpError::Setup(e.to_string()))?;
    client_handshake(
        &mut handshake_conn,
        &framer,
        initiation_payload,
        &mut thread_rng(),
    )
    .map_err(|e| KcpError::Handshake(e.to_string()))?;

    connect_after_handshake(socket, server_addr, framer, _config, _server_name).await
}

pub async fn connect_after_handshake(
    socket: std::net::UdpSocket,
    server_addr: SocketAddr,
    _framer: Framer,
    _config: (),
    _server_name: &str,
) -> Result<(Endpoint, Connection), KcpError> {
    socket
        .set_nonblocking(true)
        .map_err(|e| KcpError::Setup(e.to_string()))?;
    let incoming = {
        let registry = REGISTRY
            .lock()
            .map_err(|e| KcpError::Setup(e.to_string()))?;
        registry
            .get(&server_addr)
            .cloned()
            .ok_or_else(|| KcpError::Connection("server not listening".into()))?
    };

    let (client_tx, server_rx) = mpsc::channel(8);
    let (server_tx, client_rx) = mpsc::channel(8);

    let client_conn = Connection {
        outbound: client_tx,
        inbound: Arc::new(Mutex::new(client_rx)),
    };
    let server_conn = Connection {
        outbound: server_tx,
        inbound: Arc::new(Mutex::new(server_rx)),
    };

    incoming
        .send(crate::kcp::server::IncomingConnection::new(server_conn))
        .await
        .map_err(|e| KcpError::Connection(e.to_string()))?;

    Ok((Endpoint, client_conn))
}
