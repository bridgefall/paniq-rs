use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::kcp::common::REGISTRY;
use crate::obf::Framer;

#[derive(Debug, thiserror::Error)]
pub enum KcpServerError {
    #[error("kcp server setup failed: {0}")]
    Setup(String),
}

/// Represents an accepted incoming connection.
pub struct IncomingConnection {
    inner: crate::kcp::client::Connection,
}

impl IncomingConnection {
    pub async fn await(self) -> Result<crate::kcp::client::Connection, KcpServerError> {
        Ok(self.inner)
    }
}

/// Server endpoint that receives incoming connections.
pub struct Endpoint {
    addr: SocketAddr,
    incoming: Arc<Mutex<mpsc::Receiver<IncomingConnection>>>,
}

impl Endpoint {
    pub async fn accept(&self) -> Option<IncomingConnection> {
        self.incoming.lock().await.recv().await
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

pub async fn listen(
    addr: SocketAddr,
    _framer: Framer,
    _config: (),
) -> Result<Endpoint, KcpServerError> {
    let sock = std::net::UdpSocket::bind(addr).map_err(|e| KcpServerError::Setup(e.to_string()))?;
    listen_on_socket(sock, _framer, _config).await
}

pub async fn listen_on_socket(
    sock: std::net::UdpSocket,
    _framer: Framer,
    _config: (),
) -> Result<Endpoint, KcpServerError> {
    let addr = sock.local_addr().map_err(|e| KcpServerError::Setup(e.to_string()))?;

    let (tx, rx) = mpsc::channel(8);
    REGISTRY
        .lock()
        .map_err(|e| KcpServerError::Setup(e.to_string()))?
        .insert(addr, tx);

    Ok(Endpoint {
        addr,
        incoming: Arc::new(Mutex::new(rx)),
    })
}
