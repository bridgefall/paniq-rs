#![cfg(feature = "quic")]

use std::net::SocketAddr;

use quinn::{default_runtime, Endpoint, EndpointConfig, ServerConfig};
use thiserror::Error;

use crate::obf::Framer;
use crate::quic::client::FramedUdpSocket;

#[derive(Debug, Error)]
pub enum QuicServerError {
    #[error("quic server setup failed: {0}")]
    Setup(String),
}

pub async fn listen(
    addr: SocketAddr,
    framer: Framer,
    config: ServerConfig,
) -> Result<Endpoint, QuicServerError> {
    let sock =
        std::net::UdpSocket::bind(addr).map_err(|e| QuicServerError::Setup(e.to_string()))?;
    listen_on_socket(sock, framer, config).await
}

pub async fn listen_on_socket(
    sock: std::net::UdpSocket,
    framer: Framer,
    config: ServerConfig,
) -> Result<Endpoint, QuicServerError> {
    let runtime =
        default_runtime().ok_or_else(|| QuicServerError::Setup("no async runtime".into()))?;
    let framed =
        FramedUdpSocket::new(sock, framer).map_err(|e| QuicServerError::Setup(e.to_string()))?;
    Endpoint::new_with_abstract_socket(EndpointConfig::default(), Some(config), framed, runtime)
        .map_err(|e| QuicServerError::Setup(e.to_string()))
}
