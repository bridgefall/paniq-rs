pub mod client;
pub mod enc_timestamp;
pub mod mac1;
pub mod padding;
pub mod replay;
pub mod server;
pub mod transport;

#[cfg(test)]
mod tests;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("invalid length prefix")]
    InvalidLength,
    #[error("counter rejected")]
    CounterRejected,
    #[error("handshake timed out")]
    HandshakeTimeout,
    #[error("replay detected")]
    Replay,
    #[error("authentication failed")]
    Authentication,
    #[error("timestamp error: {0}")]
    Timestamp(String),
}
