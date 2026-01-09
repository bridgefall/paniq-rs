use std::io;
#[cfg(feature = "kcp")]
use std::pin::Pin;
#[cfg(feature = "kcp")]
use std::task::{Context, Poll};
#[cfg(feature = "kcp")]
use tokio::io::ReadBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Default buffer size for bidirectional relaying (32KB).
pub const DEFAULT_RELAY_BUFFER_SIZE: usize = 32768;

#[cfg(feature = "kcp")]
use crate::kcp::client::{RecvStream, SendStream};

#[cfg(feature = "kcp")]
/// Stream wrapper that implements [`AsyncRead`] and [`AsyncWrite`] for Paniq (KCP) sessions.
///
/// This provides a standard socket-like interface over the underlying split [`SendStream`] and [`RecvStream`].
///
/// ### Invariants
/// - **Graceful Shutdown**: The [`AsyncWrite::poll_shutdown`] implementation ensures that the KCP/smux
///   session's send-side is properly finalized. This is critical for signaling EOF to the remote peer
///   and allowing them to close their side of the stream gracefully.
/// - **Resource Management**: When dropped without explicit shutdown, the constituent streams are dropped,
///   but the remote peer may only receive a Reset rather than an EOF.
pub struct PaniqStream {
    send: Option<SendStream>,
    recv: RecvStream,
}

#[cfg(feature = "kcp")]
impl PaniqStream {
    /// Create a new `PaniqStream` from a pair of constituent halves.
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send: Some(send),
            recv,
        }
    }

    /// Split the stream into its constituent halves.
    pub fn into_parts(self) -> (SendStream, RecvStream) {
        (self.send.expect("send half must be present"), self.recv)
    }
}

#[cfg(feature = "kcp")]
impl AsyncRead for PaniqStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

#[cfg(feature = "kcp")]
impl AsyncWrite for PaniqStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.send {
            Some(send) => Pin::new(send).poll_write(cx, buf),
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "send half joined or closed",
            ))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.send {
            Some(send) => Pin::new(send).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(mut send) = self.send.take() {
            // Initiate graceful shutdown of the send side.
            // This is critical for signaling EOF to the remote smux session.
            match Pin::new(&mut send).poll_shutdown(cx) {
                Poll::Ready(result) => {
                    // Shutdown complete, discard send side
                    Poll::Ready(result)
                }
                Poll::Pending => {
                    // Put it back to continue polling later
                    self.send = Some(send);
                    Poll::Pending
                }
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> IoStream for T {}

/// Check if an error represents an expected connection close.
/// Includes standard IO errors and smux-specific errors.
pub fn is_expected_close_error(e: &std::io::Error) -> bool {
    // Check standard error kinds
    if matches!(
        e.kind(),
        std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::ConnectionAborted
    ) {
        return true;
    }
    // Check for smux-specific errors (async-smux returns these as io::Error)
    let error_msg = e.to_string().to_lowercase();
    error_msg.contains("tx is already closed")
        || error_msg.contains("rx is already closed")
        || error_msg.contains("stream is closed")
        || error_msg.contains("connection closed")
}

/// Read a frame prefixed by a 16-bit big-endian length.
pub async fn read_u16_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_len: usize,
) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame length {} exceeds maximum {}", len, max_len),
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write a frame prefixed by a 16-bit big-endian length.
pub async fn write_u16_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    if data.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length exceeds u16::MAX",
        ));
    }
    writer.write_all(&(data.len() as u16).to_be_bytes()).await?;
    writer.write_all(data).await?;
    Ok(())
}
