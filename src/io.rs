use crate::kcp::client::{RecvStream, SendStream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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

impl AsyncRead for PaniqStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

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
