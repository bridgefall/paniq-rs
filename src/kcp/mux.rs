//! Channel-based adapter for KCP stream multiplexing.
//!
//! This module provides the `KcpStreamAdapter` which bridges KCP with async_smux
//! using non-blocking channels, avoiding block_on and proper async I/O.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

const DEFAULT_CHANNEL_CAPACITY: usize = 4096;
const MIN_COALESCE_LIMIT: usize = 1;

/// Channels for communicating with the KCP pump task.
/// These are the channels that the pump task owns/receives.
pub struct KcpPumpChannels {
    /// pump receives: UDP → pump (incoming KCP packets from UDP)
    pub input_rx: mpsc::Receiver<Vec<u8>>,
    /// pump receives: smux writes → pump (application data to send via KCP)
    pub write_rx: mpsc::Receiver<Bytes>,
    /// pump sends: pump → smux reads (application data received via KCP)
    pub read_tx: mpsc::Sender<Bytes>,
    /// pump sends pump → UDP send loop (outgoing KCP packets to send via UDP)
    pub output_tx: mpsc::Sender<Bytes>,
}

/// Channels for the transport layer (server/client).
/// These are the channels that transport.rs owns/uses.
pub struct KcpTransportChannels {
    /// transport sends: UDP → pump (send incoming KCP packets to pump)
    pub input_tx: mpsc::Sender<Vec<u8>>,
    /// transport receives: pump → UDP (receive outgoing KCP packets from pump)
    pub output_rx: mpsc::Receiver<Bytes>,
}

/// Stream adapter that implements AsyncRead + AsyncWrite using PollSender.
///
/// This avoids blocking and integrates properly with async_smux.
pub struct KcpStreamAdapter {
    /// Channel for receiving data from KCP (for reads)
    read_rx: mpsc::Receiver<Bytes>,
    /// Buffer for partial reads (when data doesn't fit in the read buffer)
    read_buf: Option<Bytes>,
    /// Channel for sending data to KCP (for writes)
    write_tx: PollSender<Bytes>,
    /// Buffer for coalescing small writes
    write_buf: Vec<u8>,
    /// Maximum coalesced payload size
    coalesce_limit: usize,
}

impl KcpStreamAdapter {
    /// Create a new adapter with associated channels.
    ///
    /// Returns:
    /// - The adapter (for smux)
    /// - Channels for the KCP pump
    /// - Channels for the transport layer
    pub fn new_adapter(coalesce_limit: usize) -> (Self, KcpPumpChannels, KcpTransportChannels) {
        // Channel for UDP -> KCP input
        let (input_tx, input_rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        // Channel for smux -> KCP writes
        let (write_tx, write_rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        // Channel for KCP -> smux reads
        let (read_tx, read_rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        // Channel for KCP -> UDP output
        let (output_tx, output_rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);

        let coalesce_limit = coalesce_limit.max(MIN_COALESCE_LIMIT);
        let adapter = Self {
            read_rx,
            read_buf: None,
            write_tx: PollSender::new(write_tx),
            write_buf: Vec::with_capacity(coalesce_limit),
            coalesce_limit,
        };

        let pump_channels = KcpPumpChannels {
            input_rx,
            write_rx,
            read_tx,
            output_tx,
        };

        let transport_channels = KcpTransportChannels {
            input_tx,
            output_rx,
        };

        (adapter, pump_channels, transport_channels)
    }

    /// Get a reference to the read channel (for testing).
    pub fn read_channel(&self) -> &mpsc::Receiver<Bytes> {
        &self.read_rx
    }

    /// Get the read_rx channel directly (for advanced use).
    pub fn into_read_channel(self) -> mpsc::Receiver<Bytes> {
        self.read_rx
    }

    /// Create a new adapter with channels for bidirectional communication.
    ///
    /// This is useful when you want to use externally created channels
    /// (e.g., with kcp-tokio engine).
    ///
    /// Returns (adapter, read_tx, write_rx) where:
    ///   - adapter: The KcpStreamAdapter for smux
    ///   - read_tx: Sender for data to be read by the adapter (KCP → smux)
    ///   - write_rx: Receiver for data written by the adapter (smux → KCP)
    ///
    /// Data flow:
    /// - Data sent to `read_tx` will be read from the adapter (via internal channel)
    /// - Data written to the adapter will be available on `write_rx`
    pub fn new_adapter_from(
        coalesce_limit: usize,
    ) -> (Self, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
        Self::new_adapter_from_capacity(DEFAULT_CHANNEL_CAPACITY, coalesce_limit)
    }

    /// Create a new adapter with a custom channel capacity.
    pub fn new_adapter_from_capacity(
        capacity: usize,
        coalesce_limit: usize,
    ) -> (Self, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
        // Create channels for the adapter
        let (read_tx, read_rx) = mpsc::channel(capacity);
        let (write_tx, write_rx) = mpsc::channel(capacity);

        let coalesce_limit = coalesce_limit.max(MIN_COALESCE_LIMIT);
        let adapter = Self {
            read_rx,
            read_buf: None,
            write_tx: PollSender::new(write_tx),
            write_buf: Vec::with_capacity(coalesce_limit),
            coalesce_limit,
        };

        // Return adapter, read_tx (for KCP to send to), and write_rx (for KCP to receive from)
        (adapter, read_tx, write_rx)
    }
}

impl AsyncRead for KcpStreamAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First, drain any buffered data from previous partial read
        if let Some(ref read_buf) = self.read_buf {
            let remaining = read_buf.len();
            let space = buf.remaining();

            if remaining <= space {
                // Entire buffer fits
                buf.put_slice(read_buf);
                self.read_buf = None;
                return Poll::Ready(Ok(()));
            } else {
                // Partial copy - store remainder
                buf.put_slice(&read_buf[..space]);
                self.read_buf = Some(read_buf.slice(space..));
                return Poll::Ready(Ok(()));
            }
        }

        // Try to receive new data from the read channel
        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let remaining = data.len();
                let space = buf.remaining();

                if remaining <= space {
                    // Entire buffer fits
                    buf.put_slice(&data);
                    Poll::Ready(Ok(()))
                } else {
                    // Partial copy - store remainder
                    buf.put_slice(&data[..space]);
                    self.read_buf = Some(data.slice(space..));
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Ready(None) => {
                // Channel closed - EOF
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for KcpStreamAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut consumed = 0usize;
        let limit = self.coalesce_limit;

        while consumed < buf.len() {
            let available = limit.saturating_sub(self.write_buf.len());
            if available == 0 {
                match self.write_tx.poll_reserve(cx) {
                    Poll::Ready(Ok(())) => {
                        let data = Bytes::copy_from_slice(&self.write_buf);
                        self.write_buf.clear();
                        if self.write_tx.send_item(data).is_err() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "send_item failed - channel closed",
                            )));
                        }
                    }
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "write channel closed",
                        )));
                    }
                    Poll::Pending => {
                        if consumed == 0 {
                            return Poll::Pending;
                        }
                        return Poll::Ready(Ok(consumed));
                    }
                }
                continue;
            }

            let remaining = buf.len() - consumed;
            let to_copy = remaining.min(available);
            self.write_buf
                .extend_from_slice(&buf[consumed..consumed + to_copy]);
            consumed += to_copy;
        }

        if self.write_buf.len() == limit {
            match self.write_tx.poll_reserve(cx) {
                Poll::Ready(Ok(())) => {
                    let data = Bytes::copy_from_slice(&self.write_buf);
                    self.write_buf.clear();
                    if self.write_tx.send_item(data).is_err() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "send_item failed - channel closed",
                        )));
                    }
                }
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "write channel closed",
                    )));
                }
                Poll::Pending => {
                    if consumed == 0 {
                        return Poll::Pending;
                    }
                }
            }
        }

        Poll::Ready(Ok(consumed))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        ready!(self
            .write_tx
            .poll_reserve(cx)
            .map_err(|_| { io::Error::new(io::ErrorKind::BrokenPipe, "write channel closed") })?);

        let data = Bytes::copy_from_slice(&self.write_buf);
        self.write_buf.clear();
        if self.write_tx.send_item(data).is_err() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "send_item failed - channel closed",
            )));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Don't close the write channel - it's shared by the entire mux session
        // Closing it here would break all streams, not just this one
        ready!(self.as_mut().poll_flush(cx)?);
        Poll::Ready(Ok(()))
    }
}

/// Get current system time in milliseconds for KCP.
pub fn system_time_ms() -> u32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    (now.as_secs() * 1000 + now.subsec_millis() as u64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::mpsc::error::TryRecvError;

    const CHANNEL_CAPACITY: usize = 8;
    const COALESCE_LIMIT: usize = 8;
    const SMALL_COALESCE_LIMIT: usize = 4;
    const RECV_TIMEOUT: Duration = Duration::from_millis(100);

    #[tokio::test]
    async fn coalesces_until_flush() {
        let (mut adapter, _read_tx, mut write_rx) =
            KcpStreamAdapter::new_adapter_from_capacity(CHANNEL_CAPACITY, COALESCE_LIMIT);

        adapter.write_all(b"abc").await.unwrap();
        adapter.write_all(b"def").await.unwrap();

        assert!(matches!(write_rx.try_recv(), Err(TryRecvError::Empty)));

        adapter.flush().await.unwrap();
        let data = tokio::time::timeout(RECV_TIMEOUT, write_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data[..], b"abcdef");
    }

    #[tokio::test]
    async fn sends_when_buffer_full() {
        let (mut adapter, _read_tx, mut write_rx) =
            KcpStreamAdapter::new_adapter_from_capacity(CHANNEL_CAPACITY, SMALL_COALESCE_LIMIT);

        adapter.write_all(b"abcd").await.unwrap();
        let data = tokio::time::timeout(RECV_TIMEOUT, write_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data[..], b"abcd");
    }

    #[tokio::test]
    async fn chunks_large_writes_by_limit() {
        let (mut adapter, _read_tx, mut write_rx) =
            KcpStreamAdapter::new_adapter_from_capacity(CHANNEL_CAPACITY, SMALL_COALESCE_LIMIT);

        adapter.write_all(b"abcdefgh").await.unwrap();

        let first = tokio::time::timeout(RECV_TIMEOUT, write_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let second = tokio::time::timeout(RECV_TIMEOUT, write_rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&first[..], b"abcd");
        assert_eq!(&second[..], b"efgh");
    }
}
