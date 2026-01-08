//! Channel-based adapter for KCP stream multiplexing.
//!
//! This module provides the `KcpStreamAdapter` which bridges KCP with async_smux
//! using non-blocking channels, avoiding block_on and proper async I/O.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use crate::telemetry;

const DEFAULT_CHANNEL_CAPACITY: usize = 4096;
const MIN_COALESCE_LIMIT: usize = 1;

#[derive(Clone, Copy, Default)]
struct TelemetryCounters {
    app_send_bytes: u64,
    app_recv_bytes: u64,
    kcp_input_bytes: u64,
    kcp_output_bytes: u64,
}

struct KcpTelemetry {
    last_log: Instant,
    last: TelemetryCounters,
    total: TelemetryCounters,
}

impl KcpTelemetry {
    fn new() -> Self {
        Self {
            last_log: Instant::now(),
            last: TelemetryCounters::default(),
            total: TelemetryCounters::default(),
        }
    }

    fn observe_app_send(&mut self, bytes: u64) {
        self.total.app_send_bytes = self.total.app_send_bytes.saturating_add(bytes);
    }

    fn observe_app_recv(&mut self, bytes: u64) {
        self.total.app_recv_bytes = self.total.app_recv_bytes.saturating_add(bytes);
    }

    fn observe_kcp_input(&mut self, bytes: u64) {
        self.total.kcp_input_bytes = self.total.kcp_input_bytes.saturating_add(bytes);
    }

    fn observe_kcp_output(&mut self, bytes: u64) {
        self.total.kcp_output_bytes = self.total.kcp_output_bytes.saturating_add(bytes);
    }

    fn should_log(&self) -> bool {
        let interval = telemetry::log_interval().unwrap_or(std::time::Duration::from_secs(1));
        self.last_log.elapsed() >= interval
    }

    fn log_and_reset(&mut self, kcp: &kcp::Kcp) {
        let elapsed = self.last_log.elapsed();
        if elapsed.is_zero() {
            return;
        }

        let delta = TelemetryCounters {
            app_send_bytes: self
                .total
                .app_send_bytes
                .saturating_sub(self.last.app_send_bytes),
            app_recv_bytes: self
                .total
                .app_recv_bytes
                .saturating_sub(self.last.app_recv_bytes),
            kcp_input_bytes: self
                .total
                .kcp_input_bytes
                .saturating_sub(self.last.kcp_input_bytes),
            kcp_output_bytes: self
                .total
                .kcp_output_bytes
                .saturating_sub(self.last.kcp_output_bytes),
        };

        let secs = elapsed.as_secs_f64();
        let app_send_rate = delta.app_send_bytes as f64 / secs;
        let app_recv_rate = delta.app_recv_bytes as f64 / secs;
        let kcp_out_rate = delta.kcp_output_bytes as f64 / secs;
        let kcp_in_rate = delta.kcp_input_bytes as f64 / secs;
        let overhead_ratio = if delta.app_send_bytes > 0 {
            delta.kcp_output_bytes as f64 / delta.app_send_bytes as f64
        } else {
            0.0
        };

        tracing::info!(
            conv_id = kcp.conv(),
            interval_ms = elapsed.as_millis(),
            app_send_bytes = delta.app_send_bytes,
            app_recv_bytes = delta.app_recv_bytes,
            kcp_input_bytes = delta.kcp_input_bytes,
            kcp_output_bytes = delta.kcp_output_bytes,
            app_send_bps = app_send_rate,
            app_recv_bps = app_recv_rate,
            kcp_input_bps = kcp_in_rate,
            kcp_output_bps = kcp_out_rate,
            kcp_overhead_ratio = overhead_ratio,
            kcp_waitsnd = kcp.get_waitsnd(),
            kcp_nsnd_que = kcp.nsnd_que(),
            kcp_nrcv_que = kcp.nrcv_que(),
            kcp_nrcv_buf = kcp.nrcv_buf(),
            "kcp_telemetry"
        );

        self.last = self.total;
        self.last_log = Instant::now();
    }
}

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

/// Run the KCP pump task.
///
/// This task owns the KCP instance and handles all I/O via channels.
/// It periodically updates KCP and drains the recv/send queues.
pub async fn run_kcp_pump(
    mut kcp: Pin<Box<kcp::Kcp>>,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    mut write_rx: mpsc::Receiver<Bytes>,
    read_tx: mpsc::Sender<Bytes>,
    output_tx: mpsc::Sender<Bytes>,
) -> io::Result<()> {
    tracing::info!("KCP pump task starting");
    // Update interval must match KCP nodelay interval (10ms) for optimal throughput
    let mut update_interval = tokio::time::interval(std::time::Duration::from_millis(10));
    let mut telemetry = telemetry::logs_enabled().then(KcpTelemetry::new);

    // Drain any initial output
    let initial_output = drain_output(kcp.as_mut(), &output_tx).await?;
    if let Some(ref mut telemetry) = telemetry {
        telemetry.observe_kcp_output(initial_output);
    }

    loop {
        tokio::select! {
            // Incoming KCP packets from UDP (feed kcp.input)
            Some(data) = input_rx.recv() => {
                if let Some(ref mut telemetry) = telemetry {
                    telemetry.observe_kcp_input(data.len() as u64);
                }
                if let Err(e) = kcp.input(&data) {
                    tracing::warn!("KCP input error: {}", e);
                } else {
                    // Use KCP's monotonic timebase to avoid wall-clock jumps
                    let current = kcp.get_system_time();
                    kcp.update(current);
                    kcp.flush();
                }
            }

            // Application data to send via KCP (feed kcp.send)
            Some(data) = write_rx.recv() => {
                if let Some(ref mut telemetry) = telemetry {
                    telemetry.observe_app_send(data.len() as u64);
                }
                if let Err(e) = kcp.as_mut().send(&data) {
                    tracing::warn!("KCP send error: {}", e);
                } else {
                    // Use KCP's monotonic timebase to avoid wall-clock jumps
                    let current = kcp.get_system_time();
                    kcp.update(current);
                    kcp.flush();
                }
            }

            // Periodic KCP update
            _ = update_interval.tick() => {
                // Use KCP's monotonic timebase to avoid wall-clock jumps
                let current = kcp.get_system_time();
                kcp.update(current);
            }
        }

        // Drain KCP receive queue (application data received via KCP)
        let recv_bytes = drain_recv(kcp.as_mut(), &read_tx).await?;
        if let Some(ref mut telemetry) = telemetry {
            telemetry.observe_app_recv(recv_bytes);
        }

        // Drain KCP output queue (KCP packets to send via UDP)
        let output_bytes = drain_output(kcp.as_mut(), &output_tx).await?;
        if let Some(ref mut telemetry) = telemetry {
            telemetry.observe_kcp_output(output_bytes);
            if telemetry.should_log() {
                telemetry.log_and_reset(&kcp);
            }
        }
    }
}

/// Helper: drain KCP receive queue and send to read channel.
async fn drain_recv(mut kcp: Pin<&mut kcp::Kcp>, read_tx: &mpsc::Sender<Bytes>) -> io::Result<u64> {
    let mut read_buf = vec![0u8; 8192];
    let mut total = 0u64;
    loop {
        match kcp.recv(&mut read_buf) {
            Ok(0) => break,
            Ok(n) => {
                let data = Bytes::copy_from_slice(&read_buf[..n]);
                if read_tx.send(data).await.is_err() {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "read channel closed",
                    ));
                }
                total = total.saturating_add(n as u64);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => {
                tracing::warn!("KCP recv error: {}", e);
                break;
            }
        }
    }
    Ok(total)
}

/// Helper: drain KCP output queue and send to output channel.
async fn drain_output(
    mut kcp: Pin<&mut kcp::Kcp>,
    output_tx: &mpsc::Sender<Bytes>,
) -> io::Result<u64> {
    let mut total = 0u64;
    while kcp.has_ouput() {
        if let Some(data) = kcp.pop_output() {
            total = total.saturating_add(data.len() as u64);
            if output_tx.send(data.freeze()).await.is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "output channel closed",
                ));
            }
        } else {
            break;
        }
    }
    Ok(total)
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
