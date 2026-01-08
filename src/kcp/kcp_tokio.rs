//! KCP transport layer using kcp-tokio.
//!
//! This module provides an alternative implementation of the KCP transport
//! using kcp-tokio's async KcpEngine instead of kcp-rs.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use futures::Future;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::envelope::client::{client_handshake_async, TokioPacketConn};
use crate::envelope::padding::PaddingPolicy;
use crate::envelope::transport::{build_transport_payload, decode_transport_payload};
use crate::kcp::mux::KcpStreamAdapter;
use crate::obf::{Framer, MessageType, SharedRng};
use crate::telemetry;
use kcp_tokio::async_kcp::engine::KcpEngine;
use kcp_tokio::common::{constants as kcp_constants, KcpStats};
use kcp_tokio::config::NodeDelayConfig;

// Re-export kcp-tokio types for convenience
pub use kcp_tokio::{common::ConvId, KcpConfig};

const TRANSPORT_LEN_FIELD: usize = 2;
const TRANSPORT_COUNTER_FIELD: usize = 8;

// Smux queue sizes for concurrent stream performance
const SMUX_MAX_TX_QUEUE: usize = 8192;
const SMUX_MAX_RX_QUEUE: usize = 8192;

// KCP window sizes - match kcp-rs configuration
const KCP_SND_WND: u32 = 1024;
const KCP_RCV_WND: u32 = 1024;
const BITS_PER_BYTE: u64 = 8;
const MILLIS_PER_SEC: u64 = 1000;
const MIN_KCP_WINDOW: u32 = 1;

/// KCP telemetry counters.
#[derive(Default, Clone, Copy)]
struct KcpTelemetryCounters {
    app_send_bytes: u64,
    app_recv_bytes: u64,
    kcp_input_bytes: u64,
}

/// KCP telemetry state.
struct KcpTelemetry {
    last_log: Instant,
    last: KcpTelemetryCounters,
    total: KcpTelemetryCounters,
    last_stats: KcpStats,
}

impl KcpTelemetry {
    fn new() -> Self {
        Self {
            last_log: Instant::now(),
            last: KcpTelemetryCounters::default(),
            total: KcpTelemetryCounters::default(),
            last_stats: KcpStats::default(),
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

    fn should_log(&self) -> bool {
        self.last_log.elapsed() >= telemetry::TELEMETRY_INTERVAL
    }

    fn log_and_reset(&mut self, conv_id: u32, stats: &KcpStats) {
        let elapsed = self.last_log.elapsed();
        if elapsed.is_zero() {
            return;
        }

        let delta = KcpTelemetryCounters {
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
        };

        let secs = elapsed.as_secs_f64();
        let app_send_rate = delta.app_send_bytes as f64 / secs;
        let app_recv_rate = delta.app_recv_bytes as f64 / secs;
        let kcp_in_rate = delta.kcp_input_bytes as f64 / secs;
        let kcp_bytes_sent = stats.bytes_sent.saturating_sub(self.last_stats.bytes_sent);
        let kcp_bytes_received = stats
            .bytes_received
            .saturating_sub(self.last_stats.bytes_received);
        let kcp_packets_sent = stats
            .packets_sent
            .saturating_sub(self.last_stats.packets_sent);
        let kcp_packets_received = stats
            .packets_received
            .saturating_sub(self.last_stats.packets_received);
        let kcp_retransmissions = stats
            .retransmissions
            .saturating_sub(self.last_stats.retransmissions);
        let kcp_fast_retransmissions = stats
            .fast_retransmissions
            .saturating_sub(self.last_stats.fast_retransmissions);
        let kcp_send_bps = kcp_bytes_sent as f64 / secs;
        let kcp_recv_bps = kcp_bytes_received as f64 / secs;

        info!(
            conv_id,
            interval_ms = elapsed.as_millis(),
            app_send_bytes = delta.app_send_bytes,
            app_recv_bytes = delta.app_recv_bytes,
            kcp_input_bytes = delta.kcp_input_bytes,
            app_send_bps = app_send_rate,
            app_recv_bps = app_recv_rate,
            kcp_input_bps = kcp_in_rate,
            kcp_bytes_sent,
            kcp_bytes_received,
            kcp_packets_sent,
            kcp_packets_received,
            kcp_send_bps,
            kcp_recv_bps,
            kcp_retransmissions,
            kcp_fast_retransmissions,
            kcp_rtt_ms = stats.rtt,
            kcp_rto_ms = stats.rto,
            kcp_cwnd = stats.cwnd,
            kcp_snd_wnd = stats.snd_wnd,
            kcp_rcv_wnd = stats.rcv_wnd,
            kcp_rmt_wnd = stats.rmt_wnd,
            kcp_snd_queue = stats.snd_queue_size,
            kcp_rcv_queue = stats.rcv_queue_size,
            kcp_snd_buf = stats.snd_buf_size,
            kcp_rcv_buf = stats.rcv_buf_size,
            "kcp_telemetry"
        );

        self.last = self.total;
        self.last_log = Instant::now();
        self.last_stats = stats.clone();
    }
}

fn compute_kcp_mtu(
    max_packet_size: usize,
    max_payload: usize,
    transport_replay: bool,
    padding_reserve: usize,
) -> u32 {
    let overhead = TRANSPORT_LEN_FIELD
        + if transport_replay {
            TRANSPORT_COUNTER_FIELD
        } else {
            0
        };
    let payload_budget = max_payload.min(max_packet_size);
    payload_budget
        .saturating_sub(overhead)
        .saturating_sub(padding_reserve)
        .max(1) as u32
}

fn compute_kcp_coalesce_limit(
    max_packet_size: usize,
    max_payload: usize,
    transport_replay: bool,
    padding_reserve: usize,
) -> usize {
    let mtu = compute_kcp_mtu(
        max_packet_size,
        max_payload,
        transport_replay,
        padding_reserve,
    );
    let mss = mtu.saturating_sub(kcp_constants::IKCP_OVERHEAD) as usize;
    mss.max(1)
}

fn compute_bdp_window(mtu: u32, target_bps: u64, rtt_ms: u64) -> Option<u32> {
    if target_bps == 0 || rtt_ms == 0 {
        return None;
    }

    let mss = mtu.saturating_sub(kcp_constants::IKCP_OVERHEAD);
    if mss == 0 {
        return None;
    }

    let bytes_per_sec = target_bps / BITS_PER_BYTE;
    if bytes_per_sec == 0 {
        return None;
    }

    let inflight_bytes = (bytes_per_sec as u128)
        .saturating_mul(rtt_ms as u128)
        .saturating_add((MILLIS_PER_SEC - 1) as u128)
        / MILLIS_PER_SEC as u128;
    let window = (inflight_bytes + mss as u128 - 1) / mss as u128;
    let window = window.clamp(MIN_KCP_WINDOW as u128, u32::MAX as u128) as u32;
    Some(window)
}

fn coalesce_write_batch(
    first: Bytes,
    pending_writes: &mut VecDeque<Bytes>,
    write_rx: &mut mpsc::Receiver<Bytes>,
    max_bytes: usize,
) -> Bytes {
    if max_bytes == 0 || first.len() >= max_bytes {
        return first;
    }

    let mut buf = BytesMut::with_capacity(max_bytes.max(first.len()));
    buf.extend_from_slice(&first);

    while buf.len() < max_bytes {
        let next = if let Some(next) = pending_writes.pop_front() {
            Some(next)
        } else {
            match write_rx.try_recv() {
                Ok(next) => Some(next),
                Err(mpsc::error::TryRecvError::Empty) => None,
                Err(mpsc::error::TryRecvError::Disconnected) => None,
            }
        };

        let Some(next) = next else { break };
        if buf.len() + next.len() <= max_bytes {
            buf.extend_from_slice(&next);
        } else {
            pending_writes.push_front(next);
            break;
        }
    }

    buf.freeze()
}

fn resolve_kcp_windows(
    max_packet_size: usize,
    max_payload: usize,
    send_window: Option<u32>,
    recv_window: Option<u32>,
    target_bps: Option<u64>,
    rtt_ms: Option<u64>,
    max_snd_queue: Option<u32>,
    transport_replay: bool,
    padding_reserve: usize,
) -> (u32, u32, u32) {
    let mtu = compute_kcp_mtu(
        max_packet_size,
        max_payload,
        transport_replay,
        padding_reserve,
    );
    let bdp_window = match (target_bps, rtt_ms) {
        (Some(bps), Some(rtt)) => compute_bdp_window(mtu, bps, rtt),
        _ => None,
    };
    let bdp_snd = bdp_window.map(|w| w.max(KCP_SND_WND));
    let bdp_rcv = bdp_window.map(|w| w.max(KCP_RCV_WND));

    let snd_wnd = send_window.or(bdp_snd).unwrap_or(KCP_SND_WND);
    let rcv_wnd = recv_window.or(bdp_rcv).unwrap_or(KCP_RCV_WND);
    let max_snd_queue = max_snd_queue.unwrap_or(snd_wnd);

    (snd_wnd, rcv_wnd, max_snd_queue)
}

fn should_accept_send(stats: &KcpStats, max_snd_queue: u32) -> bool {
    if max_snd_queue == 0 {
        return false;
    }
    stats.snd_queue_size < max_snd_queue
}

fn is_fatal_kcp_error(err: &kcp_tokio::KcpError) -> bool {
    use kcp_tokio::error::ConnectionError;
    matches!(
        err,
        kcp_tokio::KcpError::Connection {
            kind: ConnectionError::Closed
                | ConnectionError::Reset
                | ConnectionError::Refused
                | ConnectionError::Lost
                | ConnectionError::Timeout
                | ConnectionError::NotConnected
        }
    )
}

fn handle_kcp_result(label: &str, result: Result<(), kcp_tokio::KcpError>) -> bool {
    if let Err(e) = result {
        warn!("KCP engine {} error: {:?}", label, e);
        return !is_fatal_kcp_error(&e);
    }
    true
}

fn log_smux_worker_result(result: Result<(), async_smux::error::MuxError>) {
    if let Err(e) = result {
        match &e {
            async_smux::error::MuxError::ConnectionClosed
            | async_smux::error::MuxError::StreamClosed(_) => {
                tracing::debug!("Smux worker closed: {:?}", e);
            }
            async_smux::error::MuxError::IoError(io) => {
                let expected = matches!(
                    io.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::ConnectionAborted
                );
                if expected {
                    tracing::debug!("Smux worker closed: {:?}", e);
                } else {
                    error!("Smux worker error: {:?}", e);
                }
            }
            _ => {
                error!("Smux worker error: {:?}", e);
            }
        }
    }
}

fn start_transport_logger() {
    if !telemetry::logs_enabled() {
        return;
    }

    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }

    tokio::spawn(async move {
        let mut last = telemetry::transport_snapshot();
        let mut interval = tokio::time::interval(telemetry::TELEMETRY_INTERVAL);
        loop {
            interval.tick().await;
            let current = telemetry::transport_snapshot();
            let delta = current.delta(last);
            last = current;

            let secs = telemetry::TELEMETRY_INTERVAL.as_secs_f64();
            let payload_out_bps = delta.transport_payload_out_bytes as f64 / secs;
            let payload_in_bps = delta.transport_payload_in_bytes as f64 / secs;
            let udp_out_bps = delta.udp_out_bytes as f64 / secs;
            let udp_in_bps = delta.udp_in_bytes as f64 / secs;
            let transport_overhead_ratio = if delta.transport_payload_out_bytes > 0 {
                delta.transport_frame_out_bytes as f64 / delta.transport_payload_out_bytes as f64
            } else {
                0.0
            };
            let udp_overhead_ratio = if delta.transport_payload_out_bytes > 0 {
                delta.udp_out_bytes as f64 / delta.transport_payload_out_bytes as f64
            } else {
                0.0
            };

            tracing::info!(
                interval_ms = telemetry::TELEMETRY_INTERVAL.as_millis(),
                udp_in_bytes = delta.udp_in_bytes,
                udp_out_bytes = delta.udp_out_bytes,
                transport_payload_in_bytes = delta.transport_payload_in_bytes,
                transport_payload_out_bytes = delta.transport_payload_out_bytes,
                transport_padding_in_bytes = delta.transport_padding_in_bytes,
                transport_padding_out_bytes = delta.transport_padding_out_bytes,
                transport_frame_in_bytes = delta.transport_frame_in_bytes,
                transport_frame_out_bytes = delta.transport_frame_out_bytes,
                transport_invalid_length = delta.transport_invalid_length,
                transport_counter_reject = delta.transport_counter_reject,
                transport_payload_too_large = delta.transport_payload_too_large,
                payload_in_bps = payload_in_bps,
                payload_out_bps = payload_out_bps,
                udp_in_bps = udp_in_bps,
                udp_out_bps = udp_out_bps,
                transport_overhead_ratio = transport_overhead_ratio,
                udp_overhead_ratio = udp_overhead_ratio,
                "transport_telemetry"
            );
        }
    });
}

/// KCP session state using kcp-tokio.
pub struct SessionState {
    /// Peer address
    pub peer_addr: SocketAddr,
    /// Last activity timestamp
    pub last_seen: tokio::time::Instant,
    /// Counter for transport replay protection (atomic for thread-safe access)
    pub counter: Arc<AtomicU64>,
    /// Channel for sending incoming KCP packets (UDP -> engine)
    pub input_tx: mpsc::Sender<Bytes>,
    /// UDP send loop handle (for cleanup)
    pub udp_send_handle: Option<tokio::task::JoinHandle<()>>,
    /// Smux connector (must be kept alive to prevent worker exit)
    pub connector: async_smux::MuxConnector<KcpStreamAdapter>,
}

/// Server-side transport that accepts incoming KCP connections using kcp-tokio.
pub struct KcpServer {
    /// UDP socket
    socket: Arc<UdpSocket>,
    /// Obfuscation framer
    framer: Arc<Framer>,
    /// Sessions keyed by (peer_addr, conv_id)
    sessions: Arc<Mutex<HashMap<(SocketAddr, u32), SessionState>>>,
    /// Profile config
    config: ServerConfig,
    /// Incoming connections channel sender
    conn_tx: Arc<Mutex<Option<tokio::sync::mpsc::Sender<super::server::IncomingConnection>>>>,
    /// Optional ready signal sender (for testing - signals when recv loop is active)
    ready_tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    /// Shutdown token
    shutdown: CancellationToken,
}

/// Server configuration.
#[derive(Clone)]
pub struct ServerConfig {
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
    /// Padding policy for transport packets
    pub padding_policy: PaddingPolicy,
    /// Idle timeout
    pub idle_timeout: Duration,
    /// Handshake timeout
    pub handshake_timeout: Duration,
    /// Maximum handshake attempts
    pub handshake_attempts: usize,
    /// Preamble delay
    pub preamble_delay: Duration,
}

impl Default for ServerConfig {
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
            padding_policy: PaddingPolicy::disabled(),
            idle_timeout: Duration::from_secs(120),
            handshake_timeout: Duration::from_secs(5),
            handshake_attempts: 3,
            preamble_delay: Duration::from_millis(5),
        }
    }
}

impl KcpServer {
    /// Create a new KCP server bound to the given address.
    pub async fn bind(
        addr: SocketAddr,
        framer: Framer,
        _rng: SharedRng,
        config: ServerConfig,
    ) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(addr).await?;
        info!(
            "KCP server (kcp-tokio) listening on {}",
            socket.local_addr()?
        );
        Ok(Self {
            socket: Arc::new(socket),
            framer: Arc::new(framer),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            config,
            conn_tx: Arc::new(Mutex::new(None)),
            ready_tx: Arc::new(Mutex::new(None)),
            shutdown: CancellationToken::new(),
        })
    }

    /// Set the channel sender for incoming connections.
    pub async fn set_connection_sender(
        &self,
        tx: tokio::sync::mpsc::Sender<super::server::IncomingConnection>,
    ) {
        *self.conn_tx.lock().await = Some(tx);
    }

    /// Set the ready signal sender (signals when recv loop is active).
    pub async fn set_ready_sender(&self, tx: tokio::sync::oneshot::Sender<()>) {
        *self.ready_tx.lock().await = Some(tx);
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    /// Shutdown the server and release all network resources.
    ///
    /// ### Invariants
    /// - **Socket Release**: All active session loops are abort-signaled, ensuring that all Clones
    ///   of the [`Arc<UdpSocket>`] are eventually dropped. This allows the OS to release the
    ///   bound port for immediate reuse by other processes (or a restarted instance).
    /// - **Receptor Termination**: The main receive loop terminates, preventing any new handshake
    ///   initiations or transport packet processing.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
        // We can't easily wait for sessions to close here without making shutdown async,
        // but aborting their handles will release the socket references quickly.
        let sessions = self.sessions.clone();
        tokio::spawn(async move {
            let mut guard = sessions.lock().await;
            for (_, mut session) in guard.drain() {
                if let Some(handle) = session.udp_send_handle.take() {
                    handle.abort();
                }
            }
        });
    }

    /// Start the server receive loop.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        start_transport_logger();
        let mut buf = vec![0u8; 65536];
        let mut update_interval = tokio::time::interval(Duration::from_millis(20));

        let mut iter_count = 0u64;

        tokio::task::yield_now().await;

        loop {
            if iter_count < 5 {}

            // Send ready signal on first iteration
            if iter_count == 0 {
                if let Some(tx) = self.ready_tx.lock().await.take() {
                    let _ = tx.send(());
                }
            }

            iter_count += 1;

            tokio::select! {
                // Receive incoming datagrams
                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, peer_addr)) => {
                            telemetry::record_udp_in(len);
                            let datagram = &buf[..len];

                            debug!("Server received {} bytes from {}", len, peer_addr);

                            // Decode the framer
                            match self.framer.decode_frame(datagram) {
                                Ok((msg_type, payload)) => {
                                    debug!("Decoded message type: {:?}, payload length: {}", msg_type, payload.len());
                                    trace!(target: "paniq::transport_dump", direction = "rx", peer = %peer_addr, len = len, msg_type = msg_type.into_u8(), hex = %hex::encode(&buf[..len]));

                                    match msg_type {
                                        MessageType::Transport => {
                                            // Handle KCP transport packet
                                            self.handle_transport(peer_addr, payload).await;
                                        }
                                        MessageType::Initiation => {
                                            // Handle handshake initiation
                                            if let Err(e) = self.handle_handshake_initiation(peer_addr, payload).await {
                                                warn!("Handshake failed from {}: {}", peer_addr, e);
                                            }
                                        }
                                        MessageType::CookieReply | MessageType::Response => {
                                            debug!("Unexpected handshake message from {}: {:?}", peer_addr, msg_type);
                                        }
                                    }
                                }
                                Err(e) => {
                                    // Log junk/invalid packets to transport dump
                                    trace!(target: "paniq::transport_dump", direction = "rx", peer = %peer_addr, len = len, msg_type = 0, hex = %hex::encode(&buf[..len]));
                                    debug!("Failed to decode frame from {}: {}", peer_addr, e);
                                    continue;
                                }
                            }
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                    }
                }

                // Shutdown signal
                _ = self.shutdown.cancelled() => {
                    debug!("KCP server shutdown requested, exiting loop");
                    break Ok(());
                }

                // Periodic session cleanup
                _ = update_interval.tick() => {
                    self.update_sessions().await;
                }
            }
        }
    }

    /// Handle handshake initiation from a client.
    async fn handle_handshake_initiation(
        &self,
        peer_addr: SocketAddr,
        _payload: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Generate a new conv_id for this session
        let conv_id = rand::random::<u32>();

        debug!(
            "Handshake from {}, assigning conv_id={}",
            peer_addr, conv_id
        );

        // Create KCP configuration matching kcp-rs settings
        let padding_reserve = self.config.padding_policy.max_padding();
        let mtu = compute_kcp_mtu(
            self.config.max_packet_size,
            self.config.max_payload,
            self.config.transport_replay,
            padding_reserve,
        );
        let (snd_wnd, rcv_wnd, max_snd_queue) = resolve_kcp_windows(
            self.config.max_packet_size,
            self.config.max_payload,
            self.config.send_window,
            self.config.recv_window,
            self.config.target_bps,
            self.config.rtt_ms,
            self.config.max_snd_queue,
            self.config.transport_replay,
            padding_reserve,
        );

        let kcp_config = KcpConfig::new()
            .mtu(mtu)
            .send_window(snd_wnd)
            .recv_window(rcv_wnd)
            .stream_mode(true)
            .nodelay_config(NodeDelayConfig::custom(
                true,
                KCP_NODELAY_INTERVAL_MS,
                KCP_FAST_RESEND,
                KCP_NO_CONGESTION,
            ));

        let channel_capacity = SMUX_MAX_RX_QUEUE.max(SMUX_MAX_TX_QUEUE);
        // Create channels for KCP engine input (UDP packets)
        let (input_tx, input_rx) = mpsc::channel(channel_capacity);
        // Create adapter and channels for smux
        let (adapter, read_tx, write_rx) =
            KcpStreamAdapter::new_adapter_from_capacity(channel_capacity, self.config.max_payload);

        // Build the smux server
        let mut builder = async_smux::MuxBuilder::server();
        builder.with_max_tx_queue(std::num::NonZeroUsize::new(SMUX_MAX_TX_QUEUE).unwrap());
        builder.with_max_rx_queue(std::num::NonZeroUsize::new(SMUX_MAX_RX_QUEUE).unwrap());
        let (connector, acceptor, worker) = builder.with_connection(adapter).build();

        // Spawn the mux worker task
        tokio::spawn(async move {
            log_smux_worker_result(worker.await);
        });

        // Spawn the KCP engine task
        let socket = self.socket.clone();
        let framer = self.framer.clone();
        let config = self.config.clone();
        let peer_addr_for_task = peer_addr;

        // Create atomic counter for replay protection
        let counter = Arc::new(AtomicU64::new(0));
        let counter_for_session = counter.clone();

        let engine_task = tokio::spawn(async move {
            run_kcp_engine_server(
                conv_id,
                kcp_config,
                input_rx,
                write_rx,
                read_tx,
                socket,
                framer,
                peer_addr_for_task,
                config,
                counter,
                max_snd_queue,
            )
            .await;
        });

        // Session state - the UDP send loop is now part of the engine task
        let session = SessionState {
            peer_addr,
            last_seen: tokio::time::Instant::now(),
            counter: counter_for_session,
            input_tx,
            udp_send_handle: Some(engine_task),
            connector,
        };

        // Insert session BEFORE sending Response to avoid race
        self.sessions
            .lock()
            .await
            .insert((peer_addr, conv_id), session);

        // NOW send Response - session is ready to receive data
        // KCP conv_id is little-endian in the payload
        let response_payload = (conv_id as u32).to_le_bytes().to_vec();
        let response = self
            .framer
            .encode_frame(MessageType::Response, &response_payload)?;
        self.socket.send_to(&response, peer_addr).await?;

        info!(
            "Session established and Response sent: {} with conv_id={}",
            peer_addr, conv_id
        );

        // Send the incoming connection through the channel
        if let Some(tx) = self.conn_tx.lock().await.as_ref() {
            let conn = super::server::IncomingConnection::new(peer_addr, acceptor);
            let _ = tx.send(conn).await;
        }

        Ok(())
    }

    /// Handle a KCP transport packet.
    async fn handle_transport(&self, peer_addr: SocketAddr, payload: Vec<u8>) {
        // Decode transport payload with counter validation
        let expect_counter = self.config.transport_replay;
        let kcp_bytes = match decode_transport_payload(
            &payload,
            expect_counter,
            None::<&mut Box<dyn FnMut(u64) -> bool>>,
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Failed to decode transport payload: {}", e);
                return;
            }
        };

        // Extract conv_id from KCP packet (first 4 bytes)
        // KCP headers are little-endian
        if kcp_bytes.len() < 4 {
            warn!("Invalid KCP packet: too short");
            return;
        }
        let conv_id = u32::from_le_bytes([kcp_bytes[0], kcp_bytes[1], kcp_bytes[2], kcp_bytes[3]]);

        // Find the session
        let mut sessions = self.sessions.lock().await;
        let session = match sessions.get_mut(&(peer_addr, conv_id)) {
            Some(s) => s,
            None => {
                warn!("Unknown session: {} conv_id={}", peer_addr, conv_id);
                return;
            }
        };

        // Feed the packet to the KCP engine via input_tx
        session.last_seen = tokio::time::Instant::now();
        if let Err(_) = session.input_tx.send(Bytes::from(kcp_bytes)).await {
            warn!("Failed to send data to KCP engine - channel closed");
        }
    }

    /// Clean up stale sessions.
    async fn update_sessions(&self) {
        let mut sessions = self.sessions.lock().await;
        let now = tokio::time::Instant::now();

        // Collect stale sessions
        let stale_keys: Vec<_> = sessions
            .iter()
            .filter(|(_, s)| now.duration_since(s.last_seen) > self.config.idle_timeout)
            .map(|(k, _)| *k)
            .collect();

        // Remove stale sessions
        for key in stale_keys {
            info!("Removing stale session: {:?}", key);
            if let Some(mut session) = sessions.remove(&key) {
                if let Some(handle) = session.udp_send_handle.take() {
                    handle.abort();
                }
            }
        }
    }
}

/// Run the KCP engine for server-side connection.
async fn run_kcp_engine_server(
    conv_id: u32,
    kcp_config: KcpConfig,
    mut input_rx: mpsc::Receiver<Bytes>,
    mut write_rx: mpsc::Receiver<Bytes>,
    read_tx: mpsc::Sender<Bytes>,
    socket: Arc<UdpSocket>,
    framer: Arc<Framer>,
    peer_addr: SocketAddr,
    config: ServerConfig,
    counter: Arc<AtomicU64>,
    max_snd_queue: u32,
) {
    use tokio::sync::mpsc::error::TrySendError;

    // Create KCP engine
    let conv = ConvId::from(conv_id);
    let update_ms = std::cmp::max(1, kcp_config.nodelay.interval);
    let mut engine = KcpEngine::new(conv, kcp_config);
    let padding_reserve = config.padding_policy.max_padding();
    let coalesce_limit = compute_kcp_coalesce_limit(
        config.max_packet_size,
        config.max_payload,
        config.transport_replay,
        padding_reserve,
    );

    // Set output function for sending KCP packets via UDP with envelope framing
    let socket_clone = socket.clone();
    let framer_clone = framer.clone();
    let config_clone = config.clone();
    let counter_clone = counter.clone();

    let output_fn = Arc::new(move |kcp_bytes: Bytes| -> Pin<Box<dyn Future<Output = Result<(), kcp_tokio::KcpError>> + Send>> {
        let socket = socket_clone.clone();
        let framer = framer_clone.clone();
        let config = config_clone.clone();
        let counter = counter_clone.clone();

        Box::pin(async move {
            // Build transport payload with counter and padding
            let replay_counter = if config.transport_replay {
                Some(counter.fetch_add(1, Ordering::SeqCst))
            } else {
                None
            };
            let payload = {
                let mut rng_guard = framer.rng().0.lock().unwrap();
                build_transport_payload(
                    kcp_bytes.as_ref(),
                    replay_counter,
                    &config.padding_policy,
                    config.max_payload,
                    &mut *rng_guard,
                )
            };

            let payload = match payload {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to build transport payload: {}", e);
                    return Err(kcp_tokio::KcpError::protocol(e.to_string()));
                }
            };

            // Encode as Transport frame
            let datagram = match framer.encode_frame(MessageType::Transport, &payload) {
                Ok(d) => d,
                Err(e) => {
                    error!("Failed to encode transport frame: {}", e);
                    return Err(kcp_tokio::KcpError::protocol(e.to_string()));
                }
            };

            // Send to peer
            telemetry::record_udp_out(datagram.len());
            trace!(target: "paniq::transport_dump", direction = "tx", peer = %peer_addr, len = datagram.len(), msg_type = MessageType::Transport.into_u8(), hex = %hex::encode(&datagram));
            if let Err(e) = socket.send_to(&datagram, peer_addr).await {
                error!("Failed to send transport packet: {}", e);
                return Err(kcp_tokio::KcpError::protocol(e.to_string()));
            }

            Ok(())
        })
    });

    engine.set_output(output_fn);

    // Initialize KCP telemetry
    let mut kcp_telemetry = telemetry::logs_enabled().then(KcpTelemetry::new);

    // Main I/O loop with periodic updates
    let mut update_interval = tokio::time::interval(Duration::from_millis(update_ms as u64));
    let mut pending_reads: VecDeque<Bytes> = VecDeque::new();
    let mut pending_writes: VecDeque<Bytes> = VecDeque::new();
    let max_pending_reads = SMUX_MAX_RX_QUEUE;
    loop {
        let allow_send = should_accept_send(engine.stats(), max_snd_queue);
        tokio::select! {
            // Incoming KCP packets from UDP (feed engine.input)
            Some(data) = input_rx.recv() => {
                if let Some(ref mut tel) = kcp_telemetry {
                    tel.observe_kcp_input(data.len() as u64);
                }
                if !handle_kcp_result("input", engine.input(data).await) {
                    break;
                }
                if !handle_kcp_result("update", engine.update().await) {
                    break;
                }
            }

            // Application data to send via KCP (feed engine.send)
            Some(data) = write_rx.recv(), if allow_send && pending_writes.is_empty() => {
                let batch = coalesce_write_batch(data, &mut pending_writes, &mut write_rx, coalesce_limit);
                if let Some(ref mut tel) = kcp_telemetry {
                    tel.observe_app_send(batch.len() as u64);
                }
                if !handle_kcp_result("send", engine.send(batch).await) {
                    break;
                }
                if !handle_kcp_result("update", engine.update().await) {
                    break;
                }
            }

            // Periodic KCP update
            _ = update_interval.tick() => {
                if !handle_kcp_result("update", engine.update().await) {
                    break;
                }
            }

            // Check if engine is dead
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if engine.is_dead() {
                    info!("KCP engine connection is dead, exiting");
                    break;
                }
            }
        }

        if allow_send && !pending_writes.is_empty() {
            if let Some(data) = pending_writes.pop_front() {
                let batch =
                    coalesce_write_batch(data, &mut pending_writes, &mut write_rx, coalesce_limit);
                if let Some(ref mut tel) = kcp_telemetry {
                    tel.observe_app_send(batch.len() as u64);
                }
                if !handle_kcp_result("send", engine.send(batch).await) {
                    break;
                }
                if !handle_kcp_result("update", engine.update().await) {
                    break;
                }
            }
        }

        // Flush any pending reads without blocking the engine loop.
        while let Some(data) = pending_reads.pop_front() {
            match read_tx.try_send(data) {
                Ok(()) => {}
                Err(TrySendError::Full(data)) => {
                    pending_reads.push_front(data);
                    break;
                }
                Err(TrySendError::Closed(_)) => {
                    warn!("Failed to send to read channel - channel closed");
                    return;
                }
            }
        }

        // Drain KCP receive queue (application data received via KCP).
        while pending_reads.len() < max_pending_reads {
            match engine.recv().await {
                Ok(Some(data)) => {
                    if let Some(ref mut tel) = kcp_telemetry {
                        tel.observe_app_recv(data.len() as u64);
                    }
                    match read_tx.try_send(data) {
                        Ok(()) => {}
                        Err(TrySendError::Full(data)) => {
                            pending_reads.push_back(data);
                            break;
                        }
                        Err(TrySendError::Closed(_)) => {
                            warn!("Failed to send to read channel - channel closed");
                            return;
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    warn!("KCP recv error: {:?}", e);
                    break;
                }
            }
        }

        // Log telemetry if enabled
        if let Some(ref mut tel) = kcp_telemetry {
            if tel.should_log() {
                let stats = engine.stats().clone();
                tel.log_and_reset(conv_id, &stats);
            }
        }

        // Flush pending ACKs
        let _ = engine.flush().await;
    }
}

/// Client-side transport that connects to a KCP server using kcp-tokio.
pub struct KcpClient {
    /// UDP socket
    socket: Arc<UdpSocket>,
    /// Server address
    server_addr: SocketAddr,
    /// Obfuscation framer
    framer: Arc<Framer>,
    /// KCP session (for tracking)
    session: Arc<Mutex<Option<SessionState>>>,
    /// Profile config
    config: ClientConfig,
    /// Smux connector for opening streams
    pub connector: Arc<Mutex<Option<async_smux::MuxConnector<KcpStreamAdapter>>>>,
    /// Smux acceptor for receiving streams (server-initiated)
    pub acceptor: Arc<Mutex<Option<async_smux::MuxAcceptor<KcpStreamAdapter>>>>,
    /// UDP receive loop handle (for cleanup)
    udp_recv_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

/// Client configuration.
#[derive(Clone)]
pub struct ClientConfig {
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
    /// Padding policy for transport packets
    pub padding_policy: PaddingPolicy,
    /// Handshake timeout
    pub handshake_timeout: Duration,
    /// Maximum handshake attempts
    pub handshake_attempts: usize,
    /// Preamble delay
    pub preamble_delay: Duration,
}

impl Default for ClientConfig {
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
            padding_policy: PaddingPolicy::disabled(),
            handshake_timeout: Duration::from_secs(5),
            handshake_attempts: 3,
            preamble_delay: Duration::from_millis(5),
        }
    }
}

impl KcpClient {
    /// Create a new KCP client connected to the given server.
    pub async fn connect(
        server_addr: SocketAddr,
        framer: Framer,
        config: ClientConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Bind to any available port using tokio socket
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(server_addr).await?;

        // Perform async handshake using tokio socket
        let mut conn = TokioPacketConn::new(socket, server_addr);
        let payload = client_handshake_async(&mut conn, &framer, &[]).await?;

        // Extract conv_id from Response payload (4 bytes little-endian, KCP format)
        if payload.len() < 4 {
            return Err("Response payload too short for conv_id".into());
        }
        let conv_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);

        info!(
            "Connected to server {} with conv_id={}",
            server_addr, conv_id
        );

        // Reconstruct the socket from the connection
        let socket = conn.sock;

        let client = Self {
            socket: Arc::new(socket),
            server_addr,
            framer: Arc::new(framer),
            session: Arc::new(Mutex::new(None)),
            config,
            connector: Arc::new(Mutex::new(None)),
            acceptor: Arc::new(Mutex::new(None)),
            udp_recv_handle: Arc::new(Mutex::new(None)),
        };

        // Complete session setup (KCP, smux, etc.)
        client.complete_session_setup(conv_id).await?;

        // Start UDP receive loop
        client.start_udp_receive_loop().await;

        Ok(client)
    }

    /// Complete session setup after handshake (KCP, smux, etc.).
    async fn complete_session_setup(&self, conv_id: u32) -> Result<(), Box<dyn std::error::Error>> {
        // Create KCP configuration matching kcp-rs settings
        let padding_reserve = self.config.padding_policy.max_padding();
        let mtu = compute_kcp_mtu(
            self.config.max_packet_size,
            self.config.max_payload,
            self.config.transport_replay,
            padding_reserve,
        );
        let (snd_wnd, rcv_wnd, max_snd_queue) = resolve_kcp_windows(
            self.config.max_packet_size,
            self.config.max_payload,
            self.config.send_window,
            self.config.recv_window,
            self.config.target_bps,
            self.config.rtt_ms,
            self.config.max_snd_queue,
            self.config.transport_replay,
            padding_reserve,
        );

        let kcp_config = KcpConfig::new()
            .mtu(mtu)
            .send_window(snd_wnd)
            .recv_window(rcv_wnd)
            .stream_mode(true)
            .nodelay_config(NodeDelayConfig::custom(
                true,
                KCP_NODELAY_INTERVAL_MS,
                KCP_FAST_RESEND,
                KCP_NO_CONGESTION,
            ));

        let channel_capacity = SMUX_MAX_RX_QUEUE.max(SMUX_MAX_TX_QUEUE);
        // Create channels for KCP engine input (UDP packets)
        let (input_tx, input_rx) = mpsc::channel(channel_capacity);
        // Create adapter and channels for smux
        let (adapter, read_tx, write_rx) =
            KcpStreamAdapter::new_adapter_from_capacity(channel_capacity, self.config.max_payload);

        // Build the smux client
        let mut builder = async_smux::MuxBuilder::client();
        builder.with_max_tx_queue(std::num::NonZeroUsize::new(SMUX_MAX_TX_QUEUE).unwrap());
        builder.with_max_rx_queue(std::num::NonZeroUsize::new(SMUX_MAX_RX_QUEUE).unwrap());
        let (connector, acceptor, worker) = builder.with_connection(adapter).build();

        // Spawn the mux worker task
        tokio::spawn(async move {
            log_smux_worker_result(worker.await);
        });

        // Spawn the KCP engine task
        let socket = self.socket.clone();
        let framer = self.framer.clone();
        let config = self.config.clone();
        let server_addr = self.server_addr;
        let counter = Arc::new(AtomicU64::new(0));
        let counter_for_session = counter.clone();

        let engine_task = tokio::spawn(async move {
            run_kcp_engine_client(
                conv_id,
                kcp_config,
                input_rx,
                write_rx,
                read_tx,
                socket,
                framer,
                server_addr,
                config,
                counter,
                max_snd_queue,
            )
            .await;
        });

        // Store the mux components
        *self.connector.lock().await = Some(connector);
        *self.acceptor.lock().await = Some(acceptor);

        let session = SessionState {
            peer_addr: self.server_addr,
            last_seen: tokio::time::Instant::now(),
            counter: counter_for_session,
            input_tx,
            udp_send_handle: Some(engine_task),
            connector: self.connector.lock().await.as_ref().unwrap().clone(),
        };

        *self.session.lock().await = Some(session);

        Ok(())
    }

    /// Start the UDP receive loop.
    async fn start_udp_receive_loop(&self) {
        start_transport_logger();
        let socket = self.socket.clone();
        let framer = self.framer.clone();
        let session = self.session.clone();
        let transport_replay = self.config.transport_replay;
        let server_addr = self.server_addr;

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match socket.recv(&mut buf).await {
                    Ok(len) => {
                        telemetry::record_udp_in(len);
                        let datagram = &buf[..len];

                        // Decode the framer
                        match framer.decode_frame(datagram) {
                            Ok((msg_type, payload)) => {
                                trace!(target: "paniq::transport_dump", direction = "rx", peer = %server_addr, len = len, msg_type = msg_type.into_u8(), hex = %hex::encode(&buf[..len]));

                                match msg_type {
                                    MessageType::Transport => {
                                        // Decode transport payload
                                        let kcp_bytes = match decode_transport_payload(
                                            &payload,
                                            transport_replay,
                                            None::<&mut Box<dyn FnMut(u64) -> bool>>,
                                        ) {
                                            Ok(bytes) => bytes,
                                            Err(e) => {
                                                tracing::warn!(
                                                    "Failed to decode transport payload: {}",
                                                    e
                                                );
                                                continue;
                                            }
                                        };

                                        // Send to KCP engine via input_tx
                                        let session_guard = session.lock().await;
                                        if let Some(ref session) = *session_guard {
                                            if let Err(_) =
                                                session.input_tx.send(Bytes::from(kcp_bytes)).await
                                            {
                                                tracing::warn!(
                                                    "Failed to send to KCP engine - channel closed"
                                                );
                                                break;
                                            }
                                        }
                                    }
                                    MessageType::Initiation
                                    | MessageType::CookieReply
                                    | MessageType::Response => {
                                        tracing::debug!(
                                            "Unexpected handshake message after connection established"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                trace!(target: "paniq::transport_dump", direction = "rx", peer = %server_addr, len = len, msg_type = 0, hex = %hex::encode(&buf[..len]));
                                tracing::debug!("Failed to decode frame: {}", e);
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("UDP receive error: {}", e);
                        break;
                    }
                }
            }
        });
        *self.udp_recv_handle.lock().await = Some(handle);
    }

    pub async fn shutdown(&self) {
        if let Some(handle) = self.udp_recv_handle.lock().await.take() {
            handle.abort();
        }
        if let Some(session) = self.session.lock().await.take() {
            if let Some(handle) = session.udp_send_handle {
                handle.abort();
            }
        }
        *self.connector.lock().await = None;
        *self.acceptor.lock().await = None;
    }

    /// Open a new multiplexed stream.
    pub async fn open_stream(
        &self,
    ) -> Result<async_smux::MuxStream<KcpStreamAdapter>, Box<dyn std::error::Error>> {
        let connector_guard = self.connector.lock().await;
        let connector = connector_guard
            .as_ref()
            .ok_or("Mux not initialized - handshake not completed")?
            .clone();
        drop(connector_guard);

        connector
            .connect()
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_bdp_window_uses_mss() {
        let mtu = 1400;
        let target_bps = 80_000_000;
        let rtt_ms = 100;
        let window = compute_bdp_window(mtu, target_bps, rtt_ms).unwrap();
        assert_eq!(window, 727);
    }

    #[test]
    fn resolve_kcp_windows_prefers_explicit_send_window() {
        let mtu_packet = 1350;
        let max_payload = 1200;
        let target_bps = 80_000_000;
        let rtt_ms = 100;
        let explicit_send = 2000;

        let expected_bdp = compute_bdp_window(
            compute_kcp_mtu(mtu_packet, max_payload, false, 0),
            target_bps,
            rtt_ms,
        )
        .unwrap();

        let (snd, rcv, max_q) = resolve_kcp_windows(
            mtu_packet,
            max_payload,
            Some(explicit_send),
            None,
            Some(target_bps),
            Some(rtt_ms),
            None,
            false,
            0,
        );

        assert_eq!(snd, explicit_send);
        let expected_rcv = expected_bdp.max(KCP_RCV_WND);
        assert_eq!(rcv, expected_rcv);
        assert_eq!(max_q, explicit_send);
    }

    #[test]
    fn should_accept_send_respects_queue_limit() {
        let mut stats = KcpStats::default();
        stats.snd_queue_size = 9;
        assert!(should_accept_send(&stats, 10));
        stats.snd_queue_size = 10;
        assert!(!should_accept_send(&stats, 10));
        assert!(!should_accept_send(&stats, 0));
    }

    #[test]
    fn coalesce_write_batch_prefers_pending_over_channel() {
        let (tx, mut rx) = mpsc::channel(4);
        tx.try_send(Bytes::from_static(b"cc")).unwrap();

        let mut pending = VecDeque::new();
        pending.push_back(Bytes::from_static(b"bb"));

        let out = coalesce_write_batch(Bytes::from_static(b"aa"), &mut pending, &mut rx, 6);

        assert_eq!(&out[..], b"aabbcc");
        assert!(pending.is_empty());
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn coalesce_write_batch_respects_limit_and_keeps_pending() {
        let (tx, mut rx) = mpsc::channel(4);
        tx.try_send(Bytes::from_static(b"cc")).unwrap();

        let mut pending = VecDeque::new();
        pending.push_back(Bytes::from_static(b"bbbb"));

        let out = coalesce_write_batch(Bytes::from_static(b"aa"), &mut pending, &mut rx, 5);

        assert_eq!(&out[..], b"aa");
        assert_eq!(&pending.front().unwrap()[..], b"bbbb");
        assert_eq!(&rx.try_recv().unwrap()[..], b"cc");
    }
}

/// Run the KCP engine for client-side connection.
async fn run_kcp_engine_client(
    conv_id: u32,
    kcp_config: KcpConfig,
    mut input_rx: mpsc::Receiver<Bytes>,
    mut write_rx: mpsc::Receiver<Bytes>,
    read_tx: mpsc::Sender<Bytes>,
    socket: Arc<UdpSocket>,
    framer: Arc<Framer>,
    _server_addr: SocketAddr,
    config: ClientConfig,
    counter: Arc<AtomicU64>,
    max_snd_queue: u32,
) {
    use tokio::sync::mpsc::error::TrySendError;

    // Create KCP engine
    let conv = ConvId::from(conv_id);
    let update_ms = std::cmp::max(1, kcp_config.nodelay.interval);
    let mut engine = KcpEngine::new(conv, kcp_config);
    let padding_reserve = config.padding_policy.max_padding();
    let coalesce_limit = compute_kcp_coalesce_limit(
        config.max_packet_size,
        config.max_payload,
        config.transport_replay,
        padding_reserve,
    );

    // Set output function for sending KCP packets via UDP with envelope framing
    let socket_clone = socket.clone();
    let framer_clone = framer.clone();
    let config_clone = config.clone();
    let counter_clone = counter.clone();

    let output_fn = Arc::new(move |kcp_bytes: Bytes| -> Pin<Box<dyn Future<Output = Result<(), kcp_tokio::KcpError>> + Send>> {
        let socket = socket_clone.clone();
        let framer = framer_clone.clone();
        let config = config_clone.clone();
        let counter = counter_clone.clone();

        Box::pin(async move {
            // Build transport payload with counter and padding
            let replay_counter = if config.transport_replay {
                Some(counter.fetch_add(1, Ordering::SeqCst))
            } else {
                None
            };
            let payload = {
                let mut rng_guard = framer.rng().0.lock().unwrap();
                build_transport_payload(
                    kcp_bytes.as_ref(),
                    replay_counter,
                    &config.padding_policy,
                    config.max_payload,
                    &mut *rng_guard,
                )
            };

            let payload = match payload {
                Ok(p) => p,
                Err(e) => {
                    error!("Failed to build transport payload: {}", e);
                    return Err(kcp_tokio::KcpError::protocol(e.to_string()));
                }
            };

            // Encode as Transport frame
            let datagram = match framer.encode_frame(MessageType::Transport, &payload) {
                Ok(d) => d,
                Err(e) => {
                    error!("Failed to encode transport frame: {}", e);
                    return Err(kcp_tokio::KcpError::protocol(e.to_string()));
                }
            };

            // Send to peer
            telemetry::record_udp_out(datagram.len());
            trace!(target: "paniq::transport_dump", direction = "tx", peer = %_server_addr, len = datagram.len(), msg_type = MessageType::Transport.into_u8(), hex = %hex::encode(&datagram));
            if let Err(e) = socket.send(&datagram).await {
                error!("Failed to send transport packet: {}", e);
                return Err(kcp_tokio::KcpError::protocol(e.to_string()));
            }

            Ok(())
        })
    });

    engine.set_output(output_fn);

    // Initialize KCP telemetry
    let mut kcp_telemetry = telemetry::logs_enabled().then(KcpTelemetry::new);

    // Main I/O loop with periodic updates
    let mut update_interval = tokio::time::interval(Duration::from_millis(update_ms as u64));
    let mut pending_reads: VecDeque<Bytes> = VecDeque::new();
    let mut pending_writes: VecDeque<Bytes> = VecDeque::new();
    let max_pending_reads = SMUX_MAX_RX_QUEUE;
    loop {
        let allow_send = should_accept_send(engine.stats(), max_snd_queue);
        tokio::select! {
            // Incoming KCP packets from UDP (feed engine.input)
            Some(data) = input_rx.recv() => {
                if let Some(ref mut tel) = kcp_telemetry {
                    tel.observe_kcp_input(data.len() as u64);
                }
                if !handle_kcp_result("input", engine.input(data).await) {
                    break;
                }
                if !handle_kcp_result("update", engine.update().await) {
                    break;
                }
            }

            // Application data to send via KCP (feed engine.send)
            Some(data) = write_rx.recv(), if allow_send && pending_writes.is_empty() => {
                let batch = coalesce_write_batch(data, &mut pending_writes, &mut write_rx, coalesce_limit);
                if let Some(ref mut tel) = kcp_telemetry {
                    tel.observe_app_send(batch.len() as u64);
                }
                if !handle_kcp_result("send", engine.send(batch).await) {
                    break;
                }
                if !handle_kcp_result("update", engine.update().await) {
                    break;
                }
            }

            // Periodic KCP update
            _ = update_interval.tick() => {
                if !handle_kcp_result("update", engine.update().await) {
                    break;
                }
            }

            // Check if engine is dead
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if engine.is_dead() {
                    info!("KCP engine connection is dead, exiting");
                    break;
                }
            }
        }

        if allow_send && !pending_writes.is_empty() {
            if let Some(data) = pending_writes.pop_front() {
                let batch =
                    coalesce_write_batch(data, &mut pending_writes, &mut write_rx, coalesce_limit);
                if let Some(ref mut tel) = kcp_telemetry {
                    tel.observe_app_send(batch.len() as u64);
                }
                if !handle_kcp_result("send", engine.send(batch).await) {
                    break;
                }
                if !handle_kcp_result("update", engine.update().await) {
                    break;
                }
            }
        }

        // Flush any pending reads without blocking the engine loop.
        while let Some(data) = pending_reads.pop_front() {
            match read_tx.try_send(data) {
                Ok(()) => {}
                Err(TrySendError::Full(data)) => {
                    pending_reads.push_front(data);
                    break;
                }
                Err(TrySendError::Closed(_)) => {
                    warn!("Failed to send to read channel - channel closed");
                    return;
                }
            }
        }

        // Drain KCP receive queue (application data received via KCP).
        while pending_reads.len() < max_pending_reads {
            match engine.recv().await {
                Ok(Some(data)) => {
                    if let Some(ref mut tel) = kcp_telemetry {
                        tel.observe_app_recv(data.len() as u64);
                    }
                    match read_tx.try_send(data) {
                        Ok(()) => {}
                        Err(TrySendError::Full(data)) => {
                            pending_reads.push_back(data);
                            break;
                        }
                        Err(TrySendError::Closed(_)) => {
                            warn!("Failed to send to read channel - channel closed");
                            return;
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    warn!("KCP recv error: {:?}", e);
                    break;
                }
            }
        }

        // Log telemetry if enabled
        if let Some(ref mut tel) = kcp_telemetry {
            if tel.should_log() {
                let stats = engine.stats().clone();
                tel.log_and_reset(conv_id, &stats);
            }
        }

        // Flush pending ACKs
        let _ = engine.flush().await;
    }
}
const KCP_NODELAY_INTERVAL_MS: u32 = 10;
const KCP_FAST_RESEND: u32 = 2;
const KCP_NO_CONGESTION: bool = true;
