//! KCP transport layer over UDP with obfuscation envelope.
//!
//! This module owns the UDP socket, performs the envelope handshake,
//! manages KCP sessions, and drives the update loops.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::envelope::client::{client_handshake_async, TokioPacketConn};
use crate::envelope::padding::PaddingPolicy;
use crate::envelope::transport::{build_transport_payload, decode_transport_payload};
use crate::kcp::mux::{run_kcp_pump, KcpStreamAdapter};
use crate::obf::{Framer, MessageType, SharedRng};
use crate::telemetry;

// Import kcp types - kcp-rs library is named "kcp" internally
use kcp::Kcp;

const TRANSPORT_LEN_FIELD: usize = 2;
const TRANSPORT_COUNTER_FIELD: usize = 8;

// Smux queue sizes for concurrent stream performance
// Default 1024 is too small for high-throughput scenarios with multiple concurrent streams
const SMUX_MAX_TX_QUEUE: usize = 8192;
const SMUX_MAX_RX_QUEUE: usize = 8192;

// KCP window sizes for high-throughput WAN scenarios
// Default 32 caps throughput at ~(32 * MTU) / RTT. At 1200B MTU and 50ms RTT: ~0.75 MB/s
// 1024 allows for ~24 MB/s at 50ms RTT, sufficient for most WAN scenarios
const KCP_SND_WND: u32 = 1024;
const KCP_RCV_WND: u32 = 1024;

fn compute_kcp_mtu(max_packet_size: usize, max_payload: usize, transport_replay: bool) -> u32 {
    let overhead = TRANSPORT_LEN_FIELD
        + if transport_replay {
            TRANSPORT_COUNTER_FIELD
        } else {
            0
        };
    let payload_budget = max_payload.min(max_packet_size);
    payload_budget.saturating_sub(overhead).max(1) as u32
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
        let interval_duration =
            telemetry::log_interval().unwrap_or(std::time::Duration::from_secs(1));
        let mut last = telemetry::transport_snapshot();
        let mut interval = tokio::time::interval(interval_duration);
        loop {
            interval.tick().await;
            let current = telemetry::transport_snapshot();
            let delta = current.delta(last);
            last = current;

            let secs = interval_duration.as_secs_f64();
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
                interval_ms = interval_duration.as_millis(),
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

/// KCP session state.
pub struct SessionState {
    /// Peer address
    pub peer_addr: SocketAddr,
    /// Last activity timestamp
    pub last_seen: tokio::time::Instant,
    /// Counter for transport replay protection
    pub counter: u64,
    /// Channel for sending incoming KCP packets to the pump (UDP -> pump -> kcp.input)
    pub input_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// UDP send loop handle (for cleanup)
    pub udp_send_handle: Option<tokio::task::JoinHandle<()>>,
    /// Smux connector (must be kept alive to prevent worker exit)
    pub connector: async_smux::MuxConnector<crate::kcp::mux::KcpStreamAdapter>,
}

/// Server-side transport that accepts incoming KCP connections.
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
}

/// Server configuration.
#[derive(Clone)]
pub struct ServerConfig {
    /// Maximum packet size for transport payloads
    pub max_packet_size: usize,
    /// Maximum payload size
    pub max_payload: usize,
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
        info!("KCP server listening on {}", socket.local_addr()?);
        Ok(Self {
            socket: Arc::new(socket),
            framer: Arc::new(framer),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            config,
            conn_tx: Arc::new(Mutex::new(None)),
            ready_tx: Arc::new(Mutex::new(None)),
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

    /// Start the server receive loop.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        start_transport_logger();
        let mut buf = vec![0u8; 65536];
        let mut update_interval = tokio::time::interval(Duration::from_millis(20));

        let mut iter_count = 0u64;

        // First, yield to ensure the tokio runtime has registered the socket
        tokio::task::yield_now().await;

        // Send ready signal AFTER we've entered the loop
        loop {
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
                            let (msg_type, payload) = match self.framer.decode_frame(datagram) {
                                Ok(v) => v,
                                Err(e) => {
                                    debug!("Failed to decode frame from {}: {}", peer_addr, e);
                                    continue;
                                }
                            };

                            debug!("Decoded message type: {:?}, payload length: {}", msg_type, payload.len());

                            match msg_type {
                                MessageType::Initiation => {
                                    // Handle handshake initiation
                                    if let Err(e) = self.handle_handshake_initiation(peer_addr, payload).await {
                                        warn!("Handshake failed from {}: {}", peer_addr, e);
                                    }
                                }
                                MessageType::Transport => {
                                    // Handle KCP transport packet
                                    self.handle_transport(peer_addr, payload).await;
                                }
                                MessageType::CookieReply | MessageType::Response => {
                                    // These are handled during handshake, ignore here
                                    debug!("Unexpected handshake message from {}: {:?}", peer_addr, msg_type);
                                }
                            }
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                    }
                }

                // Periodic KCP update and cleanup
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
        let conv_id = Kcp::rand_conv();

        debug!(
            "Handshake from {}, assigning conv_id={}",
            peer_addr, conv_id
        );

        // Create and pin KCP instance (required by kcp-rs)
        let mut kcp = Box::pin(Kcp::new(conv_id));
        kcp.as_mut().initialize();
        let mtu = compute_kcp_mtu(
            self.config.max_packet_size,
            self.config.max_payload,
            self.config.transport_replay,
        );
        kcp.as_mut().set_mtu(mtu)?;
        kcp.as_mut().set_nodelay(true, 10, 2, true);
        kcp.as_mut().set_stream(true);
        // Set larger window sizes for high-throughput WAN scenarios
        // Default 32 caps throughput at ~(32 * MTU) / RTT
        kcp.as_mut().set_wndsize(KCP_SND_WND, KCP_RCV_WND);

        // Create adapter and channels
        let (adapter, pump_chans, transport_chans) =
            KcpStreamAdapter::new_adapter(self.config.max_payload);
        let input_tx = transport_chans.input_tx.clone();

        // Build the smux server with larger queues for concurrent streams
        // Default 1024 tx/rx queues are too small for high-throughput scenarios
        let mut builder = async_smux::MuxBuilder::server();
        builder.with_max_tx_queue(std::num::NonZeroUsize::new(SMUX_MAX_TX_QUEUE).unwrap());
        builder.with_max_rx_queue(std::num::NonZeroUsize::new(SMUX_MAX_RX_QUEUE).unwrap());
        let (connector, acceptor, worker) = builder.with_connection(adapter).build();

        // Spawn the mux worker task
        tokio::spawn(async move {
            let res = worker.await;
            if let Err(e) = res {
                error!("Smux worker error: {:?}", e);
            }
        });

        // Spawn the KCP pump task
        let pump = tokio::spawn(async move {
            let res = run_kcp_pump(
                kcp,
                pump_chans.input_rx,
                pump_chans.write_rx,
                pump_chans.read_tx,
                pump_chans.output_tx,
            )
            .await;
            if let Err(e) = res {
                error!("KCP pump error: {:?}", e);
            }
        });

        // Spawn UDP send loop for KCP output
        let socket = self.socket.clone();
        let framer = self.framer.clone();
        let config = self.config.clone();
        let udp_send_loop = tokio::spawn(async move {
            udp_send_loop(
                socket,
                framer,
                peer_addr,
                pump,
                transport_chans.output_rx,
                config,
            )
            .await;
        });

        let session = SessionState {
            peer_addr,
            last_seen: tokio::time::Instant::now(),
            counter: 0,
            input_tx,
            udp_send_handle: Some(udp_send_loop),
            connector,
        };

        // Insert session BEFORE sending Response to avoid race
        self.sessions
            .lock()
            .await
            .insert((peer_addr, conv_id), session);

        // NOW send Response - session is ready to receive data
        let response_payload = conv_id.to_be_bytes().to_vec();
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
            // Ignore send errors - channel might be closed
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
            // TODO: Add replay cache for counter validation
            None::<&mut Box<dyn FnMut(u64) -> bool>>,
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Failed to decode transport payload: {}", e);
                return;
            }
        };

        // Extract conv_id from KCP packet
        let conv_id = match Kcp::read_conv(&kcp_bytes) {
            Some(id) => id,
            None => {
                warn!("Invalid KCP packet: missing conv_id");
                return;
            }
        };

        // Find the session
        let mut sessions = self.sessions.lock().await;
        let session = match sessions.get_mut(&(peer_addr, conv_id)) {
            Some(s) => s,
            None => {
                warn!("Unknown session: {} conv_id={}", peer_addr, conv_id);
                return;
            }
        };

        // Feed the packet to the KCP pump via input_tx
        session.last_seen = tokio::time::Instant::now();
        if (session.input_tx.send(kcp_bytes).await).is_err() {
            warn!("Failed to send data to KCP pump - channel closed");
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
            sessions.remove(&key);
        }
    }
}

/// UDP send loop for KCP output packets (server side).
async fn udp_send_loop(
    socket: Arc<UdpSocket>,
    framer: Arc<Framer>,
    peer_addr: SocketAddr,
    _pump_handle: tokio::task::JoinHandle<()>,
    mut output_rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    config: ServerConfig,
) {
    let mut counter = 0u64;
    while let Some(kcp_bytes) = output_rx.recv().await {
        // Build transport payload with counter and padding
        let payload = {
            let mut rng_guard = framer.rng().0.lock().unwrap();
            build_transport_payload(
                kcp_bytes.as_ref(),
                if config.transport_replay {
                    Some(counter)
                } else {
                    None
                },
                &config.padding_policy,
                config.max_payload,
                &mut *rng_guard,
            )
        };
        let payload = match payload {
            Ok(p) => p,
            Err(e) => {
                error!(
                    "Failed to build transport payload (kcp_len={}, max_payload={}): {}",
                    kcp_bytes.len(),
                    config.max_payload,
                    e
                );
                continue;
            }
        };

        if config.transport_replay {
            counter = counter.wrapping_add(1);
        }

        // Encode as Transport frame
        let datagram = match framer.encode_frame(MessageType::Transport, &payload) {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to encode transport frame: {}", e);
                continue;
            }
        };

        // Send to peer
        telemetry::record_udp_out(datagram.len());
        if let Err(e) = socket.send_to(&datagram, peer_addr).await {
            error!("Failed to send transport packet: {}", e);
            return;
        }
    }
    info!("UDP send loop ended for {}", peer_addr);
}

/// UDP send loop for KCP output packets (client side).
async fn udp_send_loop_client(
    socket: Arc<UdpSocket>,
    framer: Arc<Framer>,
    server_addr: SocketAddr,
    _pump_handle: tokio::task::JoinHandle<()>,
    mut output_rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    config: ClientConfig,
) {
    let mut counter = 0u64;
    while let Some(kcp_bytes) = output_rx.recv().await {
        // Build transport payload with counter and padding
        let payload = {
            let mut rng_guard = framer.rng().0.lock().unwrap();
            build_transport_payload(
                kcp_bytes.as_ref(),
                if config.transport_replay {
                    Some(counter)
                } else {
                    None
                },
                &config.padding_policy,
                config.max_payload,
                &mut *rng_guard,
            )
        };
        let payload = match payload {
            Ok(p) => p,
            Err(e) => {
                error!(
                    "Failed to build transport payload (kcp_len={}, max_payload={}): {}",
                    kcp_bytes.len(),
                    config.max_payload,
                    e
                );
                continue;
            }
        };

        if config.transport_replay {
            counter = counter.wrapping_add(1);
        }

        // Encode as Transport frame
        let datagram = match framer.encode_frame(MessageType::Transport, &payload) {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to encode transport frame: {}", e);
                continue;
            }
        };

        // Send to peer
        telemetry::record_udp_out(datagram.len());
        if let Err(e) = socket.send(&datagram).await {
            error!("Failed to send transport packet: {}", e);
            return;
        }
    }
    info!("UDP send loop ended for {}", server_addr);
}

/// Client-side transport that connects to a KCP server.
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
}

/// Client configuration.
#[derive(Clone)]
pub struct ClientConfig {
    /// Maximum packet size for transport payloads
    pub max_packet_size: usize,
    /// Maximum payload size
    pub max_payload: usize,
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

        // Extract conv_id from Response payload (4 bytes big-endian)
        if payload.len() < 4 {
            return Err("Response payload too short for conv_id".into());
        }
        let conv_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

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
        };

        // Complete session setup (KCP, smux, etc.)
        client.complete_session_setup(conv_id).await?;

        // Start UDP receive loop (CRITICAL - was missing!)
        client.start_udp_receive_loop();

        Ok(client)
    }

    /// Complete session setup after handshake (KCP, smux, etc.).
    async fn complete_session_setup(&self, conv_id: u32) -> Result<(), Box<dyn std::error::Error>> {
        // Create and pin KCP instance (required by kcp-rs)
        let mut kcp = Box::pin(Kcp::new(conv_id));
        kcp.as_mut().initialize();
        let mtu = compute_kcp_mtu(
            self.config.max_packet_size,
            self.config.max_payload,
            self.config.transport_replay,
        );
        kcp.as_mut().set_mtu(mtu)?;
        kcp.as_mut().set_nodelay(true, 10, 2, true);
        kcp.as_mut().set_stream(true);
        // Set larger window sizes for high-throughput WAN scenarios
        // Default 32 caps throughput at ~(32 * MTU) / RTT
        kcp.as_mut().set_wndsize(KCP_SND_WND, KCP_RCV_WND);

        // Create adapter and channels
        let (adapter, pump_chans, transport_chans) =
            KcpStreamAdapter::new_adapter(self.config.max_payload);
        let input_tx = transport_chans.input_tx.clone();

        // Trigger KCP update to ensure it's ready to send/receive
        let current = kcp.get_system_time();
        kcp.as_mut().update(current);
        kcp.as_mut().flush();

        // Build the smux client with larger queues for concurrent streams
        // Default 1024 tx/rx queues are too small for high-throughput scenarios
        let mut builder = async_smux::MuxBuilder::client();
        builder.with_max_tx_queue(std::num::NonZeroUsize::new(SMUX_MAX_TX_QUEUE).unwrap());
        builder.with_max_rx_queue(std::num::NonZeroUsize::new(SMUX_MAX_RX_QUEUE).unwrap());
        let (connector, acceptor, worker) = builder.with_connection(adapter).build();

        // Spawn the mux worker task
        tokio::spawn(async move {
            if let Err(e) = worker.await {
                error!("Smux worker error: {:?}", e);
            }
        });

        // Spawn the KCP pump task
        let kcp_pump = tokio::spawn(async move {
            if let Err(e) = run_kcp_pump(
                kcp,
                pump_chans.input_rx,
                pump_chans.write_rx,
                pump_chans.read_tx,
                pump_chans.output_tx,
            )
            .await
            {
                error!("KCP pump error: {:?}", e);
            }
        });

        // Spawn UDP send loop for KCP output
        let socket = self.socket.clone();
        let framer = self.framer.clone();
        let config = self.config.clone();
        let server_addr = self.server_addr;
        let udp_send_loop = tokio::spawn(async move {
            udp_send_loop_client(
                socket,
                framer,
                server_addr,
                kcp_pump,
                transport_chans.output_rx,
                config,
            )
            .await;
        });

        // Store the mux components
        *self.connector.lock().await = Some(connector);
        *self.acceptor.lock().await = Some(acceptor);

        let session = SessionState {
            peer_addr: self.server_addr,
            last_seen: tokio::time::Instant::now(),
            counter: 0,
            input_tx,
            udp_send_handle: Some(udp_send_loop),
            connector: self.connector.lock().await.as_ref().unwrap().clone(),
        };

        *self.session.lock().await = Some(session);

        Ok(())
    }

    /// Start the UDP receive loop (CRITICAL - this was missing!).
    fn start_udp_receive_loop(&self) {
        start_transport_logger();
        let socket = self.socket.clone();
        let framer = self.framer.clone();
        let session = self.session.clone();
        let transport_replay = self.config.transport_replay;

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match socket.recv(&mut buf).await {
                    Ok(len) => {
                        telemetry::record_udp_in(len);
                        let datagram = &buf[..len];

                        // Decode the framer
                        let (msg_type, payload) = match framer.decode_frame(datagram) {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::debug!("Failed to decode frame: {}", e);
                                continue;
                            }
                        };

                        match msg_type {
                            MessageType::Transport => {
                                // Handle KCP transport packet
                                // Decode transport payload with counter validation
                                let kcp_bytes = match decode_transport_payload(
                                    &payload,
                                    transport_replay,
                                    // TODO: Add replay cache for counter validation
                                    None::<&mut Box<dyn FnMut(u64) -> bool>>,
                                ) {
                                    Ok(bytes) => bytes,
                                    Err(e) => {
                                        tracing::warn!("Failed to decode transport payload: {}", e);
                                        continue;
                                    }
                                };

                                // Send to KCP pump via input_tx
                                let session_guard = session.lock().await;
                                if let Some(ref session) = *session_guard {
                                    if (session.input_tx.send(kcp_bytes).await).is_err() {
                                        tracing::warn!(
                                            "Failed to send to KCP pump - channel closed"
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
                        tracing::error!("UDP receive error: {}", e);
                        break;
                    }
                }
            }
        });
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

    /// Open a new bidirectional stream (for compatibility with existing API).
    pub async fn open_bi(
        &self,
    ) -> Result<crate::kcp::client::Connection, Box<dyn std::error::Error>> {
        // TODO: Implement via async_smux
        Err("open_bi not yet implemented".into())
    }
}
