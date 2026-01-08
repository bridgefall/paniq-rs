use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

pub(crate) const TELEMETRY_ENV: &str = "PANIQ_KCP_TELEMETRY";
pub(crate) const TELEMETRY_INTERVAL: Duration = Duration::from_secs(1);

static UDP_BYTES_IN: AtomicU64 = AtomicU64::new(0);
static UDP_BYTES_OUT: AtomicU64 = AtomicU64::new(0);
static TRANSPORT_PAYLOAD_IN: AtomicU64 = AtomicU64::new(0);
static TRANSPORT_PAYLOAD_OUT: AtomicU64 = AtomicU64::new(0);
static TRANSPORT_PADDING_IN: AtomicU64 = AtomicU64::new(0);
static TRANSPORT_PADDING_OUT: AtomicU64 = AtomicU64::new(0);
static TRANSPORT_FRAME_IN: AtomicU64 = AtomicU64::new(0);
static TRANSPORT_FRAME_OUT: AtomicU64 = AtomicU64::new(0);
static TRANSPORT_INVALID_LENGTH: AtomicU64 = AtomicU64::new(0);
static TRANSPORT_COUNTER_REJECT: AtomicU64 = AtomicU64::new(0);
static TRANSPORT_PAYLOAD_TOO_LARGE: AtomicU64 = AtomicU64::new(0);
static ACTIVE_CONNECTIONS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Default, Debug, serde::Serialize, serde::Deserialize)]
pub struct TransportSnapshot {
    pub udp_in_bytes: u64,
    pub udp_out_bytes: u64,
    pub transport_payload_in_bytes: u64,
    pub transport_payload_out_bytes: u64,
    pub transport_padding_in_bytes: u64,
    pub transport_padding_out_bytes: u64,
    pub transport_frame_in_bytes: u64,
    pub transport_frame_out_bytes: u64,
    pub transport_invalid_length: u64,
    pub transport_counter_reject: u64,
    pub transport_payload_too_large: u64,
    pub active_connections: u64,
}

impl TransportSnapshot {
    pub(crate) fn delta(self, prev: Self) -> Self {
        Self {
            udp_in_bytes: self.udp_in_bytes.saturating_sub(prev.udp_in_bytes),
            udp_out_bytes: self.udp_out_bytes.saturating_sub(prev.udp_out_bytes),
            transport_payload_in_bytes: self
                .transport_payload_in_bytes
                .saturating_sub(prev.transport_payload_in_bytes),
            transport_payload_out_bytes: self
                .transport_payload_out_bytes
                .saturating_sub(prev.transport_payload_out_bytes),
            transport_padding_in_bytes: self
                .transport_padding_in_bytes
                .saturating_sub(prev.transport_padding_in_bytes),
            transport_padding_out_bytes: self
                .transport_padding_out_bytes
                .saturating_sub(prev.transport_padding_out_bytes),
            transport_frame_in_bytes: self
                .transport_frame_in_bytes
                .saturating_sub(prev.transport_frame_in_bytes),
            transport_frame_out_bytes: self
                .transport_frame_out_bytes
                .saturating_sub(prev.transport_frame_out_bytes),
            transport_invalid_length: self
                .transport_invalid_length
                .saturating_sub(prev.transport_invalid_length),
            transport_counter_reject: self
                .transport_counter_reject
                .saturating_sub(prev.transport_counter_reject),
            transport_payload_too_large: self
                .transport_payload_too_large
                .saturating_sub(prev.transport_payload_too_large),
            active_connections: self
                .active_connections
                .saturating_sub(prev.active_connections),
        }
    }
}

pub(crate) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        let res = std::env::var(TELEMETRY_ENV)
            .ok()
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                _ => false,
            })
            .unwrap_or(true);
        tracing::info!(enabled = res, "Telemetry status initialized");
        res
    })
}

pub(crate) fn record_udp_in(bytes: usize) {
    if !enabled() {
        return;
    }
    tracing::trace!(bytes = bytes, "record_udp_in");
    UDP_BYTES_IN.fetch_add(bytes as u64, Ordering::Relaxed);
}

pub(crate) fn record_udp_out(bytes: usize) {
    if !enabled() {
        return;
    }
    tracing::trace!(bytes = bytes, "record_udp_out");
    UDP_BYTES_OUT.fetch_add(bytes as u64, Ordering::Relaxed);
}

pub(crate) fn record_transport_out(payload_len: usize, pad_len: usize, frame_len: usize) {
    if !enabled() {
        return;
    }
    tracing::trace!(payload_len, pad_len, frame_len, "record_transport_out");
    TRANSPORT_PAYLOAD_OUT.fetch_add(payload_len as u64, Ordering::Relaxed);
    TRANSPORT_PADDING_OUT.fetch_add(pad_len as u64, Ordering::Relaxed);
    TRANSPORT_FRAME_OUT.fetch_add(frame_len as u64, Ordering::Relaxed);
}

pub(crate) fn record_transport_in(payload_len: usize, pad_len: usize, frame_len: usize) {
    if !enabled() {
        return;
    }
    tracing::trace!(payload_len, pad_len, frame_len, "record_transport_in");
    TRANSPORT_PAYLOAD_IN.fetch_add(payload_len as u64, Ordering::Relaxed);
    TRANSPORT_PADDING_IN.fetch_add(pad_len as u64, Ordering::Relaxed);
    TRANSPORT_FRAME_IN.fetch_add(frame_len as u64, Ordering::Relaxed);
}

pub(crate) fn record_transport_invalid_length() {
    if !enabled() {
        return;
    }
    tracing::warn!("record_transport_invalid_length");
    TRANSPORT_INVALID_LENGTH.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_transport_counter_reject() {
    if !enabled() {
        return;
    }
    tracing::warn!("record_transport_counter_reject");
    TRANSPORT_COUNTER_REJECT.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_transport_payload_too_large() {
    if !enabled() {
        return;
    }
    tracing::warn!("record_transport_payload_too_large");
    TRANSPORT_PAYLOAD_TOO_LARGE.fetch_add(1, Ordering::Relaxed);
}

pub fn record_connection_open() {
    tracing::debug!("record_connection_open");
    ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
}

pub fn record_connection_close() {
    tracing::debug!("record_connection_close");
    ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
}

/// RAII guard for tracking an active connection.
pub struct ConnectionGuard;

impl ConnectionGuard {
    pub fn new() -> Self {
        record_connection_open();
        Self
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        record_connection_close();
    }
}

pub fn transport_snapshot() -> TransportSnapshot {
    TransportSnapshot {
        udp_in_bytes: UDP_BYTES_IN.load(Ordering::Relaxed),
        udp_out_bytes: UDP_BYTES_OUT.load(Ordering::Relaxed),
        transport_payload_in_bytes: TRANSPORT_PAYLOAD_IN.load(Ordering::Relaxed),
        transport_payload_out_bytes: TRANSPORT_PAYLOAD_OUT.load(Ordering::Relaxed),
        transport_padding_in_bytes: TRANSPORT_PADDING_IN.load(Ordering::Relaxed),
        transport_padding_out_bytes: TRANSPORT_PADDING_OUT.load(Ordering::Relaxed),
        transport_frame_in_bytes: TRANSPORT_FRAME_IN.load(Ordering::Relaxed),
        transport_frame_out_bytes: TRANSPORT_FRAME_OUT.load(Ordering::Relaxed),
        transport_invalid_length: TRANSPORT_INVALID_LENGTH.load(Ordering::Relaxed),
        transport_counter_reject: TRANSPORT_COUNTER_REJECT.load(Ordering::Relaxed),
        transport_payload_too_large: TRANSPORT_PAYLOAD_TOO_LARGE.load(Ordering::Relaxed),
        active_connections: ACTIVE_CONNECTIONS.load(Ordering::Relaxed),
    }
}
