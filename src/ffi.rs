use crate::config::FileConfig;
use crate::config::Socks5FileConfig as Config;
use crate::profile::Profile;
use crate::runtime::{SocksConfig, SocksHandle};
use base64::Engine;
use once_cell::sync::Lazy;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[uniffi::export]
pub fn decode_profile_to_json(base64_cbor: String) -> Result<String, PaniqError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(base64_cbor.trim())
        .map_err(|e| PaniqError::DaemonError {
            err_msg: format!("Base64 decode error: {}", e),
        })?;

    let profile = crate::profile::cbor::decode_compact_profile(&raw).map_err(|e| {
        PaniqError::DaemonError {
            err_msg: format!("CBOR decode error: {}", e),
        }
    })?;

    serde_json::to_string_pretty(&profile).map_err(|e| PaniqError::DaemonError {
        err_msg: format!("JSON encode error: {}", e),
    })
}

/// Configuration for starting the daemon (simplified version for UniFFI).
#[derive(uniffi::Record)]
pub struct DaemonStartConfig {
    pub profile_path: String,
    pub listen_addr: String,
    pub proxy_addr_override: Option<String>,
}

/// Full daemon configuration for runtime settings.
#[derive(uniffi::Record)]
pub struct DaemonSettings {
    pub log_level: String,
    pub workers: u32,
    pub max_connections: u32,
    pub dial_timeout_ms: u64,
    pub accept_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub metrics_interval_ms: u64,
    pub listen_addr: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Snapshot of transport statistics.
#[derive(uniffi::Record)]
pub struct TransportStats {
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

impl From<DaemonSettings> for Config {
    fn from(settings: DaemonSettings) -> Self {
        Self {
            log_level: settings.log_level,
            workers: settings.workers as usize,
            max_connections: settings.max_connections as usize,
            dial_timeout: std::time::Duration::from_millis(settings.dial_timeout_ms),
            accept_timeout: std::time::Duration::from_millis(settings.accept_timeout_ms),
            idle_timeout: std::time::Duration::from_millis(settings.idle_timeout_ms),
            metrics_interval: std::time::Duration::from_millis(settings.metrics_interval_ms),
            listen_addr: settings.listen_addr,
            username: settings.username,
            password: settings.password,
            control_socket: None,
        }
    }
}

impl From<Config> for DaemonSettings {
    fn from(config: Config) -> Self {
        Self {
            log_level: config.log_level,
            workers: config.workers as u32,
            max_connections: config.max_connections as u32,
            dial_timeout_ms: config.dial_timeout.as_millis() as u64,
            accept_timeout_ms: config.accept_timeout.as_millis() as u64,
            idle_timeout_ms: config.idle_timeout.as_millis() as u64,
            metrics_interval_ms: config.metrics_interval.as_millis() as u64,
            listen_addr: config.listen_addr,
            username: config.username,
            password: config.password,
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PaniqError {
    #[error("Daemon error: {err_msg}")]
    DaemonError { err_msg: String },
}

#[uniffi::export(callback_interface)]
pub trait PaniqLogHandler: Send + Sync {
    fn log(&self, level: LogLevel, message: String);
}

#[derive(uniffi::Enum)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl From<tracing::Level> for LogLevel {
    fn from(level: tracing::Level) -> Self {
        match level {
            tracing::Level::DEBUG | tracing::Level::TRACE => LogLevel::Debug,
            tracing::Level::INFO => LogLevel::Info,
            tracing::Level::WARN => LogLevel::Warn,
            tracing::Level::ERROR => LogLevel::Error,
        }
    }
}

struct PaniqLogger {
    handler: Box<dyn PaniqLogHandler>,
    min_level: tracing::Level,
}

impl<S> tracing_subscriber::Layer<S> for PaniqLogger
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // Filter events by level
        if *event.metadata().level() > self.min_level {
            return;
        }

        let mut message = String::new();
        let mut visitor = MessageVisitor {
            message: &mut message,
        };
        event.record(&mut visitor);

        self.handler
            .log((*event.metadata().level()).into(), message);
    }
}

struct MessageVisitor<'a> {
    message: &'a mut String,
}

impl<'a> tracing::field::Visit for MessageVisitor<'a> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            use std::fmt::Write;
            write!(self.message, "{:?}", value).ok();
        } else {
            self.message
                .push_str(&format!(" {}={:?}", field.name(), value));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            self.message
                .push_str(&format!(" {}={}", field.name(), value));
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        if field.name() == "message" {
            self.message.push_str(&value.to_string());
        } else {
            self.message
                .push_str(&format!(" {}={}", field.name(), value));
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "message" {
            self.message.push_str(&value.to_string());
        } else {
            self.message
                .push_str(&format!(" {}={}", field.name(), value));
        }
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        if field.name() == "message" {
            self.message.push_str(&value.to_string());
        } else {
            self.message
                .push_str(&format!(" {}={}", field.name(), value));
        }
    }
}

#[uniffi::export]
pub fn setup_logging(handler: Box<dyn PaniqLogHandler>, level: LogLevel) {
    let min_level = match level {
        LogLevel::Error => tracing::Level::ERROR,
        LogLevel::Warn => tracing::Level::WARN,
        LogLevel::Info => tracing::Level::INFO,
        LogLevel::Debug => tracing::Level::DEBUG,
    };
    let logger = PaniqLogger { handler, min_level };
    let _ = tracing_subscriber::registry().with(logger).try_init();
}

#[derive(uniffi::Object)]
pub struct PaniqDaemon {
    handle: Mutex<Option<SocksHandle>>,
    runtime: tokio::runtime::Runtime,
}

static DAEMON: Lazy<Arc<PaniqDaemon>> = Lazy::new(|| {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");
    Arc::new(PaniqDaemon {
        handle: Mutex::new(None),
        runtime,
    })
});

#[uniffi::export]
pub fn get_daemon() -> Arc<PaniqDaemon> {
    DAEMON.clone()
}

#[uniffi::export]
impl PaniqDaemon {
    pub fn start(&self, config: DaemonStartConfig) -> Result<(), PaniqError> {
        let mut handle_guard = self
            .handle
            .try_lock()
            .map_err(|_| PaniqError::DaemonError {
                err_msg: "Daemon already starting/locked".to_string(),
            })?;
        if handle_guard.is_some() {
            return Err(PaniqError::DaemonError {
                err_msg: "Daemon already running".to_string(),
            });
        }

        let profile = Profile::from_file(config.profile_path.as_str()).map_err(|e| {
            PaniqError::DaemonError {
                err_msg: format!("Profile error: {}", e),
            }
        })?;

        let listen_addr: SocketAddr =
            config
                .listen_addr
                .parse()
                .map_err(|e| PaniqError::DaemonError {
                    err_msg: format!("Invalid listen address: {}", e),
                })?;

        let mut socks_config = SocksConfig {
            listen_addr,
            profile,
            auth: None, // Can be added later if needed
        };

        if let Some(addr_override) = config.proxy_addr_override {
            socks_config.profile.proxy_addr = addr_override;
        }

        let handle = self
            .runtime
            .block_on(async { SocksHandle::spawn(socks_config).await })
            .map_err(|e| PaniqError::DaemonError {
                err_msg: format!("Failed to spawn daemon: {}", e),
            })?;

        *handle_guard = Some(handle);

        Ok(())
    }

    pub fn stop(&self) {
        if let Ok(mut handle_guard) = self.handle.try_lock() {
            if let Some(handle) = handle_guard.take() {
                handle.shutdown();
            }
        }
    }

    pub fn is_running(&self) -> bool {
        if let Ok(handle_guard) = self.handle.try_lock() {
            handle_guard.is_some()
        } else {
            false
        }
    }

    pub fn get_stats(&self) -> TransportStats {
        let snapshot = crate::telemetry::transport_snapshot();
        TransportStats {
            udp_in_bytes: snapshot.udp_in_bytes,
            udp_out_bytes: snapshot.udp_out_bytes,
            transport_payload_in_bytes: snapshot.transport_payload_in_bytes,
            transport_payload_out_bytes: snapshot.transport_payload_out_bytes,
            transport_padding_in_bytes: snapshot.transport_padding_in_bytes,
            transport_padding_out_bytes: snapshot.transport_padding_out_bytes,
            transport_frame_in_bytes: snapshot.transport_frame_in_bytes,
            transport_frame_out_bytes: snapshot.transport_frame_out_bytes,
            transport_invalid_length: snapshot.transport_invalid_length,
            transport_counter_reject: snapshot.transport_counter_reject,
            transport_payload_too_large: snapshot.transport_payload_too_large,
            active_connections: snapshot.active_connections,
        }
    }
}

/// Load daemon configuration from a JSON file.
///
/// Returns the loaded configuration or default values if the file doesn't exist.
#[uniffi::export]
pub fn load_daemon_config(path: String) -> Result<DaemonSettings, PaniqError> {
    let config = Config::load_from_file(&path).map_err(|e| PaniqError::DaemonError {
        err_msg: format!("Failed to load config: {}", e),
    })?;
    Ok(config.into())
}

/// Save daemon configuration to a JSON file.
#[uniffi::export]
pub fn save_daemon_config(path: String, settings: DaemonSettings) -> Result<(), PaniqError> {
    let config: Config = settings.into();
    config
        .save_to_file(&path)
        .map_err(|e| PaniqError::DaemonError {
            err_msg: format!("Failed to save config: {}", e),
        })?;
    Ok(())
}

/// Get default daemon configuration.
#[uniffi::export]
pub fn get_default_daemon_settings() -> DaemonSettings {
    Config::default().into()
}
