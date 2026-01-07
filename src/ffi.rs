use crate::profile::Profile;
use crate::runtime::{SocksConfig, SocksHandle};
use base64::Engine;
use once_cell::sync::Lazy;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

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

#[derive(uniffi::Record)]
pub struct DaemonConfig {
    pub profile_path: String,
    pub listen_addr: String,
    pub proxy_addr_override: Option<String>,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PaniqError {
    #[error("Daemon error: {err_msg}")]
    DaemonError { err_msg: String },
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
    pub fn start(&self, config: DaemonConfig) -> Result<(), PaniqError> {
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
}
