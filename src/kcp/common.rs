//! Shared types for the in-process KCP simulation layer.

use std::sync::Mutex;

use once_cell::sync::Lazy;
use tokio::sync::mpsc;

/// Registry keyed by the UDP address the server was started on.
pub static REGISTRY: Lazy<Mutex<std::collections::HashMap<std::net::SocketAddr, mpsc::Sender<crate::kcp::server::IncomingConnection>>>> =
    Lazy::new(|| Mutex::new(std::collections::HashMap::new()));
