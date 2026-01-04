//! Runtime components for spawnable proxy and SOCKS5 servers.
//!
//! This module provides test-friendly wrappers around the production proxy-server
//! and socks5d binaries, allowing them to be spawned in-process for integration testing.

mod proxy;
mod socks;

pub use proxy::{ProxyConfig, ProxyHandle};
pub use socks::{SocksConfig, SocksHandle};
