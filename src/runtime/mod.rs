//! Runtime components for spawnable proxy and SOCKS5 servers.
//!
//! This module provides test-friendly wrappers around the production proxy-server
//! and socks5d binaries, allowing them to be spawned in-process for integration testing.

#[cfg(feature = "kcp")]
mod proxy;
#[cfg(all(feature = "socks5", feature = "kcp"))]
mod socks;

#[cfg(feature = "kcp")]
pub use proxy::{ProxyConfig, ProxyHandle};
#[cfg(all(feature = "socks5", feature = "kcp"))]
pub use socks::{SocksConfig, SocksHandle};
