#[cfg(feature = "kcp")]
pub mod client;
pub mod config;
pub mod envelope;
#[cfg(feature = "kcp")]
pub mod io;
pub mod obf;
pub mod profile;
pub mod proxy_protocol;

pub mod telemetry;

#[cfg(feature = "kcp")]
pub mod kcp;

#[cfg(feature = "socks5")]
pub mod socks5;

#[cfg(feature = "tokio")]
pub mod control;

#[cfg(feature = "mobile")]
pub mod ffi;
pub mod runtime;

#[cfg(feature = "mobile")]
uniffi::setup_scaffolding!("paniq");
