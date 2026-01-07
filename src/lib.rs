#[cfg(feature = "kcp")]
pub mod client;
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

#[cfg(feature = "socks5")]
pub mod control;

#[cfg(all(feature = "socks5", feature = "kcp"))]
pub mod ffi;
pub mod runtime;

uniffi::setup_scaffolding!("paniq");
