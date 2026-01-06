//! Shared test harness for integration testing the full proxy stack.
//!
//! Provides a single `StackHarness` that spawns both the KCP proxy server
//! and SOCKS5 server using production code paths.

use std::net::SocketAddr;

use paniq::profile::Profile;
use paniq::runtime::{ProxyConfig, ProxyHandle, SocksConfig, SocksHandle};

/// Full stack harness for integration testing.
///
/// Spawns both a proxy server (KCP) and a SOCKS5 server that connects to it,
/// using the production code paths from `src/runtime/`.
pub struct StackHarness {
    /// Handle to the running KCP proxy server.
    pub proxy: ProxyHandle,
    /// Handle to the running SOCKS5 server.
    pub socks: SocksHandle,
}

impl StackHarness {
    fn load_profile() -> Result<Profile, Box<dyn std::error::Error + Send + Sync>> {
        let profile_path = std::env::var("PANIQ_TEST_PROFILE").unwrap_or_else(|_| {
            let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            path.push("examples");
            path.push("profile.json");
            path.to_string_lossy().to_string()
        });

        Ok(Profile::from_file(profile_path)?)
    }

    /// Spawn a new full stack with test defaults.
    ///
    /// # Arguments
    ///
    /// * `proxy_listen_addr` - Address for the proxy server to listen on
    /// * `socks_listen_addr` - Address for the SOCKS5 server to listen on
    ///
    /// # Returns
    ///
    /// A `StackHarness` containing both server handles.
    pub async fn spawn(
        proxy_listen_addr: SocketAddr,
        socks_listen_addr: SocketAddr,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let profile = Self::load_profile()?;
        Self::spawn_with_profile(proxy_listen_addr, socks_listen_addr, profile).await
    }

    /// Spawn a new full stack using a provided profile.
    pub async fn spawn_with_profile(
        proxy_listen_addr: SocketAddr,
        socks_listen_addr: SocketAddr,
        profile: Profile,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let proxy_config = ProxyConfig {
            listen_addr: proxy_listen_addr,
            profile: profile.clone(),
        };

        let proxy = ProxyHandle::spawn(proxy_config).await?;

        let mut socks_profile = profile;
        socks_profile.proxy_addr = proxy.addr.to_string();

        let socks_config = SocksConfig {
            listen_addr: socks_listen_addr,
            profile: socks_profile,
            auth: Some(("user".to_string(), "pass".to_string())),
        };

        let socks = SocksHandle::spawn(socks_config).await?;

        Ok(Self { proxy, socks })
    }

    /// Get the address of the SOCKS5 server for client connections.
    pub fn socks_addr(&self) -> SocketAddr {
        self.socks.addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_harness_spawn() {
        let harness = StackHarness::spawn("127.0.0.1:0".parse().unwrap(), "127.0.0.1:0".parse().unwrap())
            .await
            .expect("Failed to spawn harness");

        // Verify addresses are assigned
        assert_ne!(harness.proxy.addr.port(), 0);
        assert_ne!(harness.socks.addr.port(), 0);

        // Shutdown is implicit via Drop
    }
}
