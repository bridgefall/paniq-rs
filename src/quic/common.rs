use crate::profile::QuicConfig as ProfileQuicConfig;

pub fn configure_transport(config: &mut quinn::TransportConfig, quic_cfg: Option<&ProfileQuicConfig>) {
    let _ = quic_cfg; // Suppress unused warning for now

    // Use minimal configuration - similar to the passing roundtrip test
    // TODO: Properly configure from profile once we identify the issue
    config.max_idle_timeout(Some(
        std::time::Duration::from_secs(120).try_into().unwrap(),
    ));
    // Don't set keep_alive_interval - use Quinn's default
    // Don't set initial_rtt - use Quinn's default
    // Don't set max_concurrent_bidi_streams - use Quinn's default
}
