// Profile configuration for paniq client
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::envelope::padding::PaddingPolicy;
use crate::obf::{Config as ObfConfig, FRAME_HEADER_LEN};

/// Profile configuration containing proxy address, KCP settings, and obfuscation
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Profile {
    pub name: String,
    pub proxy_addr: String,

    #[serde(default)]
    #[serde(with = "serde_duration::opt")]
    pub handshake_timeout: Option<Duration>,

    #[serde(default = "default_handshake_attempts")]
    pub handshake_attempts: usize,

    #[serde(default)]
    #[serde(with = "serde_duration::opt_u64_millis")]
    pub preamble_delay_ms: Option<u64>,

    #[serde(default)]
    #[serde(with = "serde_duration::opt_u64_millis")]
    pub preamble_jitter_ms: Option<u64>,

    #[serde(default)]
    pub kcp: Option<KcpConfig>,

    #[serde(default)]
    pub transport_padding: Option<TransportPadding>,

    #[serde(default)]
    pub obfuscation: ObfuscationConfig,
}

const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 5;
const DEFAULT_PREAMBLE_DELAY_MS: u64 = 5;

fn default_handshake_attempts() -> usize {
    3
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KcpConfig {
    #[serde(default = "default_max_packet_size")]
    pub max_packet_size: usize,

    #[serde(default = "default_max_payload")]
    pub max_payload: usize,

    #[serde(default)]
    #[serde(with = "serde_duration::default")]
    pub keepalive: Duration,

    #[serde(default)]
    #[serde(with = "serde_duration::default")]
    pub idle_timeout: Duration,

    #[serde(default = "default_max_streams")]
    pub max_streams: usize,

    /// Optional explicit KCP send window size (in segments)
    #[serde(default)]
    pub send_window: Option<u32>,

    /// Optional explicit KCP receive window size (in segments)
    #[serde(default)]
    pub recv_window: Option<u32>,

    /// Optional target throughput in bits per second for BDP-based window sizing
    #[serde(default)]
    pub target_bps: Option<u64>,

    /// Optional RTT estimate in milliseconds for BDP-based window sizing
    #[serde(default)]
    pub rtt_ms: Option<u64>,

    /// Optional maximum KCP send queue size (in segments)
    #[serde(default)]
    pub max_snd_queue: Option<u32>,
}

fn default_max_packet_size() -> usize {
    1350
}
fn default_max_payload() -> usize {
    1200
}
fn default_max_streams() -> usize {
    256
}

fn default_handshake_timeout() -> Duration {
    Duration::from_secs(DEFAULT_HANDSHAKE_TIMEOUT_SECS)
}

fn default_preamble_delay_ms() -> u64 {
    DEFAULT_PREAMBLE_DELAY_MS
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            max_packet_size: default_max_packet_size(),
            max_payload: default_max_payload(),
            keepalive: Duration::default(),
            idle_timeout: Duration::default(),
            max_streams: default_max_streams(),
            send_window: None,
            recv_window: None,
            target_bps: None,
            rtt_ms: None,
            max_snd_queue: None,
        }
    }
}

impl KcpConfig {
    pub fn effective_max_payload(&self) -> usize {
        let max_packet_size = self.max_packet_size;
        let max_payload = self.max_payload.min(max_packet_size);

        if self.max_payload == default_max_payload() {
            max_packet_size
        } else {
            max_payload
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransportPadding {
    #[serde(default = "default_pad_min")]
    pub pad_min: usize,

    #[serde(default = "default_pad_max")]
    pub pad_max: usize,

    #[serde(default = "default_pad_burst_min")]
    pub pad_burst_min: usize,

    #[serde(default = "default_pad_burst_max")]
    pub pad_burst_max: usize,

    #[serde(default = "default_pad_burst_prob")]
    pub pad_burst_prob: f64,
}

fn default_pad_min() -> usize {
    16
}
fn default_pad_max() -> usize {
    96
}
fn default_pad_burst_min() -> usize {
    96
}
fn default_pad_burst_max() -> usize {
    104
}
fn default_pad_burst_prob() -> f64 {
    0.02
}

/// Obfuscation configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ObfuscationConfig {
    #[serde(default)]
    pub jc: i32,

    #[serde(default)]
    pub jmin: i32,

    #[serde(default)]
    pub jmax: i32,

    #[serde(default)]
    pub s1: i32,

    #[serde(default)]
    pub s2: i32,

    #[serde(default)]
    pub s3: i32,

    #[serde(default)]
    pub s4: i32,

    #[serde(default)]
    pub h1: String,

    #[serde(default)]
    pub h2: String,

    #[serde(default)]
    pub h3: String,

    #[serde(default)]
    pub h4: String,

    #[serde(default)]
    pub i1: String,

    #[serde(default)]
    pub i2: String,

    #[serde(default)]
    pub i3: String,

    #[serde(default)]
    pub i4: String,

    #[serde(default)]
    pub i5: String,

    #[serde(default)]
    pub server_public_key: String,

    /// Server private key (only for server-side, should not be in client profiles)
    #[serde(default)]
    pub server_private_key: String,

    #[serde(default = "default_true")]
    pub signature_validate: bool,

    #[serde(default)]
    #[serde(with = "serde_bool")]
    pub require_timestamp: Option<bool>,

    #[serde(default = "default_true")]
    pub encrypted_timestamp: bool,

    #[serde(default = "default_true")]
    pub require_encrypted_timestamp: bool,

    #[serde(default)]
    pub legacy_mode_enabled: bool,

    #[serde(default = "default_skew_soft_seconds")]
    pub skew_soft_seconds: i64,

    #[serde(default = "default_skew_hard_seconds")]
    pub skew_hard_seconds: i64,

    #[serde(default = "default_replay_window_seconds")]
    pub replay_window_seconds: usize,

    #[serde(default = "default_replay_cache_size")]
    pub replay_cache_size: usize,

    #[serde(default)]
    pub transport_replay: bool,

    #[serde(default)]
    pub transport_replay_limit: u64,

    #[serde(default = "default_rate_limit_pps")]
    pub rate_limit_pps: u64,

    #[serde(default = "default_rate_limit_burst")]
    pub rate_limit_burst: u64,
}

fn default_true() -> bool {
    true
}
fn default_skew_soft_seconds() -> i64 {
    15
}
fn default_skew_hard_seconds() -> i64 {
    30
}
fn default_replay_window_seconds() -> usize {
    30
}
fn default_replay_cache_size() -> usize {
    4096
}
fn default_rate_limit_pps() -> u64 {
    200
}
fn default_rate_limit_burst() -> u64 {
    500
}

impl ObfuscationConfig {
    pub fn to_obf_config(&self) -> ObfConfig {
        ObfConfig {
            jc: self.jc,
            jmin: self.jmin,
            jmax: self.jmax,
            s1: self.s1,
            s2: self.s2,
            s3: self.s3,
            s4: self.s4,
            h1: self.h1.clone(),
            h2: self.h2.clone(),
            h3: self.h3.clone(),
            h4: self.h4.clone(),
            i1: self.i1.clone(),
            i2: self.i2.clone(),
            i3: self.i3.clone(),
            i4: self.i4.clone(),
            i5: self.i5.clone(),
        }
    }

    pub fn transport_overhead_bytes(&self) -> usize {
        let transport_padding = self.s4.max(0) as usize;
        transport_padding.saturating_add(FRAME_HEADER_LEN)
    }
}

impl Profile {
    /// Load profile from a JSON file
    pub fn from_file<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = fs::read_to_string(path)?;
        let profile: Profile = serde_json::from_str(&content)?;
        Ok(profile)
    }

    /// Save profile to a JSON file
    pub fn to_file<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Get the obfuscation config
    pub fn obf_config(&self) -> ObfConfig {
        self.obfuscation.to_obf_config()
    }

    pub fn transport_padding_policy(&self) -> PaddingPolicy {
        match &self.transport_padding {
            Some(p) => PaddingPolicy {
                enabled: true,
                min: p.pad_min,
                max: p.pad_max,
                burst_min: p.pad_burst_min,
                burst_max: p.pad_burst_max,
                burst_prob: p.pad_burst_prob,
            },
            None => PaddingPolicy::disabled(),
        }
    }

    pub fn handshake_timeout_or_default(&self) -> Duration {
        self.handshake_timeout
            .unwrap_or_else(default_handshake_timeout)
    }

    pub fn preamble_delay_ms_or_default(&self) -> u64 {
        self.preamble_delay_ms
            .unwrap_or_else(default_preamble_delay_ms)
    }

    pub fn effective_kcp_max_packet_size(&self) -> usize {
        self.kcp
            .as_ref()
            .map(|k| k.max_packet_size)
            .unwrap_or_else(default_max_packet_size)
    }

    pub fn effective_kcp_max_payload(&self) -> usize {
        let max_payload = self
            .kcp
            .as_ref()
            .map(|k| k.effective_max_payload())
            .unwrap_or_else(|| KcpConfig::default().effective_max_payload());

        let max_packet_size = self.effective_kcp_max_packet_size();
        let obf_overhead = self.obfuscation.transport_overhead_bytes();
        let transport_budget = max_packet_size.saturating_sub(obf_overhead);

        max_payload.min(transport_budget)
    }

    /// Create a test profile with minimal configuration for integration testing.
    ///
    /// This uses the same profile structure as production but with simplified
    /// values suitable for fast, deterministic tests.
    pub fn test_profile() -> Self {
        Self {
            name: "test".to_string(),
            proxy_addr: "127.0.0.1:19000".to_string(),
            handshake_timeout: Some(default_handshake_timeout()),
            handshake_attempts: default_handshake_attempts(),
            preamble_delay_ms: Some(default_preamble_delay_ms()),
            preamble_jitter_ms: None,
            kcp: None,
            transport_padding: None,
            obfuscation: ObfuscationConfig {
                jc: 0,
                jmin: 0,
                jmax: 0,
                s1: 0,
                s2: 0,
                s3: 0,
                s4: 0,
                h1: "1".into(),
                h2: "2".into(),
                h3: "3".into(),
                h4: "4".into(),
                i1: "<d>".into(),
                // Empty strings match production serialization behavior;
                // jc/jmin/jmax = 0 means no obfuscation, so these fields are unused
                i2: String::new(),
                i3: String::new(),
                i4: String::new(),
                i5: String::new(),
                server_public_key: String::new(),
                server_private_key: String::new(),
                signature_validate: true,
                require_timestamp: None,
                encrypted_timestamp: false,
                require_encrypted_timestamp: true,
                legacy_mode_enabled: false,
                skew_soft_seconds: 15,
                skew_hard_seconds: 30,
                replay_window_seconds: 0,
                replay_cache_size: 0,
                transport_replay: false,
                transport_replay_limit: 0,
                rate_limit_pps: 0,
                rate_limit_burst: 0,
            },
        }
    }
}

// Serde duration modules - handles string formats like "5s", "20s", "2m"
pub mod serde_duration {
    use serde::{de::Visitor, Deserializer, Serialize, Serializer};
    use std::fmt;
    use std::time::Duration;

    // Module for optional Duration
    pub mod opt {
        use super::*;

        pub fn serialize<S>(opt: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match opt {
                Some(d) => serializer.serialize_some(&duration_to_string(d)),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_option(OptVisitor)
        }
    }

    // Module for required Duration
    pub mod default {
        use super::*;

        pub fn serialize<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&duration_to_string(value))
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_any(DurationVisitor)
        }
    }

    // Module for optional u64 milliseconds
    pub mod opt_u64_millis {
        use super::*;
        use serde::Deserialize;

        pub fn serialize<S>(opt: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            opt.serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
        where
            D: Deserializer<'de>,
        {
            Option::deserialize(deserializer)
        }
    }

    struct OptVisitor;

    impl<'de> Visitor<'de> for OptVisitor {
        type Value = Option<Duration>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a duration string (e.g., \"5s\", \"2m\") or null")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            Ok(Some(deserializer.deserialize_any(DurationVisitor)?))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(parse_duration_str(value).ok_or_else(|| {
                E::custom(format!("invalid duration string: {}", value))
            })?))
        }
    }

    struct DurationVisitor;

    impl<'de> Visitor<'de> for DurationVisitor {
        type Value = Duration;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a duration string (e.g., \"5s\", \"2m\") or number of seconds")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            parse_duration_str(value)
                .ok_or_else(|| E::custom(format!("invalid duration string: {}", value)))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Duration::from_secs(value))
        }
    }

    fn duration_to_string(d: &Duration) -> String {
        let secs = d.as_secs();
        if secs >= 60 {
            format!("{}m", secs / 60)
        } else {
            format!("{}s", secs)
        }
    }

    fn parse_duration_str(s: &str) -> Option<Duration> {
        let s = s.trim();
        if s.ends_with('s') {
            let num = s[..s.len() - 1].parse::<u64>().ok()?;
            Some(Duration::from_secs(num))
        } else if s.ends_with('m') {
            let num = s[..s.len() - 1].parse::<u64>().ok()?;
            Some(Duration::from_secs(num * 60))
        } else if s.ends_with('h') {
            let num = s[..s.len() - 1].parse::<u64>().ok()?;
            Some(Duration::from_secs(num * 3600))
        } else if s.ends_with("ms") {
            let num = s[..s.len() - 2].parse::<u64>().ok()?;
            Some(Duration::from_millis(num))
        } else {
            // Try as plain seconds
            let num = s.parse::<u64>().ok()?;
            Some(Duration::from_secs(num))
        }
    }
}

// Serde bool module for optional bool
pub mod serde_bool {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<bool>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(b) => serializer.serialize_some(b),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::deserialize(deserializer)
    }
}
pub mod cbor;
