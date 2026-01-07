//! Configuration management for paniq components.
//!
//! This module provides JSON-based configuration for the SOCKS5 daemon and proxy server,
//! supporting runtime settings like log level, worker counts, timeouts, etc.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

/// Error types for configuration operations.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid log level: {0}")]
    InvalidLogLevel(String),

    #[error("Invalid timeout format: {0}")]
    InvalidTimeout(String),

    #[error("Workers must be > 0")]
    InvalidWorkers,

    #[error("Max connections must be > 0")]
    InvalidMaxConnections,
}

/// Helper trait for loading/saving configuration files.
pub trait FileConfig: Serialize + for<'de> Deserialize<'de> + Default + Sized {
    /// Load configuration from a JSON file.
    ///
    /// If the file doesn't exist, returns default config.
    /// If the file exists but is invalid, returns an error.
    fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Save configuration to a JSON file.
    fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let content = serde_json::to_string_pretty(self)?;
        // Atomic write: write to temp file first, then rename
        let temp_path = path.as_ref().with_extension("tmp");
        std::fs::write(&temp_path, content)?;
        std::fs::rename(&temp_path, path)?;
        Ok(())
    }

    /// Validate configuration values.
    fn validate(&self) -> Result<(), ConfigError>;

    /// Get the log level as a tracing::Level.
    fn log_level(&self) -> &str;

    /// Get tracing::Level from log_level string.
    fn log_level_as_tracing(&self) -> tracing::Level {
        match self.log_level().to_lowercase().as_str() {
            "debug" => tracing::Level::DEBUG,
            "info" => tracing::Level::INFO,
            "warn" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            _ => tracing::Level::INFO,
        }
    }
}

/// SOCKS5 daemon configuration loaded from JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Socks5FileConfig {
    /// Listen address (e.g., "127.0.0.1:1080")
    pub listen_addr: String,

    /// Optional username for SOCKS5 authentication
    pub username: Option<String>,

    /// Optional password for SOCKS5 authentication
    pub password: Option<String>,

    /// Number of worker threads for connection handling
    pub workers: usize,

    /// Maximum concurrent connections
    pub max_connections: usize,

    /// Dial timeout (e.g., "5s", "500ms")
    #[serde(with = "duration_serde")]
    pub dial_timeout: Duration,

    /// Accept timeout (e.g., "500ms")
    #[serde(with = "duration_serde")]
    pub accept_timeout: Duration,

    /// Idle timeout before closing connection (e.g., "2m")
    #[serde(with = "duration_serde")]
    pub idle_timeout: Duration,

    /// Metrics collection interval (e.g., "10s")
    #[serde(with = "duration_serde")]
    pub metrics_interval: Duration,

    /// Log level: "debug", "info", "warn", "error"
    pub log_level: String,
}

impl Default for Socks5FileConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:1080".to_string(),
            username: None,
            password: None,
            workers: 8,
            max_connections: 128,
            dial_timeout: Duration::from_secs(5),
            accept_timeout: Duration::from_millis(500),
            idle_timeout: Duration::from_secs(120),
            metrics_interval: Duration::from_secs(10),
            log_level: "info".to_string(),
        }
    }
}

impl FileConfig for Socks5FileConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_common(
            self.workers,
            self.max_connections,
            &self.log_level,
            self.dial_timeout,
            self.accept_timeout,
        )
    }

    fn log_level(&self) -> &str {
        &self.log_level
    }
}

/// Proxy server configuration loaded from JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyFileConfig {
    /// Listen address (e.g., "0.0.0.0:9000")
    pub listen_addr: String,

    /// Number of worker threads for connection handling
    pub workers: usize,

    /// Maximum concurrent connections
    pub max_connections: usize,

    /// Dial timeout (e.g., "5s", "500ms")
    #[serde(with = "duration_serde")]
    pub dial_timeout: Duration,

    /// Accept timeout (e.g., "500ms")
    #[serde(with = "duration_serde")]
    pub accept_timeout: Duration,

    /// Idle timeout before closing connection (e.g., "2m")
    #[serde(with = "duration_serde")]
    pub idle_timeout: Duration,

    /// Metrics collection interval (e.g., "10s")
    #[serde(with = "duration_serde")]
    pub metrics_interval: Duration,

    /// Log level: "debug", "info", "warn", "error"
    pub log_level: String,
}

impl Default for ProxyFileConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:9000".to_string(),
            workers: 8,
            max_connections: 128,
            dial_timeout: Duration::from_secs(5),
            accept_timeout: Duration::from_millis(500),
            idle_timeout: Duration::from_secs(120),
            metrics_interval: Duration::from_secs(10),
            log_level: "info".to_string(),
        }
    }
}

impl FileConfig for ProxyFileConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_common(
            self.workers,
            self.max_connections,
            &self.log_level,
            self.dial_timeout,
            self.accept_timeout,
        )
    }

    fn log_level(&self) -> &str {
        &self.log_level
    }
}

fn validate_common(
    workers: usize,
    max_connections: usize,
    log_level: &str,
    dial_timeout: Duration,
    accept_timeout: Duration,
) -> Result<(), ConfigError> {
    if workers == 0 {
        return Err(ConfigError::InvalidWorkers);
    }
    if max_connections == 0 {
        return Err(ConfigError::InvalidMaxConnections);
    }

    // Validate log level
    match log_level.to_lowercase().as_str() {
        "debug" | "info" | "warn" | "error" => {}
        _ => return Err(ConfigError::InvalidLogLevel(log_level.to_string())),
    }

    // Validate timeouts are reasonable
    if dial_timeout.as_secs() > 300 {
        return Err(ConfigError::InvalidTimeout(
            "dial_timeout too long (max 300s)".to_string(),
        ));
    }
    if accept_timeout.as_secs() > 60 {
        return Err(ConfigError::InvalidTimeout(
            "accept_timeout too long (max 60s)".to_string(),
        ));
    }

    Ok(())
}

/// Module for Duration serialization/deserialization.
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let secs = duration.as_secs();
        let millis = duration.subsec_millis();
        if secs >= 60 && millis == 0 {
            serializer.serialize_str(&format!("{}s", secs))
        } else if secs >= 1 {
            serializer.serialize_str(&format!("{}.{:03}s", secs, millis))
        } else if millis >= 1 {
            serializer.serialize_str(&format!("{}ms", millis))
        } else {
            serializer.serialize_str("0s")
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_duration(&s).map_err(serde::de::Error::custom)
    }

    fn parse_duration(s: &str) -> Result<Duration, String> {
        let s = s.trim().to_lowercase();
        if s.ends_with("ms") {
            let num = s[..s.len() - 2].trim();
            let millis: u64 = num
                .parse()
                .map_err(|_| format!("invalid milliseconds: {}", num))?;
            return Ok(Duration::from_millis(millis));
        } else if s.ends_with('s') {
            let num = s[..s.len() - 1].trim();
            if num.contains('.') {
                let parts: Vec<&str> = num.split('.').collect();
                if parts.len() == 2 {
                    let secs: u64 = parts[0]
                        .parse()
                        .map_err(|_| format!("invalid seconds: {}", parts[0]))?;
                    let millis_str = format!("{:0<3}", &parts[1][..3.min(parts[1].len())]);
                    let millis: u32 = millis_str
                        .parse()
                        .map_err(|_| format!("invalid milliseconds: {}", millis_str))?;
                    return Ok(Duration::new(secs, millis * 1_000_000));
                }
            }
            let secs: u64 = num
                .parse()
                .map_err(|_| format!("invalid duration: {}", s))?;
            return Ok(Duration::from_secs(secs));
        } else if s.ends_with('m') {
            let num = s[..s.len() - 1].trim();
            let mins: u64 = num
                .parse()
                .map_err(|_| format!("invalid minutes: {}", num))?;
            return Ok(Duration::from_secs(mins * 60));
        }
        Err(format!("unknown duration format: {}", s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_configs() {
        let socks_config = Socks5FileConfig::default();
        assert_eq!(socks_config.log_level, "info");
        assert_eq!(socks_config.workers, 8);
        assert_eq!(socks_config.listen_addr, "127.0.0.1:1080");

        let proxy_config = ProxyFileConfig::default();
        assert_eq!(proxy_config.log_level, "info");
        assert_eq!(proxy_config.workers, 8);
        assert_eq!(proxy_config.listen_addr, "0.0.0.0:9000");
    }

    #[test]
    fn test_serialize_deserialize() {
        let config = Socks5FileConfig {
            log_level: "debug".to_string(),
            workers: 4,
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let restored: Socks5FileConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.log_level, "debug");
        assert_eq!(restored.workers, 4);
    }

    #[test]
    fn test_duration_parsing() {
        let json = r#"{"dial_timeout": "5s", "accept_timeout": "500ms"}"#;
        let config: Socks5FileConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.dial_timeout, Duration::from_secs(5));
        assert_eq!(config.accept_timeout, Duration::from_millis(500));
    }

    #[test]
    fn test_validate() {
        let config = Socks5FileConfig {
            workers: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = Socks5FileConfig {
            log_level: "invalid".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = Socks5FileConfig::default();
        assert!(config.validate().is_ok());
    }
}
