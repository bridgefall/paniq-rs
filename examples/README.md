# paniq-rs Configuration Examples

This directory contains example configuration files for the paniq-rs transport implementation.

## Configuration Files

### 1. socks5d.json
Runtime configuration for the SOCKS5 daemon (`socks5d`). Controls listen address, worker counts, timeouts, and log levels.

### 2. proxy-server.json
Runtime configuration for the proxy server (`proxy-server`). Similar to the daemon config but tailored for server-side operations.

### 3. profile.json
Full profile configuration including server private key. Use this for the **proxy server** or testing.

**IMPORTANT:** Never distribute profiles containing `server_private_key` to clients!

### 4. profile-client.json
Client-only profile configuration. The `server_private_key` field is empty and should be omitted before distribution.

## Configuration Schema

### Daemon/Server Config Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_addr` | string | required | Listen address (e.g., `"127.0.0.1:1080"` for SOCKS5, `"0.0.0.0:9000"` for Proxy) |
| `log_level` | string | `"info"` | Log level: "debug", "info", "warn", "error" |
| `workers` | int | `8` | Number of worker threads for connection handling |
| `max_connections` | int | `128` | Maximum concurrent connections |
| `dial_timeout` | duration | `"5s"` | Upstream connection timeout |
| `accept_timeout` | duration | `"500ms"` | Accept timeout for incoming connections |
| `idle_timeout` | duration | `"2m"` | Idle timeout before closing connection |
| `metrics_interval` | duration | `"10s"` | Metrics collection interval |
| `username` | string? | `null` | SOCKS5 auth username (**socks5d only**) |
| `password` | string? | `null` | SOCKS5 auth password (**socks5d only**) |

### Profile Fields

#### Connection Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Profile name |
| `proxy_addr` | string | required | Proxy server address (host:port) |
| `handshake_timeout` | duration | `"5s"` | Handshake timeout |
| `handshake_attempts` | int | `3` | Preamble retry attempts |
| `preamble_delay_ms` | int | `5` | Delay between preamble packets (ms) |
| `preamble_jitter_ms` | int | `5` | Random jitter for preamble delay (ms) |

#### QUIC/KCP Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_packet_size` | int | `1350` | Total envelope datagram size |
| `max_payload` | int | `1200` | Max inner QUIC payload size |
| `keepalive` | duration | `"20s"` | QUIC keepalive period |
| `idle_timeout` | duration | `"2m"` | QUIC idle timeout |
| `max_streams` | int | `256` | Max concurrent QUIC streams |
| `send_window` | int? | `null` | KCP send window size (optional) |
| `recv_window` | int? | `null` | KCP receive window size (optional) |
| `target_bps` | int? | `null` | Target throughput for BDP calculation (optional) |
| `rtt_ms` | int? | `null` | RTT estimate for BDP calculation (optional) |
| `max_snd_queue` | int? | `null` | Max KCP send queue size (optional) |

#### Transport Padding

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `pad_min` | int | `16` | Minimum padding bytes per datagram |
| `pad_max` | int | `96` | Maximum padding bytes per datagram |
| `pad_burst_min` | int | `96` | Burst padding minimum |
| `pad_burst_max` | int | `104` | Burst padding maximum |
| `pad_burst_prob` | float | `0.02` | Burst probability [0.0-1.0] |

#### Obfuscation Settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `jc` | int | `0` | Junk datagram count |
| `jmin` | int | `0` | Minimum junk datagram size |
| `jmax` | int | `0` | Maximum junk datagram size |
| `s1`..`s4` | int | `0` | Padding sizes for packet types |
| `h1`..`h4` | string | `""` | Header ranges ("x-y" or "x") |
| `i1`..`i5` | string | `""` | Signature packet specs (e.g., "<t>" for timestamp) |
| `server_public_key` | string | `""` | Base64 server public key |
| `server_private_key` | string | `""` | Base64 server private key (**server only!**) |
| `signature_validate` | bool | `true` | Validate signature contents |
| `require_timestamp` | bool? | `true` | Require `<t>` in signatures |
| `encrypted_timestamp` | bool | `true` | Send encrypted timestamp |
| `require_encrypted_timestamp` | bool | `true` | Require encrypted timestamp |
| `legacy_mode_enabled` | bool | `false` | Allow signatures without `<t>` |
| `skew_soft_seconds` | int | `15` | Soft clock skew threshold |
| `skew_hard_seconds` | int | `30` | Hard clock skew threshold |
| `replay_window_seconds` | int | `30` | Replay window duration |
| `replay_cache_size` | int | `4096` | Replay cache capacity |
| `transport_replay` | bool | `false` | Enable RFC6479 replay filter |
| `transport_replay_limit` | int | `0` | Max counter value for replay filter |
| `rate_limit_pps` | int | `200` | Per-IP handshake rate limit |
| `rate_limit_burst` | int | `500` | Per-IP burst size |

## Duration Format

Durations are specified as strings with the following format:
- `"500ms"` - milliseconds
- `"5s"` - seconds
- `"2m"` - minutes
- `"0s"` - zero/disabled

## Transport Payload Budget

The maximum QUIC payload size is calculated as:
```
max_packet_size - (s4 + 4 + 2 [+8 if transport_replay])
```

For the default values:
```
1350 - (37 + 4 + 2) = 1307 bytes
```

With transport replay enabled:
```
1350 - (37 + 4 + 2 + 8) = 1299 bytes
```

## Profile Distribution

When distributing client profiles:
1. **Remove `server_private_key`** - This should never be shared with clients
2. Keep all other settings intact
3. Use the `.client.json` extension as a convention

## Example Usage

### Mobile App (Android/iOS)

```kotlin
// Load daemon config
val config = uniffi.paniq.loadDaemonConfig(configPath)

// Load profile
val profile = Profile.from_file(profilePath)

// Start daemon
val startConfig = DaemonStartConfig(
    profile_path = profilePath,
    listen_addr = "127.0.0.1:1080",
    proxy_addr_override = null
)
daemon.start(startConfig)
```

### Desktop

```rust
use paniq::config::{FileConfig, Socks5FileConfig};

// Load socks5d config
let config = Socks5FileConfig::load_from_file("socks5d.json")?;
```

## Security Notes

1. **Key Generation**: Always generate fresh keypairs for production use
2. **Key Storage**: Store `server_private_key` securely on the server only
3. **Distribution**: Never distribute profiles containing private keys
4. **Obfuscation**: The example values are for testing; use randomized values in production
5. **MTU**: Adjust `max_packet_size` based on your network MTU (typically 1420 for internet)
