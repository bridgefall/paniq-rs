# paniq-rs

[![CI](https://github.com/bridgefall/paniq-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/bridgefall/paniq-rs/actions/workflows/ci.yml)
[![Release](https://github.com/bridgefall/paniq-rs/actions/workflows/release.yml/badge.svg)](https://github.com/bridgefall/paniq-rs/actions/workflows/release.yml)

`paniq-rs` is the high-performance Rust implementation of the **Paniq** transport protocol, a core component of the **Bridgefall** censorship-resilient connectivity substrate. It provides a robust, obfuscated, and adaptable networking layer designed to survive in high-censorship environments by mimicking innocuous UDP traffic.

## Project Overview

`paniq-rs` is a dual-purpose project:
1.  **A Standalone Application Suite**: Ready-to-use binaries (`socks5d`, `proxy-server`) for secure SOCKS5 tunneling.
2.  **A Transport SDK**: A flexible Rust library allowing developers to embed the Paniq transport protocol directly into their own applications, bypassing SOCKS5.

## Protocol Design

Unlike standard VPN protocols, Paniq is designed from the ground up to evade Deep Packet Inspection (DPI) and protocol fingerprinting. It achieves this through a multi-layered approach:
1.  **Preamble Noise**: Handshakes are preceded by configurable amounts of cryptographically random junk and custom signatures.
2.  **Header Obfuscation**: All framed packets use randomized headers within user-defined ranges to prevent fixed-offset fingerprinting.
3.  **Variable Padding**: Both handshake and transport packets are padded to randomized lengths, destroying packet-size-based signatures.
4.  **Reliable UDP**: Leverages **KCP** to provide low-latency, reliable delivery over unstable or reshaped UDP links.

## Key Features

*   **Transport Protocols**:
    *   **Obfuscated KCP (Reliable UDP)**: High-performance reliable UDP with replay protection and traffic shaping.
*   **Security & Crypto**:
    *   **X25519** ECDH for forward-secret key exchange.
    *   **XChaCha20-Poly1305** for authenticated encryption of all traffic.
    *   **Encrypted Timestamps**: Prevents replay attacks and active probing during the handshake.
    *   **MAC1 Verification**: Optional pre-handshake authentication to reject unauthorized probes early.
*   **Components**:
    *   `paniq`: The core library crate exposing the transport SDK.
    *   `socks5d`: A local SOCKS5 daemon bridging standard application traffic into the Paniq network.
    *   `proxy-server`: A high-throughput entry node that unwraps transport layers and forwards traffic to upstreams.

## Protocol Architecture

The Paniq protocol operates in two distinct phases:

### 1. Preamble Phase (Unframed)
Before any real data is sent, the client transmits a sequence of unframed packets that the server expects in strict order:
*   **Junk Packets**: `Jc` packets of random length `[Jmin, Jmax]`.
*   **Signatures**: Up to 5 signature chains (`I1..I5`) featuring fixed bytes, timestamps, or random data to satisfy simple DPI patterns.

### 2. Transport Phase (Framed)
Once the preamble is complete, communication switches to a framed format:
`| padding (S*) | header (uint32 LE) | encrypted payload |`

*   **Handshake**: A 1-RTT exchange (`MessageInitiation` -> `MessageResponse`) establishes the encrypted tunnel.
*   **Payload**: Multiple application streams are multiplexed over a single authenticated KCP session.

For more technical details, see the [Protocol Specification](docs/protocol.md).

## Project Structure

The project is organized as a Cargo workspace:

### Library Modules (`src/`)
*   **`client`**: The primary SDK entry point (`PaniqClient`) for managing connections and streams.
*   **`io`**: Async I/O primitives (`PaniqStream`) implementing standard `AsyncRead`/`AsyncWrite`.
*   **`envelope`**: Logic for preamble sequences and packet framing.
*   **`obf`**: Core obfuscation layer (crypto, randomized padding, header ranges).
*   **`kcp`**: Reliable UDP transport session management.
*   **`socks5`**: Protocol handler for local SOCKS5 proxying.
*   **`control`**: IPC module for daemon observability (Ping/Stats) via Unix Domain Sockets.
*   **`profile`**: JSON-based configuration system defining keys, endpoints, and obfuscation parameters.
*   **`runtime`**: High-level orchestration integrating everything into the Tokio async runtime.

### Binaries (`bin/`)
*   **`socks5d`**: The client entry point.
*   **`proxy-server`**: The server entry point.
*   **`paniq-ctl`**: CLI utility for monitoring the `socks5d` daemon via its control socket.
*   **`gen_test_cert`**: Utility for generating credentials and test profiles.

## Control Plane & Observability

`socks5d` supports an optional observability-only control plane via a Unix Domain Socket (UDS). This is used by external managers (e.g., systemd, Android Services, or custom CLI tools) to monitor the daemon's health and fetch real-time metrics without interrupting the transport flow.

- **Enable the Control Socket**: Pass `--control-socket <path>` to `socks5d`.
- **Query with `paniq-ctl`**:
  ```bash
  # Check if daemon is responsive
  paniq-ctl --socket /tmp/paniq_control.sock ping

  # Fetch real-time connection stats and throughput
  paniq-ctl --socket /tmp/paniq_control.sock stats
  ```

The control API uses a simple JSON-based request/response protocol over the UDS, making it easy to integrate with mobile apps or other monitoring agents.

## SDK Usage

Developers can use `paniq-rs` to build custom applications that benefit from its obfuscation and reliability features without running a separate proxy daemon.

Add to `Cargo.toml`:
```toml
[dependencies]
paniq = { path = ".", features = ["kcp"] }
```

### Example: Simple Client

```rust
use paniq::client::PaniqClient;

// Configure and connect
let client = PaniqClient::new(server_addr, obf_config, client_config);

// Open a reliable, obfuscated stream
let mut stream = client.open_stream().await?;
stream.write_all(b"Hello").await?;
```

For a complete working example of a custom client and server, see [`examples/echo.rs`](examples/echo.rs).

## Feature Flags

The crate exposes the following features to minimize compile-time deps:

*   **`kcp`**: Enables the core `PaniqClient`, `PaniqStream`, and KCP transport logic. Required for SDK usage.
*   **`socks5`**: Enables the SOCKS5 protocol handling logic. Required for `socks5d`.
*   **`mobile`**: Enables UniFFI bindings and FFI-exported functions for mobile integration (implies `kcp` and `socks5`).

## Mobile & FFI

`paniq-rs` provides high-performance FFI bindings for mobile applications (Android/iOS) via **UniFFI**. This allows mobile apps to leverage the core Paniq logic for profile parsing and daemon management.

- **Profile Decoding**: Easily decode compact, Base64-encoded CBOR profiles (e.g., from `pnq://` deep links) into JSON for UI display or processing.
- **FFI Usage**: The bindings are exposed when compiling with the `mobile` feature.

### Example: Decoding a CBOR Profile via FFI
```rust
use paniq::ffi::decode_profile_to_json;

// Decode a Base64-wrapped CBOR profile string
let json = decode_profile_to_json(b64_cbor_string)?;
```
For a complete demonstration, see [`examples/ffi_usage.rs`](examples/ffi_usage.rs).

## Installation

### Quick Install (Recommended)

Install the latest version of paniq-rs on Debian-based systems with a single command:

```bash
curl -fsSL https://raw.githubusercontent.com/bridgefall/paniq-rs/main/scripts/paniq-rs-install.sh | sudo bash
```

**What it does:**
- ✅ Detects and installs the latest release automatically
- ✅ Downloads binaries from GitHub releases
- ✅ Verifies checksums for security
- ✅ Installs to `/usr/local/bin`
- ✅ Generates server profile and client connection string
- ✅ Creates and starts systemd service
- ✅ Sets up configuration at `/etc/bridgefall-rs`

**Install a specific version:**
```bash
export PANIQ_VERSION=v20260108-abc1234
curl -fsSL https://raw.githubusercontent.com/bridgefall/paniq-rs/main/scripts/paniq-rs-install.sh | sudo bash
```

**Update existing installation (binaries only):**
```bash
curl -fsSL https://raw.githubusercontent.com/bridgefall/paniq-rs/main/scripts/paniq-rs-install.sh | sudo bash -s -- --update
```

The `--update` flag will:
- ✅ Update binaries to the latest version
- ✅ Restart the service if it's running
- ⏭️ Skip configuration regeneration (preserves your existing setup)
- ⏭️ Skip profile and systemd unit creation

### Manual Installation

If you prefer to install manually or build from source:

#### From Release Binaries

```bash
# Download the latest release
wget https://github.com/bridgefall/paniq-rs/releases/latest/download/paniq-rs-VERSION-linux-amd64.tar.gz
tar -xzf paniq-rs-VERSION-linux-amd64.tar.gz
cd paniq-rs-VERSION-linux-amd64

# Run the installer
sudo bash install-debian.sh

# Or update an existing installation (binaries only)
sudo bash install-debian.sh --update
```

#### Build from Source

**Prerequisites:**
*   Rust 1.75+ (recommended: latest stable)
*   `make` (for convenience commands)

```bash
# Clone the repository
git clone https://github.com/bridgefall/paniq-rs.git
cd paniq-rs

# Build release binaries (recommended for performance)
make build-release

# Install to cargo bin directory
make install
```

### Post-Installation

After installation, the service will be running automatically. You can manage it with:

```bash
# Check service status
sudo systemctl status paniq-rs-proxy

# View logs
sudo journalctl -u paniq-rs-proxy -f

# Restart service
sudo systemctl restart paniq-rs-proxy

# Stop service
sudo systemctl stop paniq-rs-proxy
```

**Get client connection string:**
```bash
cat /etc/bridgefall-rs/client.txt
```

This string can be shared with clients to connect to your proxy server.

### Uninstall

```bash
sudo systemctl stop paniq-rs-proxy
sudo systemctl disable paniq-rs-proxy
sudo rm /usr/local/bin/paniq-rs-*
sudo rm /etc/systemd/system/paniq-rs-proxy.service
sudo rm -rf /etc/bridgefall-rs
sudo systemctl daemon-reload
```

## Getting Started

### Running
Both components require a **Profile** (`.json`). You can generate a test set using the included tools:

**1. Run the Proxy Server:**
```bash
./target/release/proxy-server --profile config/server-profile.json
```

**2. Run the SOCKS5 Daemon:**
```bash
./target/release/socks5d --profile config/client-profile.json
```

## Configuration (Profiles)

Paniq is highly configurable via JSON profiles. Key fields include:
*   `proxy_addr`: The remote endpoint for `socks5d`.
*   `kcp`: Tuning for `keepalive`, `idle_timeout`, and window sizes (`send_window`, `recv_window`).
*   `obfuscation`: Preamble counts (`jc`), header ranges (`h1..h4`), and signature chains (`i1..i5`).
*   `transport_padding`: Dynamic padding policy for the data phase.

See [Configuration Documentation](../paniq/docs/config.md) for a full field reference.

## Testing & Validation

The project maintains a rigorous testing suite to ensure stability across releases:
*   **Unit Tests**: `make test-unit`
*   **Integration Tests**: `make test-integration` (KCP roundtrips over obfuscated sockets).
*   **Soak Tests**: `make test-soak SOAK_SECS=60` (High-load stress tests).
*   **Go Parity**: `make test-parity` (Ensures wire-level compatibility with the reference Go implementation).

## Development Status

`paniq-rs` is reaching maturity and is currently used as the primary transport for the Bridgefall ecosystem.
