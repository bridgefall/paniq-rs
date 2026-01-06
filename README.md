# paniq-rs

`paniq-rs` is the high-performance Rust implementation of the **Paniq** transport protocol, a core component of the **Bridgefall** censorship-resilient connectivity substrate. It provides a robust, obfuscated, and adaptable networking layer designed to survive in high-censorship environments by mimicking innocuous UDP traffic.

## Overview

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
*   **`envelope`**: Logic for preamble sequences and packet framing.
*   **`obf`**: Core obfuscation layer (crypto, randomized padding, header ranges).
*   **`kcp`**: Reliable UDP transport session management.
*   **`socks5`**: Protocol handler for local SOCKS5 proxying.
*   **`profile`**: JSON-based configuration system defining keys, endpoints, and obfuscation parameters.
*   **`runtime`**: High-level orchestration integrating everything into the Tokio async runtime.

### Binaries (`bin/`)
*   **`socks5d`**: The client entry point.
*   **`proxy-server`**: The server entry point.
*   **`gen_test_cert`**: Utility for generating credentials and test profiles.

## Getting Started

### Prerequisites
*   Rust (1.75+ recommended)
*   `make` (for convenience commands)

### Building
```bash
# Build release binaries (recommended for performance)
make build-release

# Install to cargo bin directory
make install
```

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
