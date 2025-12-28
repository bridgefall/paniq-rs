# paniq-rs Implementation Plan

## Overview

This document outlines a plan to implement `paniq-rs`, a Rust implementation of the paniq transport protocol. The Go implementation in `_reference/paniq/` provides AWG (AmneziaWG) parity obfuscation over UDP, with an envelope layer handling handshakes, replay protection, and transport payload framing.

## Architecture Summary

```
+-------------------+     +-------------------+     +-------------------+
|   SOCKS5 Daemon   |     |   Proxy Server    |     |  Obfuscation Lib  |
|  (TCP -> QUIC)    |<--->|  (QUIC -> TCP)    |<--->|    (paniq-rs)      |
+-------------------+     +-------------------+     +-------------------+
         |                          |                          |
         v                          v                          v
+-----------------------------------------------------------------------+
|                     QUIC Transport (quinn)                           |
+-----------------------------------------------------------------------+
         |                          |                          |
         v                          v                          v
+-----------------------------------------------------------------------+
|              Envelope Layer (handshake, framing)                      |
+-----------------------------------------------------------------------+
         |                          |                          |
         v                          v                          v
+-----------------------------------------------------------------------+
|              Obfuscation Layer (AWG parity)                          |
|  - Magic headers (H1-H4)                                              |
|  - Padding (S1-S4)                                                    |
|  - Junk datagrams (Jc, Jmin, Jmax)                                   |
|  - Signature chains (I1-I5)                                          |
+-----------------------------------------------------------------------+
         |                          |                          |
         v                          v                          v
+-----------------------------------------------------------------------+
|                        Raw UDP Socket                                |
+-----------------------------------------------------------------------+
```

## Project Structure

```
paniq-rs/
├── Cargo.toml
├── README.md
├── LICENSE
├── src/
│   ├── lib.rs                 # Public exports
│   ├── config.rs              # Configuration structs
│   ├── obf/
│   │   ├── mod.rs             # Obfuscation module
│   │   ├── types.rs           # Obf interface and Chain
│   │   ├── bytes.rs           # <b> hex bytes obfuscator
│   │   ├── timestamp.rs       # <t> timestamp obfuscator
│   │   ├── rand.rs            # <r> random bytes obfuscator
│   │   ├── rand_chars.rs      # <rc> random alpha obfuscator
│   │   ├── rand_digits.rs     # <rd> random digit obfuscator
│   │   ├── data.rs            # <d> data passthrough
│   │   ├── data_string.rs     # <ds> base64 encoding
│   │   ├── data_size.rs       # <dz> size prefix
│   │   ├── header.rs          # Magic header (H1-H4)
│   │   ├── chain.rs           # Obfuscation chain
│   │   ├── chains.rs          # ChainSet (I1-I5)
│   │   ├── headers.rs         # HeaderSet (H1-H4)
│   │   └── framer.rs          # Datagram framer
│   ├── envelope/
│   │   ├── mod.rs
│   │   ├── client.rs          # Client handshake
│   │   ├── server.rs          # Server connection
│   │   ├── transport.rs       # Transport payload
│   │   ├── replay.rs          # Replay cache
│   │   ├── mac1.rs            # MAC1 signature
│   │   ├── enc_timestamp.rs   # Encrypted timestamp
│   │   └── padding.rs         # Padding policy
│   ├── quic/
│   │   ├── mod.rs
│   │   ├── client.rs
│   │   └── server.rs
│   └── socks5/
│       ├── mod.rs
│       └── server.rs
├── examples/
│   ├── socks5d.rs
│   └── proxy-server.rs
└── tests/
    └── parity_test.rs         # Golden vector tests vs Go
```

## Phase 1: Core Obfuscation Layer

### 1.1 Types and Config (`obf/types.rs`, `config.rs`)

**Goal**: Define core data structures

- `ObfConfig`: Configuration parameters
  - `jc: u32` - Junk count
  - `jmin: u32` - Junk min size
  - `jmax: u32` - Junk max size
  - `s1, s2, s3, s4: u32` - Padding sizes
  - `h1, h2, h3, h4: String` - Header specs
  - `i1, i2, i3, i4, i5: String` - Chain specs
  - `signature_validate: bool` - Require MAC1 validation
  - `require_timestamp: bool` - Require timestamp in handshake
  - `encrypted_timestamp: bool` - Enable encrypted timestamp
  - `require_encrypted_timestamp: bool` - Require encrypted timestamp
  - `legacy_mode_enabled: bool` - Allow legacy handshake flows
  - `legacy_mode_sunset: Option<String>` - Sunset date for legacy mode
  - `legacy_mode_max_days: u32` - Max days for legacy acceptance
  - `skew_soft_seconds: i64` - Soft clock skew limit
  - `skew_hard_seconds: i64` - Hard clock skew limit
  - `replay_window_seconds: u64` - Replay window size
  - `replay_cache_size: usize` - Replay cache size
  - `transport_replay: bool` - Enable transport replay checks
  - `transport_replay_limit: u64` - Max replay counter delta
  - `rate_limit_pps: u32` - Packets per second
  - `rate_limit_burst: u32` - Rate limit burst
  - `pad_min, pad_max: Option<usize>` - Transport padding range
  - `pad_burst_min, pad_burst_max: Option<usize>` - Burst padding range
  - `pad_burst_prob: Option<f64>` - Burst padding probability

- `Obf trait`:
  ```rust
  trait Obf {
      fn obfuscate(&self, dst: &mut [u8], src: &[u8]);
      fn deobfuscate(&self, dst: &mut [u8], src: &[u8]) -> bool;
      fn obfuscated_len(&self, src_len: usize) -> usize;
      fn deobfuscated_len(&self, src_len: usize) -> usize;
  }
  ```

- `Chain` struct wrapping a vector of `Box<dyn Obf>`

### 1.2 Obfuscator Implementations (`obf/*.rs`)

Each obfuscator implements the `Obf` trait:

| Spec | File | Description |
|------|------|-------------|
| `<b hex>` | bytes.rs | Fixed hex bytes |
| `<t>` | timestamp.rs | 4-byte Unix timestamp |
| `<r N>` | rand.rs | N random bytes |
| `<rc N>` | rand_chars.rs | N random ASCII letters |
| `<rd N>` | rand_digits.rs | N random digits |
| `<d>` | data.rs | Passthrough |
| `<ds>` | data_string.rs | Base64 encode |
| `<dz N>` | data_size.rs | N-byte size prefix |

### 1.3 Magic Headers (`obf/header.rs`, `obf/headers.rs`)

- `MagicHeader`: Single header range (e.g., "1-3")
  - `start: u32`, `end: u32`
  - `validate(val: u32) -> bool`
  - `generate() -> u32` (random in range)

- `HeaderSet`: H1-H4 headers for message types

### 1.4 Framer (`obf/framer.rs`)

- `Framer` struct:
  - `cfg: ObfConfig`
  - `headers: HeaderSet`
  - `chains: ChainSet`

- Message types:
  ```rust
  enum MessageType {
      Initiation = 1,
      Response = 2,
      CookieReply = 3,
      Transport = 4,
  }
  ```

- Methods:
  - `encode_frame(msg_type: MessageType, payload: &[u8]) -> Result<Vec<u8>>`
  - `decode_frame(datagram: &[u8]) -> Result<(MessageType, Vec<u8>)>`
  - `junk_datagrams() -> Result<Vec<Vec<u8>>>`
  - `signature_datagrams() -> Result<Vec<Vec<u8>>>`

### 1.5 Dependencies

```toml
[dependencies]
rand = "0.8"
getrandom = "0.2"  # For WASM support
thiserror = "1.0"
hex = "0.4"
base64 = "0.21"
```

### 1.6 Testability Contract

- Obfuscation components must be runnable without QUIC or SOCKS5
- Each obfuscator, chain parser, and framer unit can be tested with pure inputs
- Provide deterministic RNG seeding for all randomized outputs

## Phase 2: Envelope Layer

### 2.1 Transport Payload (`envelope/transport.rs`)

- Transport payload format:
  ```
  [counter? 8] [len 2] [payload] [padding?]
  ```

- `build_transport_payload()`:
  - Optional 8-byte counter (replay protection)
  - 2-byte length prefix
  - Payload data
  - Random padding

- `decode_transport_payload()`:
  - Validate and extract payload
  - Counter validation callback

### 2.2 Padding Policy (`envelope/padding.rs`)

```rust
struct PaddingPolicy {
    enabled: bool,
    min: usize,
    max: usize,
    burst_min: usize,
    burst_max: usize,
    burst_prob: f64,
}
```

- Burst mode with probability
- Clamping to max payload size

### 2.3 Replay Cache (`envelope/replay.rs`)

- Time-based sliding window cache
- Hash key: timestamp + payload + mac1
- Eviction and reset on clock jump

### 2.4 MAC1 Signature (`envelope/mac1.rs`)

- Blake2s-MAC1 computation
- 16-byte signature
- Zero-shadow verification

### 2.5 Encrypted Timestamp (`envelope/enc_timestamp.rs`)

- TAI64N timestamp format
- X25519 key exchange
- ChaCha20Poly1305 encryption

### 2.6 Client Handshake (`envelope/client.rs`)

- `client_handshake()` function:
  1. Send junk datagrams (with pacing)
  2. Send signature datagrams (with pacing)
  3. Send initiation frame
  4. Wait for response or cookie reply
  5. If cookie reply received, resend initiation with cookie and await response

- `ClientConn`: Wrapper for `PacketConn` post-handshake

### 2.7 Server Connection (`envelope/server.rs`)

- `ServerConn`: Server-side packet wrapper
- `peer_state`: Per-connection state
  - Junk remaining
  - Signature index
  - Timestamp validation
  - Replay filter

- `handle_preamble()`: Validate handshake flow

### 2.8 Dependencies

```toml
[dependencies]
blake2 = "0.10"
chacha20poly1305 = "0.10"
x25519-dalek = "2.0"
chrono = "0.4"  # or tai64n crate
```

### 2.9 Testability Contract

- Envelope layer must be testable with an in-memory packet transport
- Handshake flows must run without QUIC or SOCKS5
- Replay, MAC1, and timestamp checks must be unit-testable in isolation

## Phase 3: QUIC Integration

### 3.1 QUIC Client (`quic/client.rs`)

- Using `quinn` crate with a wrapped UDP socket
- `connect()` function:
  - Perform envelope handshake over a `PacketConn` wrapper
  - Wrap the UDP socket so all outgoing datagrams are framed by the obfuscation layer
  - Establish QUIC connection
  - Return quinn `Connection`

### 3.2 QUIC Server (`quic/server.rs`)

- `listen()` function:
  - Wrap UDP socket with `ServerConn` and envelope validator
  - Expose a `quinn::Endpoint` backed by the wrapped socket
  - Accept QUIC connections
  - Return streams

### 3.3 Dependencies

```toml
[dependencies]
quinn = "0.10"
rustls = "0.21"
```

### 3.4 Testability Contract

- QUIC layer must accept a mocked/wrapped UDP socket for deterministic tests
- Connection setup must be testable without SOCKS5

## Phase 4: SOCKS5 Daemon

### 4.1 SOCKS5 Server (`socks5/mod.rs`)

- RFC 1928 implementation built on the `fast-socks5` parsing/authentication layer
- Username/password auth (RFC 1929)
- CONNECT command only (UDP associate and BIND disabled)
- Relay over QUIC to proxy server

### 4.2 Dependencies

```toml
[dependencies]
tokio = { version = "1.35", features = ["full"] }
```

### 4.3 Testability Contract

- SOCKS5 layer must be testable with a stubbed QUIC connection
- Authentication and CONNECT flow should be tested without network I/O

## Phase 5: Testing and Parity

### 5.1 Golden Vector Tests

- Export test vectors from Go implementation
  - `obf-parity/vectors.json`
- Rust tests read vectors and validate:
  - Obfuscation chains
  - Frame encoding/decoding
  - Handshake flow (including cookie reply)
  - Transport payload format (padding + length)
  - MAC1 signatures
  - Encrypted timestamp encode/decode
  - Replay cache acceptance/denial decisions

### 5.2 Integration Tests

- End-to-end: SOCKS5 -> QUIC -> Proxy
- Packet loss simulation
- Replay protection validation
- Rate limiting behavior under burst conditions
- Cross-language: Rust client/server with Go server/client for compatibility

### 5.3 Fuzzing

```toml
[dev-dependencies]
cargo-fuzz = "0.11"
```

- Fuzz frame decoder
- Fuzz chain parser
- Fuzz payload decoder
- Fuzz replay cache inputs for panics and DoS behavior

## Phase 6: Tooling and Examples

### 6.1 CLI Tools

- `cargo run --example socks5d`: SOCKS5 daemon
- `cargo run --example proxy-server`: Proxy server

### 6.2 Configuration

```toml
# Example config
[obfuscation]
jc = 4
jmin = 10
jmax = 50
s1 = 39
s2 = 32
s3 = 0
s4 = 0

[headers]
h1 = "1662442204"
h2 = "793654571"
h3 = "468452595"
h4 = "1578142977"

[chains]
i1 = "<b 0x01><t><r 4><rc 8><d>"
i2 = ""
i3 = ""
i4 = ""
i5 = ""
```

## Implementation Order

### Sprint 1: Foundation (Week 1)
1. Project setup (Cargo, CI)
2. Core types and config
3. Obf trait definition
4. Simple obfuscators (bytes, data, rand)

### Sprint 2: Obfuscation Layer (Week 2)
1. Remaining obfuscators
2. Chain parsing
3. Header parsing
4. Framer implementation
5. Unit tests for obfuscation

### Sprint 3: Envelope Core (Week 3)
1. Transport payload
2. Padding policy
3. Basic client/server conn
4. Integration tests

### Sprint 4: Envelope Security (Week 4)
1. Replay cache
2. MAC1 implementation
3. Encrypted timestamp
4. Rate limiting

### Sprint 5: QUIC Integration (Week 5)
1. Quinn wrapper
2. Client connection
3. Server listener
3. End-to-end tests

### Sprint 6: SOCKS5 and Polish (Week 6)
1. SOCKS5 server
2. Proxy server
3. CLI tools
4. Documentation
5. Parity validation
6. Rust <-> Go compatibility tests

## Parity Validation

### Test Vector Format

```json
{
  "chains": [
    {
      "spec": "<b 0x01><t><r 4><rc 8><d>",
      "input": "41424344",
      "output": "01454e205e55e7c0e6e6e6e641424344"
    }
  ],
  "frames": [
    {
      "type": 1,
      "padding": 39,
      "header": "1662442204",
      "payload": "010300000001",
      "output": "..."
    }
  ]
}
```

### Validation Steps

1. Run Go implementation with fixed RNG seed, capture output
2. Run Rust implementation with the same seed and input
3. Compare outputs byte-for-byte
4. For randomized values, compare against seeded vectors only

## Parity Checklist

Use this list to confirm Rust behavior matches the Go implementation before release.

- Config fields mirrored: obfuscation, padding, replay, timestamp, legacy, rate limiting
- Obfuscation chains: spec parsing, encode/decode, length math
- Headers: H1-H4 ranges, validation, randomness under seed
- Junk and signature datagrams: counts, sizes, pacing
- Framer: message type mapping, header placement, padding
- Transport payload: length prefix, optional counter, padding policy
- MAC1: calculation and verification, error handling
- Encrypted timestamp: TAI64N format, X25519, AEAD params
- Replay cache: window size, eviction, clock jump behavior
- QUIC integration: wrapped socket framing on send/recv
- SOCKS5: CONNECT flow, auth, relay correctness

## Test Vector Schema

```json
{
  "seed": 12345,
  "chains": [
    {
      "spec": "<b 0x01><t><r 4><rc 8><d>",
      "input_hex": "41424344",
      "output_hex": "..."
    }
  ],
  "frames": [
    {
      "type": 1,
      "header": "1662442204",
      "padding": 39,
      "payload_hex": "010300000001",
      "output_hex": "..."
    }
  ],
  "transport": [
    {
      "counter": 42,
      "padding": 12,
      "payload_hex": "010203",
      "output_hex": "..."
    }
  ],
  "mac1": [
    {
      "key_hex": "...",
      "input_hex": "...",
      "output_hex": "..."
    }
  ],
  "enc_timestamp": [
    {
      "client_pub_hex": "...",
      "server_pub_hex": "...",
      "timestamp_hex": "...",
      "output_hex": "..."
    }
  ]
}
```

## Dependencies Summary

```toml
[dependencies]
# Core
rand = "0.8"
getrandom = "0.2"
thiserror = "1.0"

# Encoding/Decoding
hex = "0.4"
base64 = "0.21"

# Crypto
blake2 = "0.10"
chacha20poly1305 = "0.10"
x25519-dalek = "2.0"

# QUIC
quinn = "0.10"
rustls = "0.21"

# Async
tokio = { version = "1.35", features = ["full"] }

# Time
tai64n = "0.1"  # or chrono

# Config
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"

[dev-dependencies]
criterion = "0.5"
cargo-fuzz = "0.11"
```

## Open Questions

1. **Async Runtime**: Tokio is assumed; consider async-std compatibility
2. **QUIC**: Quinn is assumed with a wrapped UDP socket; validate against protocol needs
3. **Memory Safety**: Zeroization of sensitive data (keys, timestamps)
4. **WASM Support**: Consider `getrandom` WASM backend for browser use
5. **Embedded Targets**: Evaluate `std` dependence for no-std potential

## Success Criteria

- [ ] All obfuscation chain tests pass with Go parity
- [ ] Framer encode/decode matches Go byte-for-byte
- [ ] Handshake completes successfully
- [ ] End-to-end SOCKS5 -> QUIC -> TCP works
- [ ] Replay protection blocks replayed packets
- [ ] MAC1 verification works correctly
- [ ] Encrypted timestamp decrypts successfully
- [ ] Benchmarks show acceptable performance
- [ ] Fuzzing finds no panics
- [ ] Documentation is complete

## License

The Go implementation references AmneziaWG code. The Rust implementation should:

1. Clearly attribute AWG as the source of the obfuscation design
2. Use a compatible license (MIT/Apache-2.0)
3. Include LICENSE and NOTICE files
