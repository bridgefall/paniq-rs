# Acceptance Criteria Status

This file tracks the implementation state of paniq-rs against the phases outlined in `docs/paniq-rs-implementation-plan.md`.

## Implementation Status by Phase

### Phase 1: Core Obfuscation Layer ✅ COMPLETE
- **Types and Config**: `src/obf/config.rs` defines `Config` with all obfuscation parameters
- **Obf trait**: `src/obf/mod.rs` defines the obfuscation trait
- **Obfuscator implementations**: All 8 obfuscators implemented in `src/obf/`
  - `obf_bytes.rs` (<b hex>)
  - `obf_timestamp.rs` (<t>)
  - `obf_rand.rs` (<r N>)
  - `obf_randchars.rs` (<rc N>)
  - `obf_randdigits.rs` (<rd N>)
  - `obf_data.rs` (<d>)
  - `obf_datastring.rs` (<ds>)
  - `obf_datasize.rs` (<dz N>)
- **Magic Headers**: `src/obf/header.rs` and `src/obf/headers.rs` implement H1-H4
- **Framer**: `src/obf/framer.rs` implements message type framing
- **Tests**: Unit tests in `src/obf/tests.rs` cover all obfuscators, chains, headers, and framing

### Phase 2: Envelope Layer ✅ COMPLETE
- **Transport Payload**: `src/envelope/transport.rs` implements counter, length prefix, payload, and padding
- **Padding Policy**: `src/envelope/padding.rs` implements min/max/burst padding
- **Replay Cache**: `src/envelope/replay.rs` implements time-based sliding window cache
- **MAC1 Signature**: `src/envelope/mac1.rs` implements Blake2s-MAC1 computation and verification
- **Encrypted Timestamp**: `src/envelope/enc_timestamp.rs` implements TAI64N, X25519, AEAD encryption
- **Client Handshake**: `src/envelope/client.rs` implements junk/signature pacing, cookie replies
- **Server Connection**: `src/envelope/server.rs` implements peer state, cookie issuance, preamble handling
- **Tests**: Unit tests in `src/envelope/tests.rs` cover all envelope components

### Phase 3: QUIC Integration ✅ COMPLETE
- **QUIC Client**: `src/quic/client.rs` implements Quinn client with obfuscating UDP socket wrapper
- **QUIC Server**: `src/quic/server.rs` implements Quinn server endpoint with obfuscating socket
- **Handshake Integration**: `tests/quic_handshake.rs` tests envelope handshake over UDP
- **End-to-End Test**: `tests/quic_roundtrip.rs` tests full QUIC round-trip with obfuscation

### Phase 4: SOCKS5 Daemon ✅ COMPLETE
- **SOCKS5 Server**: `src/socks5/mod.rs` now layers our relay logic on top of the `fast-socks5`
  handshake/parser
  - SOCKS5 protocol negotiation
  - Username/password authentication (RFC 1929)
  - CONNECT command only (UDP/BIND disabled)
  - IPv4, IPv6, and domain name addresses (reply mirrors requested ATYP)
- **Relay Connector**: Pluggable `RelayConnector` trait for deterministic testing
- **Tests**: Comprehensive unit tests in `src/socks5/mod.rs` cover auth flows and relay

### Phase 5: Testing and Parity ✅ COMPLETE
- **Golden Vectors**: `tests/golden_vectors.rs` tests all components against `obf-parity/vectors.json`
  - Chains, frames, transport, MAC1, encrypted timestamps, replay cache
- **Vector Generation**: `examples/dump_vectors.rs` generates golden vectors from Rust implementation
- **Go Parity Test**: `tests/go_parity.rs` validates byte-for-byte parity with Go implementation
  - Uses `_reference/paniq/cmd/obf-vector` helper tool
  - Tests chain obfuscation: `<b hex>`, `<d>`, `<dz N>`, etc.
- **Fuzzing Targets**: `fuzz/fuzz_targets/` provides libFuzzer targets for:
  - Chain parser (`obf/mod.rs`)
  - Frame decoder (`obf/framer.rs`)
  - Payload decoder (`envelope/transport.rs`)
  - Replay cache (`envelope/replay.rs`)
  - Run with: `rustup run nightly cargo fuzz run main`
- **Missing**:
  - Packet-loss simulation tests
  - End-to-end integration tests with real network conditions

### Phase 6: Tooling and Examples ✅ COMPLETE (initial tools)
- **Vector Dump Tool**: `examples/dump_vectors.rs` generates JSON test vectors
- **CLI Tools**:
  - `bin/socks5d.rs` and `bin/proxy-server.rs` provide runnable daemons backed by QUIC +
    obfuscation
  - Integration flow validated in `tests/integration_socks5_quic.rs` with an end-to-end latency
    assertion under 200ms
- **Remaining nice-to-haves**:
  - Configuration file loading/saving
  - Profile generation utilities

## Pending Work

### High Priority
- ~~Add fuzzing targets~~ ✅ Complete
  - `fuzz/fuzz_targets/` contains targets for chain parser, frame decoder, payload decoder, replay cache
  - **Note**: Requires nightly Rust - see `fuzz/README.md` for setup instructions
  - Run with: `rustup run nightly cargo fuzz run main`

### Medium Priority
- ~~Implement CLI tools:~~ ✅ Complete
  - `socks5d`: Standalone SOCKS5 daemon binary
  - `proxy-server`: Standalone proxy server binary
- Add integration tests with packet-loss simulation
- Expand golden vector coverage with more envelope/handshake cases

### Low Priority
- Add more real-world integration tests
- Performance benchmarks

## Dependencies

Required features (via Cargo features):
- `quic`: Enables QUIC integration (quinn, rustls)
- `socks5`: Enables SOCKS5 daemon (tokio, async-trait)

Default: Both features are enabled by default.
