# Acceptance Criteria Status

This file tracks the implementation state against the migration/acceptance criteria outlined for the Paniq Rust port.

## Implemented
- **Obfuscation layer (Phase 1)**: `paniq-rs` implements the `Obf` trait, chain parsing, magic headers, and the framer with deterministic RNG controls. Unit tests cover obfuscators, chain parsing, header parsing, framing encode/decode, and seeded determinism.
- **Envelope layer (Phase 2)**: padding policy, transport payload framing, replay cache, MAC1, encrypted timestamps, and deterministic in-memory handshakes are implemented with unit tests.
- **Handshake pacing/cookies (Phase 2.6/2.7)**: client-side pacing plus server-issued cookie replies now gate handshake completion in the in-memory harness.
- **Cross-language smoke checks**: `paniq-rs/tests/go_parity.rs` exercises multiple obfuscation specs against the Go helper (`cd _reference/paniq && go run ./cmd/obf-vector`) to validate byte-for-byte parity for deterministic chains.
- **Golden vector coverage (Phase 5.1)**: `paniq-rs/obf-parity/vectors.json` captures deterministic obfuscation, framing, transport, MAC1, encrypted timestamp cases, and replay cache decisions that Rust tests replay.
- **QUIC socket framing (Phase 3)**: obfuscating UDP sockets wrap Quinn's async socket abstraction so QUIC datagrams are encoded/decoded with the obfuscation framer, and UDP-backed `PacketConn` support enables running the envelope handshake over real sockets.
- **SOCKS5 server (Phase 4)**: RFC 1928/1929 CONNECT handling with optional username/password authentication, plus bidirectional relay over an injected connector to keep tests deterministic.

## Pending / Not Yet Implemented
- **QUIC integration (Phase 3)**: Quinn-backed client/server wrappers now have an obfuscating end-to-end QUIC round-trip test over real UDP sockets, but broader integration coverage is still pending.
- **Golden vector expansion (Phase 5.1)**: vector files now include replay cache decisions; still need to add more envelope/handshake cases, ideally mirrored from the Go implementation.
- **End-to-end and fuzzing (Phase 5.2/5.3)**: no Rust-side integration, packet-loss simulation, or fuzz harnesses are present.
- **Tooling/examples (Phase 6)**: CLI tooling and examples described in the plan have not been added for the Rust crate.

## Next Steps
- Expand Go↔Rust parity to cover headers, framer outputs, and envelope/MAC layers once those components are ported.
- Add golden vector fixtures exported from the Go implementation and exercise them from Rust tests.
- Implement the envelope, QUIC, and SOCKS5 layers in Rust to satisfy the remaining phases.
- Introduce fuzz targets for decoders and replay cache logic once available.
