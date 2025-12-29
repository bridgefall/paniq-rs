# Migration Plan: Direct Replacement of QUIC (quinn) with kcp-rs

## Background
- The current QUIC transport built on Quinn is broken, so integration coverage does not pass. The goal is to remove Quinn entirely and bring the system back to green by wiring kcp-rs directly into the existing obfuscation/envelope layers. `connect` performs the handshake before transport initialization, and `FramedUdpSocket` applies the envelope framing. Server setup mirrors this flow on the bound UDP socket. 【F:src/quic/client.rs†L26-L200】【F:src/quic/server.rs†L17-L38】
- Integration and soak coverage exercise a local SOCKS5 → transport proxy path that forwards to an in-process HTTP server. The soak test stresses the pipeline for 30 seconds by repeatedly issuing HTTP GETs against that local server and must continue to do so post-migration. 【F:tests/integration_socks5_quic.rs†L115-L220】【F:tests/integration_socks5_quic.rs†L477-L503】

## Goals and Acceptance Criteria
1. Rip out Quinn and land a KCP-based transport that preserves the existing obfuscation/envelope handshake without any dual-stack migration path.
2. Keep the public SOCKS5 daemon and proxy binaries functionally equivalent (same request/response semantics and authentication surface).
3. Restore green status for `integration_socks5_over_quic` and the 30-second soak test using the KCP-based transport. The soak test must continue to issue HTTP requests against the local test server to avoid external dependencies. 【F:tests/integration_socks5_quic.rs†L115-L220】【F:tests/integration_socks5_quic.rs†L477-L503】

## Migration Steps

### 1) Replace Quinn transport primitives with kcp-rs
- Add the `kcp` crate (or the kcp-rs fork used internally) and remove Quinn dependencies from the transport layer entirely so the build uses KCP by default.
- Map profile-driven transport settings (MTU, window sizes, resend/interval timers) to the KCP configuration so latency targets stay aligned with prior tuning.

### 2) Preserve obfuscation + envelope handshake
- Reuse `UdpPacketConn` and `Framer` to run the current initiation handshake before constructing a KCP session, mirroring how `connect` stages the handshake before transport setup. 【F:src/quic/client.rs†L26-L80】
- Wrap the UDP socket with the same framed adapter so the obfuscation layer continues to encode/decode transport datagrams before KCP consumes them. Replace `FramedUdpSocket`’s Quinn `AsyncUdpSocket` impl with a thin adapter that feeds bytes into `kcp::Kcp`’s `input`/`recv` APIs.

### 3) Redefine stream semantics on top of KCP
- KCP is message-oriented and single-stream; emulate bidirectional streams used by `open_bi` by multiplexing logical channels over a single KCP session (length-prefixed frames carrying stream IDs) or by instantiating one KCP session per SOCKS connection.
- Update the SOCKS5 connector and proxy server loops to use the KCP session abstraction instead of Quinn `Connection`/`SendStream`/`RecvStream`, while keeping the request framing unchanged so the higher-level protocol remains compatible. 【F:tests/integration_socks5_quic.rs†L133-L220】

### 4) Reliability, congestion, and NAT behavior
- Configure KCP timers (interval, nodelay, resend, window) to approximate prior latency budgets while respecting the MTU enforced by the obfuscation framing.
- Ensure the UDP socket stays non-blocking with explicit read/write readiness similar to `FramedUdpSocket`, and add metrics/logging to observe RTT/fast-resend behavior during soak runs.
- Implement keepalive/idle handling equivalent to the current 120s idle window; send periodic KCP probes instead of QUIC keepalives.

### 5) Testing and soak adaptations
- Port `socks5_over_quic_roundtrip` and the soak harness to instantiate the KCP-backed connector/server, removing Quinn from test setup. Keep the local HTTP server used in the current tests as the target to avoid network variance and satisfy soak requirements. 【F:tests/integration_socks5_quic.rs†L115-L220】【F:tests/integration_socks5_quic.rs†L477-L503】
- Add targeted tests for KCP session restart and loss recovery (e.g., packet drop simulation) to ensure the new transport handles edge cases and documents any divergence from the Quinn design (e.g., single-stream multiplexing costs).
- Use the Makefile’s curated targets for deterministic validation while porting: `make test` for unit + integration coverage, `make test-socks5-realistic` to exercise the local HTTP server path, and `make test-all` once KCP replaces Quinn across all binaries and features.

### 6) Execution and rollout
- Remove the Quinn dependency and ship KCP as the only supported transport. If a temporary escape hatch is required, keep a minimal behind-the-scenes feature flag solely for debugging; do not expose dual stacks to users.
- Harden the metrics/observability story during the soak run to catch regressions early because there is no migration fallback.

## Risks and Mitigations
- **Stream multiplexing complexity**: KCP lacks native bidi streams; mitigate by adding a simple stream ID framing layer and benchmarking it in the soak test.
- **Congestion window tuning**: Misconfigured KCP parameters can inflate latency. Capture metrics during soak to tune `nodelay`, window sizes, and resend thresholds.
- **NAT/port reuse**: KCP sessions must survive NAT rebinding. Mirror Quinn’s socket lifecycle by reusing a bound UDP socket per connector and detecting address changes.

## Definition of Done
- Quinn code paths are removed or disabled from production builds; KCP transport is the only path for SOCKS5 daemon and proxy binaries.
- `integration_socks5_over_quic` and `soak_socks5_over_quic_30s` pass using the KCP-backed transport and the local HTTP target.
- Documentation updated (this file) to reflect the single-path design and any deviations encountered during implementation and testing.
