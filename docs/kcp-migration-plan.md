# KCP Transport Rollout Plan

## Background
The transport layer now relies exclusively on kcp-rs paired with the existing obfuscation and envelope framing. Connections perform the handshake before instantiating the transport session, and both sides wrap the UDP socket with the same framer used throughout the stack.

## Goals and Acceptance Criteria
1. Keep the SOCKS5 daemon and proxy binaries functionally equivalent while using KCP for every transport hop.
2. Maintain the existing handshake and framing so higher-level protocols remain compatible.
3. Ensure integration and soak coverage stay green while running fully on the new transport.

## Migration Steps

### 1) Standardize on kcp-rs primitives
- Build only with the `kcp` feature set and remove leftover dependencies tied to any prior transport.
- Map profile-driven transport settings (MTU, payload sizing, keepalive) into the new configuration surface as needed.

### 2) Preserve obfuscation + envelope handshake
- Keep using the current framer around the UDP socket to encode/decode datagrams before KCP consumes them.
- Maintain the pre-transport handshake so both peers agree on keys and timing before data transfer.

### 3) Stream semantics on top of KCP
- Use framed messages to carry stream identifiers and requests over the single KCP session.
- Keep the SOCKS5 request framing identical so daemon and proxy interactions stay compatible.

### 4) Reliability, congestion, and NAT behavior
- Tune KCP timers and window sizes to respect MTU and latency expectations imposed by the obfuscation layer.
- Keep sockets non-blocking with explicit readiness handling and add metrics to watch RTT and resend behavior during soak runs.
- Implement keepalive/idle handling equivalent to the previous 120s idle window using KCP probes.

### 5) Testing and soak adaptations
- Run the SOCKS5 integration and 30-second soak tests against the KCP-backed connector and server using the local HTTP target to avoid external variance.
- Add focused tests for session restart and loss recovery to document behavior under drop or reorder scenarios.
- Use the Makefile targets (`make test`, `make test-socks5-realistic`, `make test-all`) to verify coverage while iterating.

### 6) Execution and rollout
- Ship KCP as the only supported transport path in the binaries.
- Harden observability during soak runs to catch regressions early since no alternate transport remains.

## Risks and Mitigations
- **Stream multiplexing complexity**: Framed stream identifiers add a small overhead; benchmark during soak to confirm no regression.
- **Congestion window tuning**: Misconfigured parameters can inflate latency; record metrics while adjusting `nodelay`, window sizes, and resend thresholds.
- **NAT/port reuse**: Sessions must survive NAT rebinding; keep UDP sockets stable per connector and detect address changes.

## Definition of Done
- The KCP transport is the only path for SOCKS5 daemon and proxy binaries.
- Integration and soak suites remain green against the local HTTP target.
- Documentation reflects the single-transport design and the implemented behavior.
