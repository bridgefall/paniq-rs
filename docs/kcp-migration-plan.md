# KCP Transport Rollout Plan

## Background
The target transport layer will rely on kcp-rs paired with smux and the existing obfuscation + envelope framing. Connections perform the handshake before instantiating the KCP session, and both sides wrap UDP datagrams with the same framer used throughout the stack. See `docs/kcp-transport-wrapper.md` for the design sketch.

## Current Status (2025-12-29)

### Completed
- [x] In-process KCP stub implementation using channel-based registry
- [~] Basic handshake integration (client-side only; server handshake not yet wired)
- [x] Removal of QUIC transport references from Rust codebase (excluding `_reference/paniq`)

### Blocking Issue
The current KCP implementation is an **in-process stub only**. It uses a shared memory registry (`REGISTRY` in `src/kcp/common.rs`) to map server addresses to channels. This works only when the client and server are in the **same process**.

**Symptom**: Running `proxy-server` and `socks5d` as separate binaries fails with `Error: Connection("server not listening")` because each process has its own empty registry.

**Root cause**: The stub communicates via `mpsc::channel`, not actual UDP networking. See `src/kcp/client.rs:104` and `src/kcp/server.rs:66-69`.

### Decisions (2025-12-29)
- Use **kcp-rs** as the KCP engine.
- Use **smux** for stream multiplexing over the single KCP byte stream.
- Implement KCP as a thin wrapper layer (no fork) as outlined in `docs/kcp-transport-wrapper.md`.

## Next Steps: Implement Real UDP Transport

### Phase 1: UDP Socket Layer
1. **Replace registry-based lookup with actual UDP sockets**
   - Remove `REGISTRY` from `src/kcp/common.rs`
   - Create real `UdpSocket` instances bound to configured addresses
   - Server: bind and listen on `--listen` address
   - Client: connect to `proxy_addr` from profile

2. **Preserve obfuscation/framing over UDP**
   - Keep `Framer` wrapping the UDP socket (already in place)
   - Ensure envelope handshake works over real UDP packets
   - Verify junk packets and signature chains transmit correctly

3. **Add KCP + smux crates + config surface**
   - Add `kcp-rs` and `smux` to `Cargo.toml`
   - Map profile-driven settings (`max_packet_size`, `max_payload`, `keepalive`, `idle_timeout`, `max_streams`) to KCP + smux configs
   - Decide async integration approach (tokio + UDP read/write loops + adapter)

### Phase 2: KCP Session + smux Stream Layer
1. **Server side (`src/kcp/server.rs`)**
   - Accept incoming UDP datagrams with `recv_from`/`send_to` (multi-peer)
   - Perform envelope handshake to establish session context
   - Create KCP conv/conversation for each handshake
   - Define and exchange `conv_id` during handshake; map `(peer_addr, conv_id) → SessionState`

2. **Client side (`src/kcp/client.rs`)**
   - Perform envelope handshake via UDP (remove `connect_after_handshake` bypass)
   - Receive/validate `conv_id` from server handshake response
   - Run KCP update loop for sending/receiving (tokio tasks + timers)

3. **Transport framing integration**
   - Wrap KCP datagrams using `MessageType::Transport`
   - Use `envelope::transport::{build_transport_payload, decode_transport_payload}`
   - Honor `transport_replay` / counters if enabled in profile

4. **smux integration**
   - Implement a `KcpStreamAdapter` that exposes the KCP byte stream as `AsyncRead`/`AsyncWrite`
   - Client: `smux::Session::new_client(adapter, config)`; map `open_bi()` → `open_stream()`
   - Server: `smux::Session::new_server(adapter, config)`; map `accept_bi()` → `accept_stream()`
   - Map `max_streams`, `keepalive`, and `idle_timeout` to smux settings
   - Create wrapper modules per `docs/kcp-transport-wrapper.md` (e.g., `src/kcp/transport.rs`, `src/kcp/mux.rs`)

5. **Per-packet I/O flow with kcp-rs (sketch)**
   - **Inbound UDP → KCP**
     1. `udp.recv_from()` → `datagram`
     2. `framer.decode_frame(datagram)` → `(MessageType::Transport, payload)`
     3. `decode_transport_payload(payload, expect_counter, replay_check)` → `kcp_bytes`
     4. `kcp.input(&kcp_bytes)` to feed the KCP state machine
   - **Outbound KCP → UDP**
     1. `while kcp.has_output() { kcp.pop_output() }` → `kcp_bytes`
     2. `build_transport_payload(kcp_bytes, counter, padding, max_payload, rng)` → `payload`
     3. `framer.encode_frame(MessageType::Transport, payload)` → `datagram`
     4. `udp.send_to(datagram, peer_addr)`
   - **Handshake path (before KCP)**
     - Use `MessageType::{Initiation, CookieReply, Response}` frames directly over UDP until the preamble completes; only then start wrapping KCP datagrams as `MessageType::Transport`.
   - **Diagram**
     ```
     UDP recv -> Framer.decode -> Transport.decode -> KCP.input -> KCP.update
                                                        |
     UDP send <- Framer.encode <- Transport.build <- KCP.pop_output
     ```
   - **Pseudo-code sketch**
     ```rust
     // recv path
     let (datagram, peer) = udp.recv_from()?;
     let (msg, payload) = framer.decode_frame(&datagram)?;
     if msg == MessageType::Transport {
         let kcp_bytes = decode_transport_payload(&payload, expect_ctr, replay_check)?;
         kcp.input(&kcp_bytes);
     }
     // periodic update tick (e.g., 10-20ms)
     kcp.update(now_ms);

     // send path
     while kcp.has_output() {
         let kcp_bytes = kcp.pop_output();
         let payload = build_transport_payload(
             &kcp_bytes,
             counter.next(),
             &padding,
             max_payload,
             &mut rng,
         )?;
         let datagram = framer.encode_frame(MessageType::Transport, &payload)?;
         udp.send_to(&datagram, peer)?;
     }
     ```

### Phase 3: Integration Points to Modify
- `proxy-server`: Use `UdpSocket::bind()` instead of registry registration
- `socks5d`: Use `UdpSocket::connect()` to `proxy_addr` and run client handshake (no registry lookup)
- Remove `src/kcp/common.rs` entirely (no shared state needed)
- Replace the channel-based stream stub with smux-backed streams

### Phase 4: Testing Strategy
1. Start with local loopback tests (127.0.0.1)
2. Verify `proxy-server` and `socks5d` communicate as separate processes
3. Run integration tests against real HTTP target
4. Soak testing with packet loss/reordering scenarios

## Goals and Acceptance Criteria
1. Keep the SOCKS5 daemon and proxy binaries functionally equivalent while using KCP for every transport hop.
2. Maintain the existing handshake and framing so higher-level protocols remain compatible.
3. Ensure integration and soak coverage stay green while running fully on the new transport.

## Migration Steps

### 1) Standardize on kcp-rs + smux primitives
- Build only with the `kcp` feature set and remove leftover dependencies tied to any prior transport.
- Add `smux` and the KCP stream adapter to the transport module (no fork).
- Map profile-driven transport settings (MTU, payload sizing, keepalive) into the new configuration surface as needed.

### 2) Preserve obfuscation + envelope handshake
- Keep using the current framer around the UDP socket to encode/decode datagrams before KCP consumes them.
- Maintain the pre-transport handshake so both peers agree on keys and timing before data transfer.

### 3) Stream semantics on top of KCP
- Use **smux** to multiplex logical streams over the single KCP byte stream.
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
- **Stream multiplexing complexity**: smux adds overhead and backpressure dynamics; benchmark during soak to confirm no regression.
- **Congestion window tuning**: Misconfigured parameters can inflate latency; record metrics while adjusting `nodelay`, window sizes, and resend thresholds.
- **NAT/port reuse**: Sessions must survive NAT rebinding; keep UDP sockets stable per connector and detect address changes.

## Open Questions (with Suggested Defaults)
1. **Which smux crate API/traits should the adapter target?**
   - Suggested default: Use a tokio-friendly `smux` crate and implement `AsyncRead`/`AsyncWrite` for the KCP adapter; if needed, use a compat shim rather than forking.

2. **How should `conv_id` be generated and exchanged?**
   - Suggested default: Server-generated 32-bit random `conv_id` (per session) returned in the handshake response payload; key sessions by `(peer_addr, conv_id)` to tolerate NAT rebinding while preventing collisions.

3. **What is the transport framing contract for KCP datagrams?**
   - Suggested default: Encapsulate each KCP UDP datagram as `MessageType::Transport` with `build_transport_payload`, using counters when `transport_replay` is enabled; keep payload size within `max_payload` to preserve padding headroom.

4. **How should the KCP update loop be scheduled?**
   - Suggested default: Use a tokio task per session with a tight timer (e.g., 10–20ms tick) and drive `update/flush` on readiness; bind a separate UDP read task that feeds KCP `input` with decoded transport payloads.

5. **Client handshake flow: when to call it and how to retry?**
   - Suggested default: Always run the envelope handshake before KCP session creation; honor `handshake_timeout` and `handshake_attempts` from profile, with jittered retries matching existing preamble delay settings.

## Definition of Done
- The KCP transport is the only path for SOCKS5 daemon and proxy binaries.
- Integration and soak suites remain green against the local HTTP target.
- Documentation reflects the single-transport design and the implemented behavior.
