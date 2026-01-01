# KCP Transport Rollout Plan

## Background
The target transport layer will rely on kcp-rs paired with async_smux and the existing obfuscation + envelope framing. Connections perform the handshake before instantiating the KCP session, and both sides wrap UDP datagrams with the same framer used throughout the stack. See `docs/kcp-transport-wrapper.md` for the design sketch.

## Current Status (2025-12-29)

### Completed
- [x] In-process KCP stub implementation using channel-based registry
- [x] Basic handshake integration (client-side only; server handshake not yet wired)
- [x] Removal of QUIC transport references from Rust codebase (excluding `_reference/paniq`)
- [x] **Phase 1: Real UDP transport layer** - KCP handshake working across separate processes
- [x] Removal of in-process `REGISTRY` from `src/kcp/common.rs`

### Original Blocking Issue
The KCP implementation was an **in-process stub only**. It used a shared memory registry (`REGISTRY` in `src/kcp/common.rs`) to map server addresses to channels. This worked only when the client and server were in the **same process**.

**Symptom**: Running `proxy-server` and `socks5d` as separate binaries failed with `Error: Connection("server not listening")` because each process had its own empty registry.

**Root cause**: The stub communicated via `mpsc::channel`, not actual UDP networking. See `src/kcp/client.rs:104` and `src/kcp/server.rs:66-69`.

### Additional Issues Found During Implementation
When implementing real UDP networking, several protocol-level bugs were discovered and fixed:

1. **Protocol mismatch: `CookieReply` vs `Response`**
   - **Location**: `src/envelope/client.rs:140-155`
   - **Issue**: Rust `client_handshake` expected `CookieReply` → `Response` two-step flow, but Go implementation sends `Response` directly
   - **Fix**: Removed `CookieReply` handling to match Go implementation

2. **Socket API misuse: `try_send_to` on connected socket**
   - **Location**: `src/kcp/transport.rs:369-372`
   - **Issue**: After `UdpSocket::connect()`, must use `try_send()` not `try_send_to()`
   - **Symptom**: "deadline has elapsed" error
   - **Fix**: Changed from `try_send_to(&data, addr)` to `try_send(&data)`

3. **Double-consumption of Response packet**
   - **Location**: `src/kcp/transport.rs:438-446`
   - **Issue**: `client_handshake` consumed the Response packet, then code tried to `recv_from()` again to extract `conv_id`
   - **Symptom**: "deadline has elapsed" waiting for second Response
   - **Fix**: Changed `client_handshake` to return `Result<Vec<u8>>` (Response payload) instead of `Result<()>`

All three issues were **code bugs**, not profile or configuration issues. The original `examples/profile.json` works correctly after these fixes.

### Decisions (2025-12-29)
- Use **kcp-rs** as the KCP engine.
- Use **async_smux** for stream multiplexing over the single KCP byte stream.
- Implement KCP as a thin wrapper layer (no fork) as outlined in `docs/kcp-transport-wrapper.md`.
- Encode `conv_id` in the envelope handshake response payload (4 bytes, big-endian).

## Next Steps: Implement Real UDP Transport

### Phase 1: UDP Socket Layer ✅ COMPLETED
1. ✅ **Replace registry-based lookup with actual UDP sockets**
   - ✅ Remove `REGISTRY` from `src/kcp/common.rs` (file deleted)
   - ✅ Create real `UdpSocket` instances bound to configured addresses
   - ✅ Server: bind and listen on `--listen` address (`KcpServer::bind()`)
   - ✅ Client: connect to `proxy_addr` from profile (`KcpClient::connect()`)

2. ✅ **Preserve obfuscation/framing over UDP**
   - ✅ Keep `Framer` wrapping the UDP socket
   - ✅ Envelope handshake works over real UDP packets
   - ✅ Junk packets and signature chains transmit correctly

3. ✅ **Add KCP + async_smux crates + config surface**
   - ✅ Add `kcp-rs` and `async_smux` to `Cargo.toml`
   - ✅ Map profile settings to `ServerConfigWrapper`/`ClientConfigWrapper`
   - ✅ Implement tokio-based UDP read/write loops with KCP update

### Phase 2: KCP Session + smux Stream Layer ✅ COMPLETED
1. ✅ **Server side (`src/kcp/server.rs` and `src/kcp/transport.rs`)**
   - ✅ Accept incoming UDP datagrams with `recv_from`/`send_to` (multi-peer)
   - ✅ Perform envelope handshake to establish session context
   - ✅ Create KCP conv/conversation for each handshake
   - ✅ Define and exchange `conv_id` during handshake; map `(peer_addr, conv_id) → SessionState`
   - ✅ Include `conv_id` in the `MessageType::Response` payload (4 bytes, big-endian)
   - ✅ Initialize async_smux on server after handshake completes
   - ✅ Send `IncomingConnection` through channel to application layer

2. ✅ **Client side (`src/kcp/client.rs` and `src/kcp/transport.rs`)**
   - ✅ Perform envelope handshake via UDP (remove `connect_after_handshake` bypass)
   - ✅ Receive/validate `conv_id` from server handshake response payload
   - ✅ Create `Kcp::new(conv_id)`, then call `initialize()` and pin the instance (required by kcp-rs)
   - ✅ Run KCP update loop for sending/receiving (tokio tasks + timers)
   - ✅ Initialize async_smux on client after handshake completes

3. ✅ **Transport framing integration**
   - ✅ Wrap KCP datagrams using `MessageType::Transport`
   - ✅ Use simplified transport payload: `[len][data]` (2-byte length prefix)
   - ✅ Transport replay protection stub (can be enhanced later)

4. ✅ **async_smux integration**
   - ✅ Use `async_smux` as the smux implementation (tokio-based)
   - ✅ Implement a `KcpStreamAdapter` that exposes the KCP byte stream as `tokio::io::AsyncRead + AsyncWrite + Unpin`
   - ✅ Build the mux via `MuxBuilder::client/server().with_connection(adapter).build()`, then spawn the worker task
   - ✅ Client: `connector.connect()` maps to `Connection::open_bi()`
   - ✅ Server: `acceptor.accept().await` maps to `IncomingConnection::accept_bi()`
   - ✅ Create wrapper modules per `docs/kcp-transport-wrapper.md` (e.g., `src/kcp/transport.rs`, `src/kcp/mux.rs`)

5. **Per-packet I/O flow with kcp-rs (sketch)**
   - **Inbound UDP → KCP**
     1. `udp.recv_from()` → `datagram`
     2. `framer.decode_frame(datagram)` → `(MessageType::Transport, payload)`
     3. `decode_transport_payload(payload, expect_counter, replay_check)` → `kcp_bytes`
     4. `kcp.input(&kcp_bytes)` to feed the KCP state machine
   - **Outbound KCP → UDP**
     1. `while kcp.has_ouput() { kcp.pop_output() }` → `kcp_bytes` (note: method is spelled `has_ouput` in kcp-rs)
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
     while kcp.has_ouput() {
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
- Add `async_smux` and the KCP stream adapter to the transport module (no fork).
- Map profile-driven transport settings (MTU, payload sizing, keepalive) into the new configuration surface as needed.

### 2) Preserve obfuscation + envelope handshake
- Keep using the current framer around the UDP socket to encode/decode datagrams before KCP consumes them.
- Maintain the pre-transport handshake so both peers agree on keys and timing before data transfer.

### 3) Stream semantics on top of KCP
- Use **async_smux** to multiplex logical streams over the single KCP byte stream.
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
1. **Which async_smux version/config surface should we target?**
   - Suggested default: Use the latest `async_smux` with `MuxBuilder` + `TokioConn`, and implement `tokio::io::AsyncRead + AsyncWrite + Unpin` for the KCP adapter.

2. **Confirm `conv_id` generation details (RNG + lifetime).**
   - Suggested default: Server-generated 32-bit random `conv_id` (per session), encoded in the handshake `Response` payload (big-endian) and keyed by `(peer_addr, conv_id)`.

3. **What is the transport framing contract for KCP datagrams?**
   - Suggested default: Encapsulate each KCP UDP datagram as `MessageType::Transport` with `build_transport_payload`, using counters when `transport_replay` is enabled; keep payload size within `max_payload` to preserve padding headroom.

4. **How should the KCP update loop be scheduled?**
   - Suggested default: Use a tokio task per session with a tight timer (e.g., 10–20ms tick) and drive `update/flush` on readiness; bind a separate UDP read task that feeds KCP `input` with decoded transport payloads.

5. **Client handshake flow: when to call it and how to retry?**
   - Suggested default: Always run the envelope handshake before KCP session creation; honor `handshake_timeout` and `handshake_attempts` from profile, with jittered retries matching existing preamble delay settings.

## Definition of Done
- The KCP transport is the only path for SOCKS5 daemon and proxy binaries.
- Integration and soak suites operate over UDP and remain green against the local HTTP target.
- Documentation reflects the single-transport design and the implemented behavior.
