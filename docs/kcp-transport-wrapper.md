# KCP Transport Wrapper (kcp-rs + Envelope)

## Summary
Build a thin transport wrapper around `kcp-rs` that owns UDP I/O, applies the obfuscation envelope per packet, and exposes the existing `Connection`-style API (`open_bi`/`accept_bi`). Keep `kcp-rs` unmodified and keep envelope logic in this repo.

## Goals
- Preserve the current obfuscation envelope (junk, signature, padding, transport framing).
- Support separate processes (real UDP networking).
- Provide the same high-level API surface used by `socks5d` and `proxy-server`.
- Keep `kcp-rs` as a dependency without forking.

## Non-Goals
- Modifying or forking `kcp-rs`.
- Reintroducing QUIC or other transports.
- Designing a new external protocol; this is internal wiring.

## Architecture (High-Level)
```
UDP socket
  -> Framer.decode (MessageType)
  -> Transport.decode (payload/counter)
  -> kcp-rs input/update
  -> stream mux/demux (stream ids)
  -> Connection API
```

### Proposed Modules
- `src/kcp/transport.rs` (new)
  - Owns UDP socket, handshake, per-session KCP state, timers.
  - Encodes/decodes `MessageType::Transport` frames.
- `src/kcp/mux.rs` (new)
  - Lightweight stream mux on top of single KCP session.
  - Maps `stream_id -> mpsc` or `tokio::io::DuplexStream`.
- `src/kcp/client.rs` / `src/kcp/server.rs`
  - Thin wrappers that call into `transport`.

## Packet Flow (Per-Packet Envelope)
**Inbound UDP → KCP**
1. `recv_from` UDP datagram.
2. `framer.decode_frame(datagram)` → `(MessageType, payload)`.
3. If `Transport`: `decode_transport_payload(payload, ...)` → `kcp_bytes`.
4. `kcp.input(&kcp_bytes)` and `kcp.update(now_ms)`.

**Outbound KCP → UDP**
1. `while kcp.has_output() { kcp.pop_output() }` → `kcp_bytes`.
2. `build_transport_payload(kcp_bytes, counter, padding, max_payload, rng)` → `payload`.
3. `framer.encode_frame(MessageType::Transport, payload)` → `datagram`.
4. `send_to(datagram, peer_addr)`.

**Handshake Path (Before KCP)**
- Use `MessageType::{Initiation, CookieReply, Response}` directly over UDP.
- Only start KCP once the envelope preamble completes and `conv_id` is known.

## Session Model
- Key sessions by `(peer_addr, conv_id)`.
- Server: `HashMap<(SocketAddr, u32), SessionState>`.
- SessionState holds:
  - `kcp: kcp_rs::Kcp`
  - `last_seen`, `next_update`
  - `mux: smux::Session`
  - `send_queue` (if needed for backpressure)

## Stream Multiplexing (async_smux)
- Use `async_smux` to multiplex streams over the single KCP byte stream.
- Expose KCP as a reliable byte stream (`futures::io::AsyncRead + AsyncWrite + Unpin + Send`) via a small adapter:
  - `KcpStreamAdapter` reads from the KCP receive buffer and writes via `kcp.send(...)`.
  - If other layers are `tokio::io`, bridge with `tokio_util::compat` (`compat` feature).
- Client:
  - `async_smux::Mux::new(adapter, MuxConfig::default())` + `connect().await` maps to `open_bi()`.
- Server:
  - `async_smux::Mux::new(adapter, MuxConfig::default())` + `accept().await` maps to `accept_bi()`.
- Initial SOCKS target request stays the same: written as the first bytes on the accepted stream.
- Config mapping:
  - `max_streams` → mux config limit.
  - `keepalive` / `idle_timeout` → mux keepalive/idle settings (align with profile).

## Integration Touchpoints
- `bin/socks5d.rs`: use `kcp::client::connect` (with handshake) and keep `open_bi`.
- `bin/proxy-server.rs`: use `kcp::server::listen` and keep `accept_bi`.
- Remove `src/kcp/common.rs` and its `REGISTRY`.

## Risks / Notes
- KCP is not multiplexed by itself; mux framing is required to preserve current API.
- Timer tick + UDP I/O must be efficient to avoid latency regressions.
- Replay/counter handling must match `transport_replay` profile settings.
