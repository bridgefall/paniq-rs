# Go Parity Roadmap

## Milestone 1: Transport handshake compatibility
- Align ALPN-free UDP handshake framing between Go and Rust so sessions establish without negotiation errors.
- AC: Rust client can establish a KCP session to the Go proxy using the shared envelope handshake values.

## Milestone 2: Transport configuration parity
- Reflect profile values (keepalive, idle timeout, padding controls) consistently across both implementations.
- AC: Reconnect and session reuse mirror Go behavior without requiring a restart of the SOCKS5 daemon.

## Milestone 3: Resilience and recovery
- Add pooled or restartable sessions on the client side, closing the underlying UDP socket when reconnecting.
- AC: Stream opens recover transparently after a dropped connection while preserving obfuscation state.
