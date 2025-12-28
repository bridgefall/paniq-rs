# Go vs Rust Implementation Differences

## Protocol Handshake and TLS/ALPN
- Go requires the custom ALPN value `bridgefall-paniq` and uses TLS 1.3 certificates generated at runtime; the QUIC dialer sets `NextProtos` accordingly and skips certificate verification. The server listener also advertises the same ALPN string when accepting connections. 【F:_reference/paniq/pkg/socks5daemon/quic.go†L16-L84】【F:_reference/paniq/internal/proxyserver/quic.go†L23-L114】
- The Rust binaries do not configure any ALPN value on the QUIC endpoints; they rely on statically embedded test certificates and the default Quinn ALPN handling, which makes them incompatible with the Go peers’ `bridgefall-paniq` requirement. 【F:bin/socks5d.rs†L143-L180】【F:bin/proxy-server.rs†L200-L241】

## QUIC Transport Parameters
- Go sets a 20s keep-alive, 2 minute idle timeout, and caps incoming streams, and it sizes initial packets based on the obfuscation framing/padding to avoid PMTU discovery. 【F:_reference/paniq/pkg/socks5daemon/quic.go†L192-L235】【F:_reference/paniq/internal/proxyserver/quic.go†L70-L88】
- Rust hardcodes a 1s keep-alive, 30s idle timeout, and leaves path MTU discovery enabled with Quinn defaults; packet sizing is not coordinated with the obfuscation framing. These mismatches mean the transports don’t share timing or packet-size assumptions, which can cause spurious timeouts and extra retransmissions versus the Go defaults. 【F:bin/socks5d.rs†L154-L180】【F:bin/proxy-server.rs†L228-L241】

## Session Management and Reconnection
- Go maintains a pooled QUIC connection guarded by a mutex and transparently reconnects when a stream open fails or when the connection context is done. It also closes the underlying UDP socket when reconnecting. 【F:_reference/paniq/pkg/socks5daemon/quic.go†L24-L165】
- Rust stores a single `quinn::Connection` without any reconnect logic; if the connection is dropped, all new SOCKS streams fail until the daemon restarts. The Go design hides transient losses, reducing tail latency during soak tests. 【F:bin/socks5d.rs†L200-L255】

## Proxy Request/Reply Flow
- Go’s client sends a proxy request and waits for a structured reply (`status`, bind address, bind port) before relaying data; the server validates the request, dials upstream, and sends a reply before streaming payload. 【F:_reference/paniq/pkg/socks5daemon/quic.go†L42-L85】【F:_reference/paniq/internal/proxyserver/quic.go†L164-L201】
- Rust sends the request and immediately starts data relay with no reply parsing, while the server never returns a success/failure header. This handshake mismatch makes the two implementations wire-incompatible—each side is waiting for different stream framing. 【F:bin/socks5d.rs†L200-L255】【F:bin/proxy-server.rs†L93-L190】

## Upstream Dialing and DNS Behavior
- Go performs DNS lookups with a 5s timeout and uses Happy Eyeballs racing for upstream TCP dials, returning errors quickly and measuring handshake latency for metrics. 【F:bin/proxy-server.rs†L143-L191】
- Rust resolves all addresses up front with a 5s timeout but then races every address with a 10s connect timeout, with no success reply to the client. The lack of pooled upstream connections and longer race window contribute to higher per-request latency compared with the Go design. 【F:bin/proxy-server.rs†L143-L191】

## Metrics and Padding
- Go threads envelope metrics and optional padding/replay controls from the profile into both client and server QUIC transports, logging effective payload budgets to keep MTU-safe packet sizes. 【F:_reference/paniq/pkg/socks5daemon/quic.go†L192-L235】【F:_reference/paniq/internal/proxyserver/quic.go†L70-L150】
- Rust does not propagate padding or replay limits into Quinn’s transport sizing, so actual UDP packet sizes can exceed the framed budget expected by the obfuscator, risking fragmentation and latency spikes. 【F:bin/socks5d.rs†L154-L180】
