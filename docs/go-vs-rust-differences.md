# Go vs Rust Differences

The Go reference implementations and the Rust binaries now share a KCP-based transport and a common obfuscation handshake. Key differences to keep in mind:

- **ALPN/TLS**: The Rust stack no longer embeds TLS for transport; the UDP tunnel is authenticated and encrypted by the obfuscation layer plus KCP framing.
- **Connection pooling**: Go keeps a pooled transport session guarded by a mutex and reconnects transparently on failures. The Rust implementation prefers a single framed session that is reused across SOCKS5 requests.
- **Request/response framing**: Both sides send a structured proxy request and wait for a reply before relaying payloads. DNS resolution is bounded with a timeout on the Rust proxy side.
- **Transport metrics**: Go threads padding and replay controls from the profile into its transport metrics. Rust exposes similar knobs through the profile and logs effective payload budgets when configured.
