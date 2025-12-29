# SOCKS5 & Proxy Daemon Latency Review

## Executive Summary
The SOCKS5 daemon (`socks5d.rs`) and proxy server (`proxy-server.rs`) now relay traffic over an obfuscated KCP tunnel. Requests are framed identically to the legacy flow, but the transport stack has been simplified to rely solely on kcp-rs. The review below captures the current architecture and highlights areas to watch for latency regressions.

---

## Architecture Overview
```
Client (curl)
    ↓ (SOCKS5 protocol)
socks5d.rs (local)
    ↓ (Obfuscated KCP over UDP)
proxy-server.rs (remote)
    ↓ (TCP)
Target Server (ifconfig.io)
```

Flow outline:
1. The local SOCKS5 server accepts TCP connections.
2. It opens a framed KCP session to the proxy and forwards the target request.
3. The proxy decodes the target and connects via TCP.
4. Bidirectional relaying runs over the single KCP session.

---

## Current Notes and Recommendations

### Connection Contention
- Each SOCKS5 request shares the same framed transport session. Monitor lock contention in connection setup paths and consider lightweight pooling if contention shows up in benchmarks.

### DNS Resolution Timing
- DNS lookups still happen after the transport request arrives on the proxy. Adding a short timeout and optional caching would bound worst-case latency when upstream DNS is slow.

### Keepalive Configuration
- KCP keepalive timing should be kept conservative (e.g., matching the previous 120s idle window) to avoid excess probe traffic that could compete with payload data.

### Socket Buffering
- Explicit TCP buffer sizing on accepted sockets can help prevent stalls when relaying larger responses. Pair this with `set_nodelay(true)` (already present) to keep latency predictable.

### Logging Overhead
- High-volume `eprintln!` calls in the hot path can introduce noise. Prefer structured logging via `tracing` with debug-level filtering during profiling runs.

These recommendations keep the KCP-based path lean while preserving the existing protocol framing.
