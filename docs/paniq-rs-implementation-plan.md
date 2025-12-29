# paniq-rs Implementation Plan (KCP-Only)

## Architecture
```
(TCP client) -> SOCKS5 daemon -> obfuscation/envelope -> KCP over UDP -> proxy server -> TCP upstream
```

Modules:
- `envelope/` and `obf/`: framing, padding, and key handling for UDP datagrams.
- `kcp/`: transport session management, including handshake wiring and framed messaging for proxy requests.
- `socks5/`: connector logic for translating SOCKS5 requests into framed transport messages.
- `bin/`: runnable daemons (`socks5d`, `proxy-server`) that stitch the layers together.

## Phases
1. **Core crypto & framing**: Keep envelope and obfuscation components reusable without the transport feature flags.
2. **Transport integration**: Expose a stable KCP session API that wraps the framer and supports bidirectional relaying for proxy requests.
3. **SOCKS5 integration**: Use the transport API inside the SOCKS5 connector and proxy server, ensuring request/response framing remains backward compatible.
4. **Testing**: Maintain deterministic unit tests plus integration coverage (`kcp_roundtrip`, `integration_socks5_kcp`, and the realistic soak harness).

## Definition of Done
- The project builds with only the `kcp` and `socks5` feature flags.
- SOCKS5 daemon and proxy binaries interoperate over the KCP transport without auxiliary transports or stubs.
- Integration and soak tests exercise the full path against the bundled local HTTP server and remain green.
- Documentation reflects the single-transport design and test coverage.
