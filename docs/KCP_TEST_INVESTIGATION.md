# SOCKS5 KCP Integration Test Investigation

The previous integration test failures have been replaced by KCP-backed coverage. Current checklist:

- `integration_socks5_kcp`: Exercises the SOCKS5 daemon, KCP transport, and proxy against the in-process HTTP server.
- `integration_socks5_realistic`: Runs a 30-second soak using repeated HTTP GETs to validate stability under sustained load.

Observations:
- Framed request/response handling remains stable when the proxy dials upstream targets.
- Loss and reorder tolerance comes from the KCP session; keep `nodelay` and window settings aligned with profile expectations during soak runs.

If regressions reappear, capture logs from both daemons with `RUST_LOG=debug` and rerun the soak harness to surface timing issues.
