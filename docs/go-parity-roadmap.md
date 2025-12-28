# Rust-to-Go Parity Roadmap

This roadmap lists the concrete steps required to bring the Rust implementation in line with the Go reference. Each milestone includes acceptance criteria (AC) to confirm compatibility and latency alignment.

## Milestone 1: QUIC handshake compatibility
- Enable the Go ALPN value `bridgefall-paniq` on both client and server QUIC endpoints.
- Apply Go default transport timers (20s keep-alive, 2m idle timeout) or profile overrides.
- AC: Rust client can establish a QUIC connection to the Go proxy using ALPN `bridgefall-paniq` without negotiation errors.

## Milestone 2: Proxy request/reply parity
- Match the Go proxy framing: client sends versioned request and waits for a versioned reply with status and bind address.
- Server returns success/failure replies before starting data relay.
- AC: Rust SOCKS5 daemon waits for a successful proxy reply (status 0) and surfaces errors on non-zero statuses, mirroring Go behavior.

## Milestone 3: Transport sizing alignment
- Derive transport timeouts, packet sizing, and path MTU behavior from the profile to mirror Go defaults (keep-alive, idle, max payload, max packet).
- AC: QUIC transport configuration in Rust reflects profile values or Go defaults when absent, matching the reference assumptions.

## Milestone 4: Connection lifecycle resilience
- Add pooled/reconnectable QUIC connections on the client side, closing the UDP socket when reconnecting.
- AC: QUIC stream opens transparently recover after a dropped connection without restarting the SOCKS5 daemon.

## Milestone 5: Metrics and padding parity
- Thread profile padding/replay settings into transport sizing and logging to maintain MTU-safe payload budgets.
- AC: Effective payload calculations match Go logs, and padding/replay limits are enforced during transfers.

## Milestone 6: Upstream dialing behavior
- Implement Happy Eyeballs style racing with bounded dial windows and explicit success/failure replies.
- AC: Upstream dial latency matches Go reference within expected RTTs, and proxy replies report failures consistently.

## Milestone 7: Logging and observability alignment
- Gate verbose logging behind flags and mirror Go metrics for handshake latency, reconnects, and bytes transferred.
- AC: Comparable metrics output exists in Rust and can be scraped/tested alongside the Go implementation.

## Execution status
- Milestones 1–3 implemented in this iteration (ALPN, proxy reply handshake, profile-driven transport defaults).
- Milestones 4–7 remain to be implemented in follow-up work.
