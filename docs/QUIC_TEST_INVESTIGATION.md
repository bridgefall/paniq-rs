# SOCKS5 QUIC Integration Test Investigation

## Problem

Both `integration_socks5_over_quic` and `soak_socks5_over_quic_30s` tests fail with client read timeout.

## Root Cause

The issue is a fundamental deadlock with `quinn::SendStream::finish()`:

1. When the HTTP server closes after sending response, proxy's target→client task exits read loop
2. Task calls `send.finish().await` to send FIN frame
3. **`finish()` blocks waiting for client to ACK all sent data**
4. But client is waiting to READ the response
5. Client won't ACK until it receives the FIN from `finish()`
6. **Circular dependency: finish() waits for ACK, client waits for FIN**

## Investigation Summary

### Compared Go vs Rust Implementation

**Go (`quic-go`):**
- Uses `defer stream.Close()` which queues FIN and returns immediately (non-blocking)
- Stream cleanup happens automatically when handler returns

**Rust (`quinn`):**
- `SendStream::finish().await` blocks until all data is ACKed
- Dropping `SendStream` calls `reset()` (aborts), not graceful close

### Solutions Attempted

1. **Spawn finish() in background** ❌
   - Client couldn't read because FIN never sent before stream dropped

2. **Use timeout on finish()** ❌
   - When timeout expires, same issue - no FIN sent

3. **Use tokio::select! (first error)** ❌
   - Task exits before data delivered

4. **Use tokio::try_join! (both complete)** ✅ **Partially works**
   - Structure: two async blocks running concurrently
   - `client_to_target`: QUIC → Target
   - `target_to_client`: Target → QUIC, then `finish().await`
   - **Current status**: Works with `println!` debugging (8/9 iterations in soak test)
   - **Fails without println!** - suggests race condition or task scheduling issue

5. **Add tokio::task::yield_now()** ❌
   - Attempted to replace println's task-yielding effect
   - Still fails

## Current State

The `try_join!` approach from the production proxy server is structurally correct, but test implementation has subtle issue:

- Works intermittently with debug logging
- Fails consistently without logging
- Suggests timing-dependent bug or race condition

## Open Questions

1. **Why does println! make it work?**
   - Not just task yielding (tried `yield_now()`)
   - Possibly stdout flushing triggers different async runtime behavior?

2. **Is there a Quinn API difference from production code?**
   - Production proxy uses identical pattern
   - But runs in real server context with different lifecycle

3. **Should we match Go's non-blocking semantics differently?**
   - Perhaps need custom Drop impl or different stream management?

## Recommendation

Need user input on direction:

**Option A**: Continue debugging race condition
- Add more instrumentation
- Compare exact timing with production proxy
- Risk: May be chasing compiler/runtime undefined behavior

**Option B**: Restructure test to match production exactly
- Use real server/client binaries instead of embedded test proxy
- Pro: Guaranteed to work like production
- Con: More complex test setup

**Option C**: Accept blocking finish() with longer timeout
- Set very long timeout (30s+) as safety net
- Ship with known limitation documented
- Risk: May hide real production issues
