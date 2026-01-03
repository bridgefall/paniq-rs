# Logging Style Guide

This document defines the logging conventions for the paniq-rs project. All new code should follow these guidelines, and existing `eprintln!` calls should be migrated to structured logging using `tracing`.

## Log Levels

### ERROR
Unrecoverable failures that impact correctness or require immediate attention.
- Bind/listen failures
- Failed connections after retries
- Fatal relay errors
- Invalid configuration that prevents startup

**Example:**
```rust
error!(
    error = %e,
    peer_addr = %peer_addr,
    "Error handling connection"
);
```

### WARN
Recoverable errors or unexpected conditions that do not terminate the process.
- Invalid client requests (that are handled gracefully)
- Connection timeouts (with retries)
- Protocol mismatches that are handled
- Skipped test conditions

**Example:**
```rust
warn!(
    peer_addr = %conn.peer_addr(),
    reason = %e,
    "Connection error during relay"
);
```

### INFO
High-level lifecycle milestones and important state changes. This is the default level for production.
- Server startup with listen address
- New client connections accepted
- Successful handshakes
- Session closed
- Connection to remote server established

**Example:**
```rust
info!(
    listen_addr = %endpoint.local_addr(),
    "proxy-server listening"
);
```

### DEBUG
Diagnostic context for troubleshooting. Enabled when debugging issues.
- Handshake step details
- Relay negotiation details
- Packet summaries
- Retry loop progress

**Example:**
```rust
debug!(
    target = ?target,
    "Connecting to target"
);
```

### TRACE
Very detailed, high-volume events for deep debugging. Disabled by default even in DEBUG mode.
- Per-frame relay operations
- Per-packet details
- Tight-loop iteration logging
- Byte-level I/O operations

**Example:**
```rust
trace!(
    bytes = n,
    direction = "client_to_target",
    "Read from KCP"
);
```

## Standard Field Names

Use these consistent field names across all modules:

| Field | Type | Description |
|-------|------|-------------|
| `conn_id` | `u64` or `&str` | Unique connection identifier |
| `peer_addr` | `SocketAddr` | Remote peer address (display) |
| `client_addr` | `SocketAddr` | SOCKS client address |
| `target_addr` | `TargetAddr` | Target server address |
| `listen_addr` | `SocketAddr` | Server listen address |
| `server_addr` | `SocketAddr` | Proxy server address |
| `bytes` | `usize` | Byte count for I/O operations |
| `bytes_in` | `u64` | Total bytes received |
| `bytes_out` | `u64` | Total bytes sent |
| `error` / `err` | `impl Display` | Error value |
| `protocol` | `&str` | Protocol name (e.g., "socks5", "kcp") |
| `direction` | `&str` | Data flow direction |
| `duration_ms` | `u64` | Duration in milliseconds |

## Formatting Guidelines

### Use Display formatting (`%`) for user-facing values
```rust
info!(target_addr = %socket_addr, "Connecting to {}", socket_addr);
```

### Use Debug formatting (`?`) for diagnostic values
```rust
debug!(target = ?target_addr, "Parsed target address");
```

### Keep messages short and action-oriented
```rust
// Good
info!(listen_addr = %local_addr, "Server listening");

// Avoid
info!(listen_addr = %local_addr, "The server is now listening on the specified address");
```

### Use spans for connection/session context
```rust
let span = info_span!(
    "conn",
    conn_id = %conn_id,
    peer_addr = %peer_addr
);

let _guard = span.enter();
// All logs in this scope inherit conn_id and peer_addr
```

## Module-Specific Guidelines

### `bin/proxy-server.rs`
- **INFO**: Server startup, connection acceptance, stream acceptance
- **DEBUG**: Target connection attempts
- **TRACE**: Per-byte relay operations (use sparingly)
- **ERROR**: Failed to bind/listen, fatal relay errors

### `bin/socks5d.rs`
- **INFO**: Daemon startup, proxy server connection established
- **DEBUG**: Accepted client connections
- **ERROR**: Failed to bind, proxy server connection failure

### `src/socks5/mod.rs`
- **INFO**: Protocol upgrade, connection to target, success reply
- **DEBUG**: Target address parsing, relay task lifecycle, EOF on normal connection close
- **TRACE**: Individual read/write operations in relay
- **ERROR**: Protocol errors, authentication failures

### Tests
- Use `tracing` with appropriate levels for test diagnostics
- Avoid spamming output; use `DEBUG`/`TRACE` for verbose test logs
- Use `WARN` for skipped test conditions

## Environment Configuration

Logs are filtered via `RUST_LOG` environment variable:

```bash
# Default (INFO and above)
RUST_LOG=info cargo run

# Debug mode
RUST_LOG=debug cargo run

# Trace specific module
RUST_LOG=paniq::socks5=trace cargo run

# Multiple modules
RUST_LOG=paniq::socks5=debug,paniq::kcp=info cargo run
```

## Performance Considerations

1. **Hot paths**: Relay loops should use `TRACE` level for per-packet logging
2. **Allocation**: Prefer static strings and existing types over allocations in log macros
3. **Filtering**: `tracing` is designed to have minimal overhead when logs are filtered out
4. **Structured fields**: Field values are only evaluated if the log level is enabled

## Migration Checklist

When migrating `eprintln!` calls:

- [ ] Select appropriate log level (use decision tree above)
- [ ] Add structured fields for key context
- [ ] Use consistent field names from table above
- [ ] Keep message strings short and stable
- [ ] Consider adding a span for connection/session context
- [ ] Remove the `eprintln!` call
- [ ] Test with `RUST_LOG=debug` to verify output
