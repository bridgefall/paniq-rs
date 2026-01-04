# Testing Guide

This document describes the testing frameworks and strategies used in paniq-rs.

## Overview

paniq-rs uses a multi-layered testing approach:

| Layer | Location | Purpose | Speed |
|-------|----------|---------|-------|
| Unit | `src/*/tests.rs` | Test individual functions and modules | Fast (ms) |
| Golden Vectors | `tests/golden_vectors.rs` | Validate cryptographic correctness | Fast (ms) |
| Integration | `tests/integration_socks5_kcp.rs` | Full stack with production code | Medium (s) |
| Realistic | `tests/integration_socks5_realistic.rs` | Test against actual binaries | Slow (10s+) |
| Soak | `tests/integration_socks5_kcp.rs` | Long-running stability tests | Slow (10s+) |
| Benchmark | `tests/benchmark_transfer.rs` | Measure throughput performance | Slow (s) |

## Test Structure

```
paniq-rs/
├── src/
│   ├── obf/tests.rs              # Unit tests for obfuscation
│   ├── envelope/tests.rs         # Unit tests for envelope protocol
│   ├── socks5/tests.rs           # Unit tests for SOCKS5
│   └── ...
└── tests/
    ├── golden_vectors.rs         # Golden vector tests
    ├── kcp_roundtrip.rs          # KCP transport roundtrip
    ├── integration_socks5_kcp.rs # Full stack integration
    ├── integration_socks5_realistic.rs  # Binary integration tests
    ├── benchmark_transfer.rs     # Performance benchmarks
    └── support/
        ├── mod.rs
        └── harness.rs            # Test harness utilities
```

---

## 1. Unit Tests

Unit tests are located alongside the code they test in `src/*/tests.rs` files.

### Running Unit Tests

```bash
# Run all unit tests
cargo test --lib

# Run specific module tests
cargo test --lib obf::tests
cargo test --lib envelope::tests
cargo test --lib socks5::tests

# Run with output
cargo test --lib -- --nocapture

# Run with logs
RUST_LOG=debug cargo test --lib
```

### Examples

**Obfuscation tests** (`src/obf/tests.rs`):
- `bytes_obf_matches_input` - Byte obfuscation roundtrip
- `chain_obfuscates_in_order` - Chain obfuscation correctness
- `header_range_validates` - Header range validation
- `framer_round_trip` - Framer encoding/decoding

**Envelope tests** (`src/envelope/tests.rs`):
- `padding_policy_respects_bounds` - Padding size constraints
- `mac1_computes_and_verifies` - MAC1 correctness
- `client_server_handshake_cycle` - Handshake protocol
- `transport_round_trip` - Transport layer roundtrip
- `encrypted_timestamp_cycle` - Timestamp encryption
- `replay_cache_blocks_duplicate` - Replay protection

**SOCKS5 tests** (`src/socks5/tests.rs`):
- `socks5_no_auth_roundtrip` - SOCKS5 without authentication
- `socks5_userpass_success` - SOCKS5 with username/password
- `socks5_rejects_bad_method` - Method rejection

---

## 2. Golden Vector Tests

Golden vector tests validate cryptographic operations against known good values.

### Location
`tests/golden_vectors.rs`

### Test Data

Test vectors are stored in `tests/vectors/`:
- `chain.json` - Obfuscation chain vectors
- `frame.json` - Framed packet vectors
- `mac1.json` - MAC1 computation vectors
- `transport.json` - Transport payload vectors
- `timestamp.json` - Encrypted timestamp vectors

### Running Golden Vector Tests

```bash
# Run all golden vector tests
cargo test --test golden_vectors --features kcp

# Run specific test
cargo test --test golden_vectors test_chain_vectors --features kcp
```

### Test Categories

- `test_chain_vectors` - Obfuscation chain roundtrips
- `test_frame_vectors` - Framed packet encoding
- `test_transport_vectors` - Transport payload encoding
- `test_mac1_vectors` - MAC1 computation
- `test_timestamp_vectors` - Encrypted timestamps

---

## 3. Integration Tests

Integration tests exercise the full proxy stack using production code paths from `src/runtime/`.

### Location
`tests/integration_socks5_kcp.rs`

### Architecture

These tests use the `StackHarness` from `tests/support/harness.rs` which spawns:
- A KCP proxy server (`ProxyHandle` from `src/runtime/proxy.rs`)
- A SOCKS5 server (`SocksHandle` from `src/runtime/socks.rs`)

Both servers use **production code**, not mocks.

### Running Integration Tests

```bash
# Run all integration tests
cargo test --test integration_socks5_kcp --features kcp,socks5

# Run specific test
cargo test --test integration_socks5_kcp integration_socks5_over_kcp --features kcp,socks5

# Run with output
cargo test --test integration_socks5_kcp --features kcp,socks5 -- --nocapture

# Run with logs
RUST_LOG=debug cargo test --test integration_socks5_kcp --features kcp,socks5
```

### Test Cases

| Test | Description | Duration |
|------|-------------|----------|
| `integration_socks5_over_kcp` | Full roundtrip: SOCKS5 → KCP → proxy → HTTP | ~100ms |
| `soak_socks5_over_kcp_30s` | Repeated connections over 10s (configurable) | ~10s |
| `lifecycle_repeated_setup_teardown` | Repeated server start/stop cycles | Variable |

### Configuration

Environment variables for test tuning:

```bash
# Soak test duration (default: 10 seconds)
SOAK_SECS=30 cargo test soak_socks5_over_kcp_30s --features kcp,socks5

# Lifecycle iterations (default: 10)
LIFECYCLE_ITERATIONS=20 cargo test lifecycle_repeated_setup_teardown --features kcp,socks5
```

### Timing Constants

Tests use named constants for timing (see `integration_socks5_kcp.rs`):

```rust
const SERVER_STARTUP_DELAY_MS: u64 = 100;      // Time for servers to start
const STREAM_SHUTDOWN_DELAY_MS: u64 = 10;      // Smux stream cleanup time
const SOAK_CLEANUP_DELAY_MS: u64 = 50;         // Longer delay for soak tests
const MAX_END_TO_END_LATENCY: Duration = 1s;   // Performance threshold
```

---

## 4. Realistic Integration Tests

These tests spin up actual proxy and SOCKS5 binaries and test them as black boxes.

### Location
`tests/integration_socks5_realistic.rs`

### Running Realistic Tests

```bash
# Run realistic integration tests
cargo test --test integration_socks5_realistic --features kcp,socks5

# Run with logs
RUST_LOG=info cargo test --test integration_socks5_realistic --features kcp,socks5 -- --nocapture
```

### What It Tests

- Binary spawning and lifecycle
- Profile loading from JSON files
- Inter-process communication over TCP
- Real-world connection patterns

**Note**: These tests are slower and more resource-intensive than the in-process integration tests.

---

## 5. KCP Roundtrip Tests

Tests the KCP transport layer directly over obfuscated UDP.

### Location
`tests/kcp_roundtrip.rs`

### Running KCP Roundtrip Tests

```bash
cargo test --test kcp_roundtrip --features kcp
```

### What It Tests

- KCP client/server handshake
- Bidirectional stream multiplexing (smux)
- Data transmission over obfuscated UDP
- Stream open/close semantics

---

## 6. Performance Benchmarks

Benchmarks measure actual throughput through the full proxy stack.

### Location
`tests/benchmark_transfer.rs`

### Running Benchmarks

```bash
# Run all benchmarks
cargo test --test benchmark_transfer --features kcp,socks5 -- --nocapture

# Run specific benchmark
cargo test --test benchmark_transfer benchmark_smoke --features kcp,socks5 -- --nocapture
cargo test --test benchmark_transfer benchmark_transfer_small --features kcp,socks5 -- --nocapture
cargo test --test benchmark_transfer benchmark_transfer_medium --features kcp,socks5 -- --nocapture

# Run large benchmark (100 MB) - requires --ignored
cargo test --test benchmark_transfer benchmark_transfer_large --features kcp,socks5 -- --nocapture --ignored
```

### For Release Performance

```bash
# Run benchmarks with release optimizations
cargo test --release --test benchmark_transfer --features kcp,socks5 -- --nocapture
```

### Benchmark Test Cases

| Test | Size | Iterations | Purpose |
|------|------|------------|---------|
| `benchmark_smoke` | 1 MB | 1 | Quick sanity check |
| `benchmark_transfer_small` | 10 MB | 3 | Standard throughput test |
| `benchmark_transfer_medium` | 50 MB | 3 | Sustained throughput |
| `benchmark_transfer_large` | 100 MB | 3 | Max throughput (manual) |

### Example Output

```
=== Small File Transfer Benchmark ===
Test size: 10.00 MB
Iterations: 3
  Iteration 1/3: 10.00 MB in 0.16s = 62.31 MB/s
  Iteration 2/3: 10.00 MB in 0.15s = 64.62 MB/s
  Iteration 3/3: 10.00 MB in 0.15s = 67.14 MB/s

Results:
  Total transferred: 30.00 MB
  Average throughput: 64.63 MB/s
  Min iteration time: 0.15s
  Max iteration time: 0.16s
```

### Performance Expectations

With current optimizations (32KB buffers + TCP_NODELAY):
- **Target**: ~70 MB/s (matching Go implementation)
- **Minimum**: ~10 MB/s (triggers warning)
- **Debug builds**: ~60-65 MB/s
- **Release builds**: ~100+ MB/s

---

## 7. Test Support Utilities

### Location
`tests/support/`

#### `harness.rs`

Provides `StackHarness` for spawning production servers:

```rust
pub struct StackHarness {
    pub proxy: ProxyHandle,    // KCP proxy server
    pub socks: SocksHandle,    // SOCKS5 server
}

impl StackHarness {
    pub async fn spawn(
        proxy_listen_addr: SocketAddr,
        socks_listen_addr: SocketAddr,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // ...
    }

    pub fn socks_addr(&self) -> SocketAddr {
        self.socks.addr
    }
}
```

---

## Running All Tests

### Quick Test (Unit + Integration)

```bash
# Run all tests except benchmarks and realistic tests
cargo test --features kcp,socks5
```

### Full Test Suite

```bash
# Run everything (including slow tests)
cargo test --features kcp,socks5
cargo test --test integration_socks5_realistic --features kcp,socks5
```

### With Makefile

```bash
# Run all library tests
make test-lib

# Run integration tests
make test-integration

# Run golden vector tests
make test-golden

# Run KCP roundtrip tests
make test-kcp

# Run everything
make test-all
```

---

## Test Feature Flags

| Feature | Tests Enabled | Components |
|---------|---------------|------------|
| `kcp` | KCP transport tests | KCP client/server, smux |
| `socks5` | SOCKS5 tests | SOCKS5 server, authentication |
| `kcp,socks5` | Full stack tests | All components |

Most integration tests require `--features "kcp,socks5"`.

---

## Writing New Tests

### Unit Test

Add to `src/<module>/tests.rs`:

```rust
#[test]
fn my_test() {
    let result = function_under_test();
    assert_eq!(result, expected);
}
```

### Integration Test

Add to `tests/integration_socks5_kcp.rs`:

```rust
#[tokio::test]
async fn my_integration_test() {
    let harness = StackHarness::spawn(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    ).await.expect("Failed to spawn harness");

    // Use harness.socks_addr() for client connections
    // Test your functionality...

    drop(harness); // Cleanup is automatic
}
```

### Benchmark

Add to `tests/benchmark_transfer.rs`:

```rust
#[tokio::test]
async fn benchmark_my_use_case() {
    run_benchmark("My Use Case", TEST_SIZE_SMALL, 3)
        .await
        .expect("Benchmark failed");
}
```

---

## Troubleshooting

### Test Failures

**"Connection reset by peer" errors during cleanup**:
- Normal during soak test shutdown
- Related to smux stream cleanup timing
- Can be mitigated by increasing `STREAM_SHUTDOWN_DELAY_MS`

**"Address already in use" errors**:
- May indicate a previous test didn't clean up properly
- Check for leaked handles or tasks
- Try running tests sequentially: `cargo test -- --test-threads=1`

**Timeout failures**:
- Increase timeout in test or use `RUST_LOG=debug` to diagnose
- Check system load (tests can be slower on busy systems)

### Performance Issues

**Lower than expected throughput**:
1. Ensure debug vs release builds are appropriate
2. Check for CPU throttling
3. Verify `TCP_NODELAY` is being applied
4. Run with `RUST_LOG=debug` to see relay buffer sizes

### Flaky Tests

If tests are flaky:
1. Run with `--test-threads=1` to eliminate concurrency issues
2. Increase startup/shutdown delays
3. Check for resource leaks (unclosed sockets, etc.)
4. Run with `RUST_BACKTRACE=1` for detailed error traces

---

## CI/CD Integration

Tests run automatically on push/PR via GitHub Actions (`.github/workflows/ci.yml`).

### CI Pipeline

```yaml
- Run unit tests
- Run golden vector tests
- Run integration tests
- Run benchmarks (optional)
```

### Skipping CI

Add `#[ignore]` to skip a test in CI:

```rust
#[tokio::test]
#[ignore]
async fn manual_test() {
    // Only runs with --ignored flag
}
```

Run manually:
```bash
cargo test -- --ignored
```
