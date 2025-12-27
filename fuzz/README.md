# Fuzzing

This directory contains fuzz targets for the paniq-rs library using `cargo-fuzz`.

## Quick Start

Run fuzz using rustup:
```bash
rustup run nightly cargo fuzz run main
```

Or if nightly is your default:
```bash
cargo +nightly fuzz run main
```

## Prerequisites

**Nightly Rust is required** - cargo-fuzz uses unstable compiler flags (`-Zsanitizer=address`).

Install nightly Rust:
```bash
rustup install nightly
rustup component add rust-src --toolchain nightly
cargo install cargo-fuzz
```

## Running Fuzz Targets

Run all fuzz targets:
```bash
rustup run nightly cargo fuzz run main
```

Run specific fuzz targets:
```bash
rustup run nightly cargo fuzz run chain_parser
rustup run nightly cargo fuzz run frame_decoder
rustup run nightly cargo fuzz run payload_decoder
rustup run nightly cargo fuzz run replay_cache
```

## Fuzz Targets

| Target | Description | Location |
|--------|-------------|----------|
| `main` | Exercises all 4 components | All of below |
| `chain_parser` | Fuzzes the obfuscation chain parser | `src/obf/mod.rs` |
| `frame_decoder` | Fuzzes the frame encoder/decoder | `src/obf/framer.rs` |
| `payload_decoder` | Fuzzes transport payload encoding/decoding | `src/envelope/transport.rs` |
| `replay_cache` | Fuzzes replay cache acceptance/rejection | `src/envelope/replay.rs` |

## Running with Coverage

To run with coverage reporting:
```bash
rustup run nightly cargo fuzz coverage main
```

## Stopping Fuzzing

Press `Ctrl+C` to stop. The fuzzer will save interesting test cases to `fuzz/corpus/<target>/`.

## Troubleshooting

**"option `Z` is only accepted on the nightly compiler"**
- Install nightly Rust: `rustup install nightly`
- Use: `rustup run nightly cargo fuzz run <target>`
