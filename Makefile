# paniq-rs Makefile
# Bridgefall Secure Proxy System - Rust Implementation

# Variables
CARGO := cargo
FEATURES_QUIC := quic
FEATURES_SOCKS5 := socks5
FEATURES_RCGEN := rcgen
FEATURES_ALL := quic socks5 rcgen
FEATURES_FULL := --features "quic,socks5,rcgen"

# Binaries
BIN_PROXY_SERVER := proxy-server
BIN_SOCKS5D := socks5d
BIN_GEN_CERT := gen_test_cert
BINS := $(BIN_PROXY_SERVER) $(BIN_SOCKS5D) $(BIN_GEN_CERT)

# Test names
TEST_ROUNDTRIP := quic_round_trip_over_obfuscating_socket
TEST_HANDSHAKE := quic_handshake
TEST_INTEGRATION_QUIC := integration_socks5_quic
TEST_INTEGRATION_REALISTIC := integration_socks5_realistic
TEST_GOLDEN := golden_vectors
TEST_PARITY := go_parity

# Directories
TARGET_DEBUG := target/debug
TARGET_RELEASE := target/release

# Colors for output
COLOR_RESET := \033[0m
COLOR_BOLD := \033[1m
COLOR_GREEN := \033[32m
COLOR_YELLOW := \033[33m
COLOR_BLUE := \033[34m

.PHONY: all
all: build

## ============================================================================
## Build Targets
## ============================================================================

.PHONY: build
build: $(BINS)

.PHONY: build-debug
build-debug: $(BINS)

.PHONY: build-release
build-release:
	@echo "$(COLOR_BLUE)Building release binaries...$(COLOR_RESET)"
	$(CARGO) build --release $(FEATURES_FULL)

.PHONY: $(BIN_PROXY_SERVER)
$(BIN_PROXY_SERVER):
	@echo "$(COLOR_GREEN)Building $(BIN_PROXY_SERVER)...$(COLOR_RESET)"
	$(CARGO) build --bin $(BIN_PROXY_SERVER) --features "quic,rcgen"

.PHONY: $(BIN_SOCKS5D)
$(BIN_SOCKS5D):
	@echo "$(COLOR_GREEN)Building $(BIN_SOCKS5D)...$(COLOR_RESET)"
	$(CARGO) build --bin $(BIN_SOCKS5D) --features "socks5,quic,rcgen"

.PHONY: $(BIN_GEN_CERT)
$(BIN_GEN_CERT):
	@echo "$(COLOR_GREEN)Building $(BIN_GEN_CERT)...$(COLOR_RESET)"
	$(CARGO) build --bin $(BIN_GEN_CERT) --features "rcgen"

## ============================================================================
## Test Targets
## ============================================================================

.PHONY: test
test: test-unit test-integration

.PHONY: test-unit
test-unit:
	@echo "$(COLOR_BLUE)Running unit tests...$(COLOR_RESET)"
	$(CARGO) test --lib

.PHONY: test-integration
test-integration: test-quic test-socks5

.PHONY: test-all
test-all:
	@echo "$(COLOR_BLUE)Running all tests...$(COLOR_RESET)"
	$(CARGO) test --all-targets $(FEATURES_FULL)

# QUIC-specific tests
.PHONY: test-quic
test-quic: test-roundtrip test-handshake

.PHONY: test-roundtrip
test-roundtrip:
	@echo "$(COLOR_BLUE)Running QUIC roundtrip test...$(COLOR_RESET)"
	$(CARGO) test --test quic_roundtrip --features "quic,rcgen" $(TEST_ROUNDTRIP)

.PHONY: test-handshake
test-handshake:
	@echo "$(COLOR_BLUE)Running QUIC handshake test...$(COLOR_RESET)"
	$(CARGO) test --test quic_handshake --features "quic,rcgen"

# SOCKS5 integration tests
.PHONY: test-socks5
test-socks5: test-socks5-quic test-socks5-realistic

.PHONY: test-socks5-quic
test-socks5-quic:
	@echo "$(COLOR_BLUE)Running SOCKS5 QUIC integration test...$(COLOR_RESET)"
	$(CARGO) test --test $(TEST_INTEGRATION_QUIC) --features "socks5,quic,rcgen"

.PHONY: test-socks5-realistic
test-socks5-realistic:
	@echo "$(COLOR_BLUE)Running SOCKS5 realistic integration test...$(COLOR_RESET)"
	$(CARGO) test --test $(TEST_INTEGRATION_REALISTIC) --features "socks5,quic,rcgen"

# Other tests
.PHONY: test-golden
test-golden:
	@echo "$(COLOR_BLUE)Running golden vectors test...$(COLOR_RESET)"
	$(CARGO) test --test $(TEST_GOLDEN)

.PHONY: test-parity
test-parity:
	@echo "$(COLOR_BLUE)Running Go parity test...$(COLOR_RESET)"
	$(CARGO) test --test $(TEST_PARITY) --features "quic,rcgen"

# Test with verbose output
.PHONY: test-verbose
test-verbose:
	$(CARGO) test --all-targets $(FEATURES_FULL) -- --nocapture

# Test with output
.PHONY: test-output
test-output:
	$(CARGO) test --all-targets $(FEATURES_FULL) -- --show-output

## ============================================================================
## Development Targets
## ============================================================================

.PHONY: fmt
fmt:
	@echo "$(COLOR_BLUE)Formatting code...$(COLOR_RESET)"
	$(CARGO) fmt

.PHONY: fmt-check
fmt-check:
	@echo "$(COLOR_BLUE)Checking code format...$(COLOR_RESET)"
	$(CARGO) fmt -- --check

.PHONY: clippy
clippy:
	@echo "$(COLOR_BLUE)Running Clippy lints...$(COLOR_RESET)"
	$(CARGO) clippy --all-targets $(FEATURES_FULL)

.PHONY: clippy-fix
clippy-fix:
	@echo "$(COLOR_BLUE)Running Clippy with auto-fix...$(COLOR_RESET)"
	$(CARGO) clippy --all-targets $(FEATURES_FULL) --fix

.PHONY: check
check:
	@echo "$(COLOR_BLUE)Running cargo check...$(COLOR_RESET)"
	$(CARGO) check --all-targets $(FEATURES_FULL)

.PHONY: doc
doc:
	@echo "$(COLOR_BLUE)Generating documentation...$(COLOR_RESET)"
	$(CARGO) doc --no-deps $(FEATURES_FULL)

.PHONY: doc-open
doc-open:
	@echo "$(COLOR_BLUE)Opening documentation in browser...$(COLOR_RESET)"
	$(CARGO) doc --no-deps $(FEATURES_FULL) --open

.PHONY: clean
clean:
	@echo "$(COLOR_BLUE)Cleaning build artifacts...$(COLOR_RESET)"
	$(CARGO) clean

.PHONY: help
help:
	@echo "$(COLOR_BOLD)paniq-rs Makefile$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_GREEN)Build Targets:$(COLOR_RESET)"
	@echo "  make build              - Build all debug binaries"
	@echo "  make build-release      - Build all release binaries"
	@echo "  make proxy-server       - Build proxy-server binary"
	@echo "  make socks5d            - Build socks5d binary"
	@echo "  make gen_test_cert      - Build gen_test_cert binary"
	@echo ""
	@echo "$(COLOR_GREEN)Test Targets:$(COLOR_RESET)"
	@echo "  make test               - Run all tests"
	@echo "  make test-unit          - Run unit tests only"
	@echo "  make test-integration   - Run integration tests only"
	@echo "  make test-all           - Run all tests with all features"
	@echo ""
	@echo "  $(COLOR_YELLOW)QUIC Tests:$(COLOR_RESET)"
	@echo "  make test-quic          - Run all QUIC tests"
	@echo "  make test-roundtrip     - Run QUIC roundtrip test"
	@echo "  make test-handshake     - Run QUIC handshake test"
	@echo ""
	@echo "  $(COLOR_YELLOW)SOCKS5 Tests:$(COLOR_RESET)"
	@echo "  make test-socks5        - Run all SOCKS5 tests"
	@echo "  make test-socks5-quic   - Run SOCKS5 QUIC integration test"
	@echo "  make test-socks5-realistic - Run SOCKS5 realistic integration test"
	@echo ""
	@echo "$(COLOR_GREEN)Development:$(COLOR_RESET)"
	@echo "  make fmt                - Format code"
	@echo "  make fmt-check          - Check code formatting"
	@echo "  make clippy             - Run Clippy linter"
	@echo "  make clippy-fix         - Run Clippy with auto-fix"
	@echo "  make check              - Run cargo check"
	@echo "  make doc                - Generate documentation"
	@echo "  make doc-open           - Open documentation in browser"
	@echo "  make clean              - Clean build artifacts"
	@echo ""
	@echo "$(COLOR_GREEN)Utilities:$(COLOR_RESET)"
	@echo "  make help               - Show this help message"
	@echo ""
	@echo "$(COLOR_GREEN)Examples:$(COLOR_RESET)"
	@echo "  make build && make test"
	@echo "  make clippy && make test-all"
	@echo "  make fmt-check && make check"
	@echo ""

## ============================================================================
## Installation Targets
## ============================================================================

.PHONY: install
install: build-release
	@echo "$(COLOR_BLUE)Installing release binaries...$(COLOR_RESET)"
	$(CARGO) install --path . $(FEATURES_FULL)

.PHONY: install-debug
install-debug: build
	@echo "$(COLOR_BLUE)Installing debug binaries...$(COLOR_RESET)"
	$(CARGO) install --path . $(FEATURES_FULL)

## ============================================================================
## Feature-Specific Builds
## ============================================================================

.PHONY: build-quic
build-quic:
	$(CARGO) build --features "quic,rcgen"

.PHONY: build-socks5
build-socks5:
	$(CARGO) build --features "socks5,quic,rcgen"

## ============================================================================
## Watch/Development Helpers
## ============================================================================

.PHONY: watch
watch:
	@echo "$(COLOR_BLUE)Watching for changes...$(COLOR_RESET)"
	$(CARGO) watch --test $(FEATURES_FULL)

.PHONY: watch-build
watch-build:
	@echo "$(COLOR_BLUE)Watching for build changes...$(COLOR_RESET)"
	$(CARGO) watch --build $(FEATURES_FULL)

.PHONY: run-proxy-server
run-proxy-server: build
	@echo "$(COLOR_BLUE)Running proxy-server...$(COLOR_RESET)"
	$(TARGET_DEBUG)/$(BIN_PROXY_SERVER) --profile test_profile_gen.json

.PHONY: run-socks5d
run-socks5d: build
	@echo "$(COLOR_BLUE)Running socks5d...$(COLOR_RESET)"
	$(TARGET_DEBUG)/$(BIN_SOCKS5D) --profile test_profile_gen.json
