# paniq-rs Makefile
# Bridgefall Secure Proxy System - Rust Implementation

# Variables
# Use rustup-installed cargo if available, otherwise fall back to PATH
CARGO := $(shell [ -f "$(HOME)/.cargo/bin/cargo" ] && echo "$(HOME)/.cargo/bin/cargo" || echo "cargo")
FEATURES_KCP := kcp
FEATURES_SOCKS5 := socks5
FEATURES_RCGEN :=
FEATURES_ALL := kcp socks5
FEATURES_FULL := --features "kcp,socks5"

# Binaries
BIN_PROXY_SERVER := proxy-server
BIN_SOCKS5D := socks5d
BIN_GEN_CERT := gen_test_cert
BINS := $(BIN_PROXY_SERVER) $(BIN_SOCKS5D) $(BIN_GEN_CERT)

# Test names
TEST_ROUNDTRIP := kcp_round_trip_over_obfuscating_socket
TEST_INTEGRATION_KCP := integration_socks5_kcp
TEST_INTEGRATION_REALISTIC := integration_socks5_realistic
TEST_GOLDEN := golden_vectors

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
	$(CARGO) build --bin $(BIN_PROXY_SERVER) --features "kcp"

.PHONY: $(BIN_SOCKS5D)
$(BIN_SOCKS5D):
	@echo "$(COLOR_GREEN)Building $(BIN_SOCKS5D)...$(COLOR_RESET)"
	$(CARGO) build --bin $(BIN_SOCKS5D) --features "socks5,kcp"

.PHONY: $(BIN_GEN_CERT)
$(BIN_GEN_CERT):
	@echo "$(COLOR_GREEN)Building $(BIN_GEN_CERT)...$(COLOR_RESET)"
	$(CARGO) build --bin $(BIN_GEN_CERT)

## ============================================================================
## Test Targets
## ============================================================================

.PHONY: test
test: test-unit test-integration

.PHONY: test-unit
test-unit:
	@echo "$(COLOR_BLUE)Running unit tests...$(COLOR_RESET)"
	$(CARGO) test --lib $(FEATURES_FULL)

.PHONY: test-integration
test-integration: test-kcp
# Note: test-socks5 disabled - tests use old API and are marked with #[ignore]

.PHONY: test-all
test-all:
	@echo "$(COLOR_BLUE)Running all tests...$(COLOR_RESET)"
	$(CARGO) test --all-targets $(FEATURES_FULL)

# KCP-specific tests
.PHONY: test-kcp
test-kcp: test-roundtrip

.PHONY: test-roundtrip
test-roundtrip:
	@echo "$(COLOR_BLUE)Running KCP roundtrip test...$(COLOR_RESET)"
	$(CARGO) test --test kcp_roundtrip --features "kcp" $(TEST_ROUNDTRIP)

# SOCKS5 integration tests
.PHONY: test-socks5
test-socks5: test-socks5-kcp test-socks5-realistic

.PHONY: test-socks5-kcp
test-socks5-kcp:
	@echo "$(COLOR_BLUE)Running SOCKS5 KCP integration test...$(COLOR_RESET)"
	$(CARGO) test --test $(TEST_INTEGRATION_KCP) --features "socks5,kcp"

.PHONY: test-socks5-realistic
test-socks5-realistic:
	@echo "$(COLOR_BLUE)Running SOCKS5 realistic integration test...$(COLOR_RESET)"
	$(CARGO) test --test $(TEST_INTEGRATION_REALISTIC) --features "socks5,kcp"

# Other tests
.PHONY: test-golden
test-golden:
	@echo "$(COLOR_BLUE)Running golden vectors test...$(COLOR_RESET)"
	$(CARGO) test --test $(TEST_GOLDEN)

# Soak tests (long-running stress tests)
# Usage: make test-soak SOAK_SECS=60  (default: 30 seconds)
.PHONY: test-soak
test-soak:
	@echo "$(COLOR_BLUE)Running soak tests ($(SOAK_SECS)s)...$(COLOR_RESET)"
	$(CARGO) test --test $(TEST_INTEGRATION_KCP) --features "socks5,kcp" soak_socks5_over_kcp_30s -- --nocapture


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
	@echo "  $(COLOR_YELLOW)KCP Tests:$(COLOR_RESET)"
	@echo "  make test-kcp           - Run all KCP tests"
	@echo "  make test-roundtrip     - Run KCP roundtrip test"
	@echo ""
	@echo "  $(COLOR_YELLOW)SOCKS5 Tests:$(COLOR_RESET)"
	@echo "  make test-socks5        - Run all SOCKS5 tests"
	@echo "  make test-socks5-kcp    - Run SOCKS5 KCP integration test"
	@echo "  make test-socks5-realistic - Run SOCKS5 realistic integration test"
	@echo ""
	@echo "  $(COLOR_YELLOW)Soak Tests:$(COLOR_RESET)"
	@echo "  make test-soak          - Run soak test (default: 30s)"
	@echo "  make test-soak SOAK_SECS=60 - Run 60-second soak test"
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
	@echo "$(COLOR_GREEN)Installation (Debian):$(COLOR_RESET)"
	@echo "  make install-debian      - Full installation on Debian (requires sudo)"
	@echo "  make uninstall-debian    - Full uninstallation on Debian (requires sudo)"
	@echo "  make test-install-debian - Test installation in Docker"
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
## Debian Installation
## ============================================================================

.PHONY: install-deps-debian
install-deps-debian:
	@echo "$(COLOR_BLUE)Installing dependencies...$(COLOR_RESET)"
	@set -e; \
	apt-get update; \
	apt-get install -y curl jq build-essential pkg-config libssl-dev; \
	if ! command -v cargo >/dev/null 2>&1; then \
		echo "Installing Rust via rustup..."; \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
		export PATH="$$HOME/.cargo/bin:$$PATH"; \
	fi

.PHONY: gen-profile
gen-profile:
	@echo "$(COLOR_BLUE)Generating profile...$(COLOR_RESET)"
	@set -e; \
	IP=$$(curl -s https://ifconfig.me); \
	if [ -z "$$IP" ]; then \
		echo "failed to fetch public ip" >&2; \
		exit 1; \
	fi; \
	$(TARGET_RELEASE)/paniq-ctl create-profile --mtu 1420 --proxy-addr "$$IP:9001" > profile.json

.PHONY: install-proxy-systemd
install-proxy-systemd: gen-profile
	@echo "$(COLOR_BLUE)Installing paniq-rs-proxy systemd unit + default configs...$(COLOR_RESET)"
	@set -e; \
	if [ "$$(id -u)" -ne 0 ]; then \
		echo "run as root (e.g. sudo make install-proxy-systemd)" >&2; \
		exit 1; \
	fi; \
	install -d /etc/bridgefall-rs; \
	install -m 0644 docs/examples/paniq-rs-proxy.json /etc/bridgefall-rs/paniq-rs-proxy.json; \
	install -m 0644 profile.json /etc/bridgefall-rs/profile.json; \
	install -m 0644 systemd/paniq-rs-proxy.service /etc/systemd/system/paniq-rs-proxy.service; \
	install -m 0755 $(TARGET_RELEASE)/proxy-server /usr/local/bin/paniq-rs-proxy; \
	install -m 0755 $(TARGET_RELEASE)/paniq-ctl /usr/local/bin/paniq-rs-ctl; \
	$(TARGET_RELEASE)/paniq-ctl profile-cbor --base64 < /etc/bridgefall-rs/profile.json > /etc/bridgefall-rs/client.txt; \
	chmod 644 /etc/bridgefall-rs/client.txt; \
	systemctl daemon-reload; \
	systemctl enable --now paniq-rs-proxy.service; \
	echo "==> paniq-rs-proxy enabled and started"; \
	echo "==> client connection string saved to /etc/bridgefall-rs/client.txt"

.PHONY: install-debian
install-debian: install-deps-debian build-release install-proxy-systemd

.PHONY: uninstall-debian
uninstall-debian:
	@echo "$(COLOR_BLUE)Uninstalling paniq-rs-proxy systemd unit + configs...$(COLOR_RESET)"
	@set -e; \
	if [ "$$(id -u)" -ne 0 ]; then \
		echo "run as root (e.g. sudo make uninstall-debian)" >&2; \
		exit 1; \
	fi; \
	systemctl disable --now paniq-rs-proxy.service || true; \
	rm -f /etc/systemd/system/paniq-rs-proxy.service; \
	rm -f /usr/local/bin/paniq-rs-proxy; \
	rm -f /usr/local/bin/paniq-rs-ctl; \
	rm -rf /etc/bridgefall-rs; \
	systemctl daemon-reload; \
	echo "==> paniq-rs-proxy disabled and removed"

.PHONY: test-install-debian
test-install-debian:
	@echo "$(COLOR_BLUE)Testing installation in Docker...$(COLOR_RESET)"
	docker build -f Dockerfile.test-install -t paniq-rs-install-test .
	@echo "$(COLOR_GREEN)Installation test successful!$(COLOR_RESET)"

## ============================================================================
## Feature-Specific Builds
## ============================================================================

.PHONY: build-socks5
build-socks5:
	$(CARGO) build --features "socks5,kcp,rcgen"

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
# Target to build Android libraries
.PHONY: build-android
build-android:
	@echo "$(COLOR_BLUE)Building Android libraries...$(COLOR_RESET)"
	cargo ndk -t arm64-v8a -t armeabi-v7a -o dist/android/jniLibs build --release --features mobile

# Target to generate UniFFI Kotlin bindings
.PHONY: uniffi-gen-kotlin
uniffi-gen-kotlin:
	@echo "$(COLOR_BLUE)Generating UniFFI Kotlin bindings...$(COLOR_RESET)"
	cargo run --bin uniffi-bindgen --features mobile generate --library target/release/libpaniq.so --language kotlin --out-dir dist/android/kotlin
