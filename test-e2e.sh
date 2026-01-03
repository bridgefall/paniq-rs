#!/bin/bash
set -euo pipefail

# E2E Test Script for KCP Migration Validation
# Tests real proxy-server and socks5d binaries with curl

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Configuration
PROXY_PORT=19000
SOCKS_PORT=11080
PROFILE_PATH="examples/profile.json"
LOG_DIR="$SCRIPT_DIR/e2e-logs"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Log files
PROXY_LOG="$LOG_DIR/proxy-server-$TIMESTAMP.log"
SOCKS_LOG="$LOG_DIR/socks5d-$TIMESTAMP.log"
CURL_LOG="$LOG_DIR/curl-$TIMESTAMP.log"
TEST_LOG="$LOG_DIR/test-$TIMESTAMP.log"

# PID files
PROXY_PID=""
SOCKS_PID=""

# Cleanup function
cleanup() {
    echo "=== Cleanup ===" | tee -a "$TEST_LOG"

    if [ -n "$SOCKS_PID" ] && kill -0 "$SOCKS_PID" 2>/dev/null; then
        echo "Stopping socks5d (PID: $SOCKS_PID)" | tee -a "$TEST_LOG"
        kill "$SOCKS_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$SOCKS_PID" 2>/dev/null || true
    fi

    if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        echo "Stopping proxy-server (PID: $PROXY_PID)" | tee -a "$TEST_LOG"
        kill "$PROXY_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$PROXY_PID" 2>/dev/null || true
    fi

    echo "Cleanup complete" | tee -a "$TEST_LOG"
}

# Set trap for cleanup on exit
trap cleanup EXIT INT TERM

# Create log directory
mkdir -p "$LOG_DIR"

# Ensure binaries are built
echo "=== Building binaries ===" | tee "$TEST_LOG"
cargo build --bin proxy-server --bin socks5d --features "kcp,socks5" 2>&1 | tee -a "$TEST_LOG"
if [ "${PIPESTATUS[0]}" -ne 0 ]; then
    echo "❌ FAILED: Build failed" | tee -a "$TEST_LOG"
    exit 1
fi

# Check if profile exists
if [ ! -f "$PROFILE_PATH" ]; then
    echo "❌ FAILED: Profile not found: $PROFILE_PATH" | tee -a "$TEST_LOG"
    exit 1
fi

# Update profile with our test ports
echo "=== Preparing test profile ===" | tee -a "$TEST_LOG"
TEST_PROFILE="$LOG_DIR/test-profile-$TIMESTAMP.json"
jq ".proxy_addr = \"127.0.0.1:$PROXY_PORT\"" "$PROFILE_PATH" > "$TEST_PROFILE"

echo "=== Starting proxy-server ===" | tee -a "$TEST_LOG"
./target/debug/proxy-server -l "127.0.0.1:$PROXY_PORT" -p "$TEST_PROFILE" > "$PROXY_LOG" 2>&1 &
PROXY_PID=$!
echo "proxy-server PID: $PROXY_PID" | tee -a "$TEST_LOG"

# Wait for proxy to be ready
echo "Waiting for proxy-server to start..." | tee -a "$TEST_LOG"
for i in {1..30}; do
    if grep -q "listening on" "$PROXY_LOG" 2>/dev/null; then
        echo "✅ proxy-server is ready" | tee -a "$TEST_LOG"
        break
    fi
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        echo "❌ FAILED: proxy-server died during startup" | tee -a "$TEST_LOG"
        cat "$PROXY_LOG" | tee -a "$TEST_LOG"
        exit 1
    fi
    sleep 0.5
done

if ! grep -q "listening on" "$PROXY_LOG" 2>/dev/null; then
    echo "❌ FAILED: proxy-server didn't start in time" | tee -a "$TEST_LOG"
    cat "$PROXY_LOG" | tee -a "$TEST_LOG"
    exit 1
fi

echo "=== Starting socks5d ===" | tee -a "$TEST_LOG"
./target/debug/socks5d --profile "$TEST_PROFILE" --listen "127.0.0.1:$SOCKS_PORT" > "$SOCKS_LOG" 2>&1 &
SOCKS_PID=$!
echo "socks5d PID: $SOCKS_PID" | tee -a "$TEST_LOG"

# Wait for socks5d to be ready
echo "Waiting for socks5d to start..." | tee -a "$TEST_LOG"
for i in {1..30}; do
    if grep -q "listening on" "$SOCKS_LOG" 2>/dev/null; then
        echo "✅ socks5d is ready" | tee -a "$TEST_LOG"
        break
    fi
    if ! kill -0 "$SOCKS_PID" 2>/dev/null; then
        echo "❌ FAILED: socks5d died during startup" | tee -a "$TEST_LOG"
        cat "$SOCKS_LOG" | tee -a "$TEST_LOG"
        exit 1
    fi
    sleep 0.5
done

if ! grep -q "listening on" "$SOCKS_LOG" 2>/dev/null; then
    echo "❌ FAILED: socks5d didn't start in time" | tee -a "$TEST_LOG"
    cat "$SOCKS_LOG" | tee -a "$TEST_LOG"
    exit 1
fi

# Give services a moment to stabilize
sleep 2

echo "=== Running curl test ===" | tee -a "$TEST_LOG"
echo "Testing: curl -m 30 -vvv --socks5-hostname 127.0.0.1:$SOCKS_PORT http://ifconfig.io/country_code" | tee -a "$TEST_LOG"

# Run curl and capture output
set +e
CURL_OUTPUT=$(curl -m 30 -vvv --socks5-hostname "127.0.0.1:$SOCKS_PORT" http://ifconfig.io/country_code 2>&1)
CURL_EXIT=$?
set -e

echo "$CURL_OUTPUT" > "$CURL_LOG"

# Analyze results
echo "" | tee -a "$TEST_LOG"
echo "=== Test Results ===" | tee -a "$TEST_LOG"
echo "Curl exit code: $CURL_EXIT" | tee -a "$TEST_LOG"

if [ $CURL_EXIT -eq 0 ]; then
    COUNTRY_CODE=$(echo "$CURL_OUTPUT" | tail -1)
    echo "✅ SUCCESS: Curl completed successfully" | tee -a "$TEST_LOG"
    echo "Country code received: $COUNTRY_CODE" | tee -a "$TEST_LOG"

    # Validate it's a reasonable country code
    if echo "$COUNTRY_CODE" | grep -qE '^[A-Z]{2}$'; then
        echo "✅ Valid country code format" | tee -a "$TEST_LOG"
    else
        echo "⚠️  WARNING: Unexpected country code format" | tee -a "$TEST_LOG"
    fi
else
    echo "❌ FAILED: Curl exited with code $CURL_EXIT" | tee -a "$TEST_LOG"
fi

# Show relevant log excerpts
echo "" | tee -a "$TEST_LOG"
echo "=== Proxy Server Log (last 20 lines) ===" | tee -a "$TEST_LOG"
tail -20 "$PROXY_LOG" | tee -a "$TEST_LOG"

echo "" | tee -a "$TEST_LOG"
echo "=== SOCKS5 Daemon Log (last 20 lines) ===" | tee -a "$TEST_LOG"
tail -20 "$SOCKS_LOG" | tee -a "$TEST_LOG"

echo "" | tee -a "$TEST_LOG"
echo "=== Curl Output ===" | tee -a "$TEST_LOG"
cat "$CURL_LOG" | tee -a "$TEST_LOG"

# Final summary
echo "" | tee -a "$TEST_LOG"
echo "=== Summary ===" | tee -a "$TEST_LOG"
echo "Logs saved to: $LOG_DIR" | tee -a "$TEST_LOG"
echo "  - Proxy log: $PROXY_LOG" | tee -a "$TEST_LOG"
echo "  - SOCKS log: $SOCKS_LOG" | tee -a "$TEST_LOG"
echo "  - Curl log: $CURL_LOG" | tee -a "$TEST_LOG"
echo "  - Test log: $TEST_LOG" | tee -a "$TEST_LOG"

if [ $CURL_EXIT -eq 0 ]; then
    echo "" | tee -a "$TEST_LOG"
    echo "🎉 E2E TEST PASSED 🎉" | tee -a "$TEST_LOG"
    exit 0
else
    echo "" | tee -a "$TEST_LOG"
    echo "❌ E2E TEST FAILED ❌" | tee -a "$TEST_LOG"
    exit 1
fi
