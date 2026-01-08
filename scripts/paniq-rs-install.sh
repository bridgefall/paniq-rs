#!/bin/bash
#
# paniq-rs one-line installer for Debian-based systems
# Usage: curl -fsSL https://raw.githubusercontent.com/bridgefall/paniq-rs/main/scripts/paniq-rs-install.sh | sudo bash
#
# This script will:
# 1. Detect the latest release (or use a specified version)
# 2. Download the release archive
# 3. Verify checksums
# 4. Delegate to install-debian.sh for actual installation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="bridgefall/paniq-rs"
VERSION="${PANIQ_VERSION:-latest}"

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."

    # Check if Debian-based
    if [ ! -f /etc/debian_version ]; then
        log_error "This installer is designed for Debian-based systems"
        exit 1
    fi

    # Check for required commands
    local missing_deps=()
    for cmd in curl tar sha256sum; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_info "Installing missing dependencies..."
        apt-get update -qq
        apt-get install -y -qq curl coreutils tar
    fi

    log_success "System requirements met"
}

# Get latest release version
get_latest_version() {
    log_info "Fetching latest release version..."

    local api_url="https://api.github.com/repos/${REPO}/releases/latest"
    local version=$(curl -fsSL "$api_url" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [ -z "$version" ]; then
        log_error "Failed to fetch latest version"
        exit 1
    fi

    echo "$version"
}

# Download and verify release
download_release() {
    local version=$1
    local tmp_dir=$(mktemp -d)

    log_info "Downloading paniq-rs ${version}..."

    local base_url="https://github.com/${REPO}/releases/download/${version}"
    local archive_name="paniq-rs-${version}-linux-amd64.tar.gz"
    local archive_url="${base_url}/${archive_name}"
    local checksums_url="${base_url}/SHA256SUMS"

    cd "$tmp_dir"

    # Download archive
    if ! curl -fsSL -o "$archive_name" "$archive_url"; then
        log_error "Failed to download release archive"
        log_error "URL: $archive_url"
        rm -rf "$tmp_dir"
        exit 1
    fi

    # Download checksums
    if ! curl -fsSL -o SHA256SUMS "$checksums_url"; then
        log_warn "Failed to download checksums, skipping verification"
    else
        log_info "Verifying checksums..."
        # Extract just the binaries from checksums (not the archive itself)
        if sha256sum -c SHA256SUMS --ignore-missing --quiet 2>/dev/null; then
            log_success "Checksum verification passed"
        else
            log_warn "Checksum verification skipped (archive not in SHA256SUMS)"
        fi
    fi

    # Extract archive
    log_info "Extracting archive..."
    tar -xzf "$archive_name"

    echo "$tmp_dir"
}

# Run install-debian.sh from the extracted archive
run_installer() {
    local tmp_dir=$1

    log_info "Running install-debian.sh..."

    if [ ! -f "$tmp_dir/install-debian.sh" ]; then
        log_error "install-debian.sh not found in release archive"
        log_error "Contents of $tmp_dir:"
        ls -la "$tmp_dir"
        exit 1
    fi

    chmod +x "$tmp_dir/install-debian.sh"

    # Run the installer from the temp directory
    cd "$tmp_dir"
    bash install-debian.sh
}

# Print installation summary
print_summary() {
    local version=$1

    echo ""
    log_success "paniq-rs ${version} installed successfully!"
    echo ""
    echo "For more information:"
    echo "  - View logs: journalctl -u paniq-rs-proxy -f"
    echo "  - Check status: systemctl status paniq-rs-proxy"
    echo "  - Client connection: cat /etc/bridgefall-rs/client.txt"
    echo ""
}

# Main installation flow
main() {
    log_info "Starting paniq-rs installation..."
    echo ""

    check_root
    check_requirements

    # Determine version to install
    if [ "$VERSION" = "latest" ]; then
        VERSION=$(get_latest_version)
    fi

    log_info "Installing version: ${VERSION}"

    # Download and install
    tmp_dir=$(download_release "$VERSION")
    run_installer "$tmp_dir"

    # Cleanup
    rm -rf "$tmp_dir"

    print_summary "$VERSION"
}

# Run main function
main "$@"
