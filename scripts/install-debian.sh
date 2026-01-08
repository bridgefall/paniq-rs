#!/bin/bash
# paniq-rs Debian install script for pre-built binaries
# This script installs paniq-rs from a release archive (no compilation required)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLOR_BLUE='\033[0;34m'
COLOR_GREEN='\033[0;32m'
COLOR_RESET='\033[0m'

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (e.g. sudo ./install-debian.sh)" >&2
    exit 1
fi

# Verify binaries exist in the script directory
for bin in paniq-rs-proxy paniq-rs-ctl; do
    if [ ! -f "${SCRIPT_DIR}/${bin}" ]; then
        echo "Error: ${bin} not found in ${SCRIPT_DIR}" >&2
        echo "This script must be run from the release archive directory" >&2
        exit 1
    fi
done

echo -e "${COLOR_BLUE}Installing paniq-rs runtime dependencies...${COLOR_RESET}"
apt-get update
apt-get install -y curl jq

echo -e "${COLOR_BLUE}Installing paniq-rs binaries...${COLOR_RESET}"
install -m 0755 "${SCRIPT_DIR}/paniq-rs-proxy" /usr/local/bin/paniq-rs-proxy
install -m 0755 "${SCRIPT_DIR}/paniq-rs-ctl" /usr/local/bin/paniq-rs-ctl

echo -e "${COLOR_BLUE}Creating config directory...${COLOR_RESET}"
install -d /etc/bridgefall-rs

# Write proxy config
cat > /etc/bridgefall-rs/paniq-rs-proxy.json <<'EOF'
{
    "listen_addr": "0.0.0.0:9001",
    "workers": 8,
    "max_connections": 128,
    "dial_timeout": "5s",
    "accept_timeout": "500ms",
    "idle_timeout": "2m",
    "metrics_interval": "10s",
    "log_level": "info",
    "control_socket": "/tmp/paniq-rs-proxy.sock"
}
EOF
chmod 0644 /etc/bridgefall-rs/paniq-rs-proxy.json

echo -e "${COLOR_BLUE}Generating profile...${COLOR_RESET}"
IP=$(curl -s https://ifconfig.me)
if [ -z "$IP" ]; then
    echo "Error: failed to fetch public IP" >&2
    exit 1
fi

/usr/local/bin/paniq-rs-ctl create-profile --mtu 1420 --proxy-addr "${IP}:9001" > /etc/bridgefall-rs/profile.json
chmod 0644 /etc/bridgefall-rs/profile.json

echo -e "${COLOR_BLUE}Installing systemd unit...${COLOR_RESET}"
cat > /etc/systemd/system/paniq-rs-proxy.service <<'EOF'
[Unit]
Description=Bridgefall Proxy Server (Rust)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/paniq-rs-proxy --config /etc/bridgefall-rs/paniq-rs-proxy.json --profile /etc/bridgefall-rs/profile.json
Restart=on-failure
RestartSec=2s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/paniq-rs-proxy.service

echo -e "${COLOR_BLUE}Generating client connection string...${COLOR_RESET}"
/usr/local/bin/paniq-rs-ctl profile-cbor --base64 < /etc/bridgefall-rs/profile.json > /etc/bridgefall-rs/client.txt
chmod 0644 /etc/bridgefall-rs/client.txt

echo -e "${COLOR_BLUE}Enabling and starting paniq-rs-proxy service...${COLOR_RESET}"
systemctl daemon-reload
systemctl enable --now paniq-rs-proxy.service

echo -e "${COLOR_GREEN}==> Installation complete!${COLOR_RESET}"
echo -e "${COLOR_GREEN}==> paniq-rs-proxy enabled and started${COLOR_RESET}"
echo -e "${COLOR_GREEN}==> Config directory: /etc/bridgefall-rs${COLOR_RESET}"
echo -e "${COLOR_GREEN}==> Client connection string saved to /etc/bridgefall-rs/client.txt${COLOR_RESET}"
echo ""
echo "To view logs: journalctl -u paniq-rs-proxy -f"
echo "To stop: systemctl stop paniq-rs-proxy"
echo "To restart: systemctl restart paniq-rs-proxy"
