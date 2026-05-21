#!/bin/bash
# LINxAI VPS Module Installer
# Installs remote server management capability
#
# Usage: sudo bash modules/install-vps.sh

set -e
[ "$EUID" -ne 0 ] && echo "Run as root: sudo bash modules/install-vps.sh" && exit 1

REAL_USER="${SUDO_USER:-ubuntu}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

echo ""
echo "Installing LINxAI VPS Module..."
echo ""

pip3 install -q paramiko pyyaml

# Create default servers config if not exists
SERVERS_CONF="/etc/linxai/servers.yaml"
if [ ! -f "$SERVERS_CONF" ]; then
    cat > "$SERVERS_CONF" << 'EOF'
# LINxAI Remote Server Configuration
# Add your VPS servers here
#
# servers:
#   production-web:
#     host: "your.server.ip"
#     port: 22
#     username: "ubuntu"
#     key_path: "~/.ssh/your_key"
#     description: "Production web server"
servers: {}
EOF
    echo "Created /etc/linxai/servers.yaml — add your servers there"
fi

# Enable VPS in config
CONFIG=/etc/linxai/config.yaml
if [ -f "$CONFIG" ]; then
    sed -i 's/vps_enabled: false/vps_enabled: true/' "$CONFIG"
fi

echo ""
echo "✓ VPS module installed."
echo "  Add servers to: /etc/linxai/servers.yaml"
echo "  Then: linxai \"check disk on production-web\""
echo ""