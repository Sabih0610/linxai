#!/bin/bash
# LINxAI — Native Ubuntu Installation Script
# Installs LINxAI as a proper system tool on Ubuntu 22.04
#
# Usage: sudo bash install.sh
#
# After install:
#   linxai "restart nginx"          ← works from anywhere
#   sudo systemctl status linxai-ebpf
#   linxai-logs --tail 20

set -e

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; exit 1; }
step() { echo -e "\n${BOLD}[$1]${NC} $2"; }

# ── Must run as root ──────────────────────────────────────────────────────────
[ "$EUID" -ne 0 ] && fail "Run as root: sudo bash install.sh"

REAL_USER="${SUDO_USER:-ubuntu}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
INSTALL_DIR="/opt/linxai"
CONFIG_DIR="/etc/linxai"
LOG_DIR="/var/log/linxai"
BIN_DIR="/usr/local/bin"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     LINxAI — System Installation            ║${NC}"
echo -e "${BOLD}║     Intelligent Linux Administration Layer   ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Verify system ────────────────────────────────────────────────────
step "1/8" "Verifying system requirements..."

# Check Ubuntu version
if command -v lsb_release &>/dev/null; then
    VERSION=$(lsb_release -rs)
    [[ "$VERSION" == "22.04" ]] && ok "Ubuntu 22.04 confirmed" \
        || warn "Built for 22.04, you have $VERSION — proceeding anyway"
fi

# Check kernel for eBPF
KERNEL=$(uname -r)
MAJOR=$(echo "$KERNEL" | cut -d. -f1)
MINOR=$(echo "$KERNEL" | cut -d. -f2)
if [ "$MAJOR" -gt 5 ] || ([ "$MAJOR" -eq 5 ] && [ "$MINOR" -ge 15 ]); then
    ok "Kernel $KERNEL — eBPF supported"
else
    fail "Kernel $KERNEL too old. Need 5.15+ for eBPF ring buffers."
fi

# ── Step 2: System packages ───────────────────────────────────────────────────
step "2/8" "Installing system packages..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-dev \
    git curl wget build-essential \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    linux-tools-common \
    bpfcc-tools python3-bpfcc libbpfcc-dev \
    nginx net-tools \
    libssl-dev libffi-dev \
    portaudio19-dev ffmpeg \
    libpam0g-dev gcc \
    2>/dev/null
ok "System packages installed"

# ── Step 3: Ollama + model ────────────────────────────────────────────────────
step "3/8" "Setting up AI model..."
if ! command -v ollama &>/dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
    ok "Ollama installed"
else
    ok "Ollama already installed"
fi

systemctl enable ollama 2>/dev/null
systemctl start ollama
sleep 3

if ollama list 2>/dev/null | grep -q "qwen2.5:1.5b"; then
    ok "qwen2.5:1.5b model ready"
else
    echo "  Pulling qwen2.5:1.5b (~1.2GB)..."
    sudo -u "$REAL_USER" ollama pull qwen2.5:1.5b
    ok "Model downloaded"
fi

# ── Step 4: Python packages ───────────────────────────────────────────────────
step "4/8" "Installing Python dependencies..."
pip3 install -q \
    langgraph langchain langchain-community \
    requests paramiko psutil \
    opencv-python-headless \
    pyyaml pytest 2>/dev/null
ok "Core Python packages installed"

# ── Step 5: Directory structure ───────────────────────────────────────────────
step "5/8" "Creating system directories..."

# Config directory
mkdir -p "$CONFIG_DIR"

# Log directory
mkdir -p "$LOG_DIR"
chown "$REAL_USER":"$REAL_USER" "$LOG_DIR"

# Runtime data
mkdir -p "$REAL_HOME/.linxai"
chown "$REAL_USER":"$REAL_USER" "$REAL_HOME/.linxai"

# Make sure install dir is owned correctly
# chown -R "$REAL_USER":"$REAL_USER" "$INSTALL_DIR"

ok "Directories created"

# ── Step 6: System config ────────────────────────────────────────────────────
step "6/8" "Writing system configuration..."

# Main config at /etc/linxai/config.yaml
cat > "$CONFIG_DIR/config.yaml" << EOF
# LINxAI System Configuration
# Edit this file to customise behaviour

ai:
  model: "qwen2.5:1.5b"
  ollama_host: "http://localhost:11434"
  max_context: 5
  timeout_s: 120

execution:
  command_timeout_s: 30
  face_auth_enabled: false
  use_sudo: true

ebpf:
  enabled: true
  filter_noise: true

logging:
  log_path: "/var/log/linxai/audit.jsonl"
  level: "INFO"

resource:
  cpu_threshold_pct: 80.0
  poll_interval_s: 1.0

modules:
  voice_enabled: false
  vps_enabled: true
  resource_enabled: true
EOF

ok "Config written to $CONFIG_DIR/config.yaml"

# ── Step 7: System commands ───────────────────────────────────────────────────
step "7/8" "Installing system commands..."

# Main linxai command
cat > "$BIN_DIR/linxai" << 'LINXAI_CMD'
#!/bin/bash
# LINxAI — Intelligent Linux Administration Layer
# Usage:
#   linxai "restart nginx only if port 80 is free"
#   linxai --demo
#   linxai --status
#   linxai --interactive

export PYTHONPATH=/opt/linxai
export LINXAI_CONFIG=/etc/linxai/config.yaml

if [ "$1" = "--status" ]; then
    echo "LINxAI System Status"
    echo "────────────────────"
    echo -n "eBPF daemon:  "
    systemctl is-active linxai-ebpf 2>/dev/null || echo "not running"
    echo -n "Ollama:       "
    systemctl is-active ollama 2>/dev/null || echo "not running"
    echo -n "AI model:     "
    ollama list 2>/dev/null | grep -q "qwen2.5:1.5b" && echo "ready" || echo "not found"
    echo -n "Log file:     "
    LOG=/var/log/linxai/audit.jsonl
    [ -f "$LOG" ] && echo "$(wc -l < $LOG) records" || echo "empty"
    exit 0
fi

if [ "$1" = "--demo" ]; then
    exec sudo python3 /opt/linxai/demo.py
fi

if [ "$1" = "--interactive" ] || [ -z "$1" ]; then
    exec sudo python3 /opt/linxai/main.py
fi

if [ "$1" = "--attack-sim" ]; then
    exec sudo python3 /opt/linxai/tests/attack_simulation.py
fi

# Single command mode
exec sudo python3 /opt/linxai/main.py --command "$*"
LINXAI_CMD

chmod +x "$BIN_DIR/linxai"
ok "linxai command installed at $BIN_DIR/linxai"

# Log viewer command
cat > "$BIN_DIR/linxai-logs" << 'LOGS_CMD'
#!/bin/bash
# LINxAI log viewer
export PYTHONPATH=/opt/linxai
exec python3 /opt/linxai/logger/cli.py "$@"
LOGS_CMD

chmod +x "$BIN_DIR/linxai-logs"
ok "linxai-logs command installed"

# Status command shortcut
cat > "$BIN_DIR/linxai-status" << 'STATUS_CMD'
#!/bin/bash
linxai --status
STATUS_CMD

chmod +x "$BIN_DIR/linxai-status"
ok "linxai-status command installed"

# ── Step 8: systemd services ──────────────────────────────────────────────────
step "8/8" "Installing systemd services..."

cp "$INSTALL_DIR/systemd/linxai-ebpf.service" /etc/systemd/system/
cp "$INSTALL_DIR/systemd/linxai-core.service" /etc/systemd/system/

# Update core service to use correct user
sed -i "s/User=ubuntu/User=$REAL_USER/" /etc/systemd/system/linxai-core.service

systemctl daemon-reload
systemctl enable linxai-ebpf
ok "linxai-ebpf service enabled (starts on boot)"

# ── Compile PAM module if source exists ──────────────────────────────────────
PAM_C="$INSTALL_DIR/executor/pam/pam_linxai_face.c"
if [ -f "$PAM_C" ]; then
    gcc -shared -fPIC -o /lib/x86_64-linux-gnu/security/pam_linxai_face.so \
        "$PAM_C" -lpam -lpam_misc -O2 2>/dev/null \
        && ok "PAM face auth module compiled" \
        || warn "PAM module compilation failed — face auth unavailable"
fi

# ── Create uninstall script ───────────────────────────────────────────────────
cat > "$INSTALL_DIR/uninstall.sh" << 'UNINSTALL'
#!/bin/bash
echo "Removing LINxAI..."
sudo systemctl stop linxai-ebpf linxai-core 2>/dev/null
sudo systemctl disable linxai-ebpf linxai-core 2>/dev/null
sudo rm -f /etc/systemd/system/linxai-ebpf.service
sudo rm -f /etc/systemd/system/linxai-core.service
sudo rm -f /usr/local/bin/linxai
sudo rm -f /usr/local/bin/linxai-logs
sudo rm -f /usr/local/bin/linxai-status
sudo rm -f /lib/x86_64-linux-gnu/security/pam_linxai_face.so
sudo rm -rf /etc/linxai
sudo systemctl daemon-reload
echo "LINxAI removed. Code at /opt/linxai, logs at /var/log/linxai"
UNINSTALL
chmod +x "$INSTALL_DIR/uninstall.sh"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║     LINxAI Installation Complete!           ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo "  Commands available system-wide:"
echo ""
echo -e "  ${BOLD}linxai${NC} \"restart nginx\"       — run a command"
echo -e "  ${BOLD}linxai${NC} --interactive          — interactive mode"
echo -e "  ${BOLD}linxai${NC} --demo                 — jury demo"
echo -e "  ${BOLD}linxai${NC} --status               — system status"
echo -e "  ${BOLD}linxai${NC} --attack-sim            — attack simulation"
echo -e "  ${BOLD}linxai-logs${NC} --tail 20          — view audit log"
echo -e "  ${BOLD}linxai-logs${NC} --summary          — log statistics"
echo ""
echo "  Services:"
echo "  sudo systemctl start linxai-ebpf    — start kernel monitor"
echo "  sudo systemctl status linxai-ebpf   — check status"
echo "  journalctl -u linxai-ebpf -f        — live logs"
echo ""
echo "  Config: /etc/linxai/config.yaml"
echo "  Logs:   /var/log/linxai/audit.jsonl"
echo ""
echo "  Reboot to start eBPF daemon automatically."
echo ""