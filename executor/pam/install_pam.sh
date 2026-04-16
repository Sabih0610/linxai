#!/bin/bash
# executor/pam/install_pam.sh
# Compiles and installs the LINxAI PAM module.
# Must be run as root (sudo).
# Run: sudo bash executor/pam/install_pam.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SO_NAME="pam_linxai_face.so"
PAM_DIR="/lib/x86_64-linux-gnu/security"
PAM_SUDO="/etc/pam.d/sudo"
BACKUP_SUDO="/etc/pam.d/sudo.linxai_backup"

echo "=================================================="
echo "  LINxAI PAM Module Installation"
echo "=================================================="

# Check running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root."
    echo "Run: sudo bash executor/pam/install_pam.sh"
    exit 1
fi

# Install build dependencies
echo "[1/5] Installing build dependencies..."
apt-get install -y -qq libpam0g-dev gcc

# Compile the PAM module
echo "[2/5] Compiling pam_linxai_face.c..."
gcc -shared -fPIC -o "${SCRIPT_DIR}/${SO_NAME}" \
    "${SCRIPT_DIR}/pam_linxai_face.c" \
    -lpam -lpam_misc \
    -Wall -Wextra -O2

echo "  Compiled: ${SCRIPT_DIR}/${SO_NAME}"

# Install to PAM security directory
echo "[3/5] Installing to ${PAM_DIR}/..."
cp "${SCRIPT_DIR}/${SO_NAME}" "${PAM_DIR}/${SO_NAME}"
chmod 644 "${PAM_DIR}/${SO_NAME}"
echo "  Installed: ${PAM_DIR}/${SO_NAME}"

# Backup existing sudo PAM config
echo "[4/5] Backing up ${PAM_SUDO} to ${BACKUP_SUDO}..."
if [ ! -f "${BACKUP_SUDO}" ]; then
    cp "${PAM_SUDO}" "${BACKUP_SUDO}"
    echo "  Backup saved."
else
    echo "  Backup already exists — skipping."
fi

# Inject LINxAI line as first auth line in /etc/pam.d/sudo
echo "[5/5] Configuring ${PAM_SUDO}..."

LINXAI_LINE="auth sufficient pam_linxai_face.so"

if grep -q "pam_linxai_face" "${PAM_SUDO}"; then
    echo "  LINxAI PAM line already present — skipping."
else
    # Insert as the first auth line
    # Find line number of first 'auth' line and insert before it
    FIRST_AUTH=$(grep -n "^auth" "${PAM_SUDO}" | head -1 | cut -d: -f1)
    if [ -n "${FIRST_AUTH}" ]; then
        sed -i "${FIRST_AUTH}i\\${LINXAI_LINE}" "${PAM_SUDO}"
    else
        # No existing auth lines — prepend
        echo "${LINXAI_LINE}" | cat - "${PAM_SUDO}" > /tmp/pam_sudo_tmp
        mv /tmp/pam_sudo_tmp "${PAM_SUDO}"
    fi
    echo "  Added: ${LINXAI_LINE}"
fi

echo ""
echo "=================================================="
echo "  Installation complete!"
echo ""
echo "  Current /etc/pam.d/sudo:"
cat "${PAM_SUDO}"
echo ""
echo "  To uninstall:"
echo "    sudo cp ${BACKUP_SUDO} ${PAM_SUDO}"
echo "    sudo rm ${PAM_DIR}/${SO_NAME}"
echo "=================================================="