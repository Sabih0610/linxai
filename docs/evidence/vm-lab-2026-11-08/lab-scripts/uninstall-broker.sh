#!/bin/bash
# Removes everything deploy-broker.sh installed. Keeps /var/lib/linxai-broker
# (root audit + replay state) unless --purge is given, so evidence survives.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
systemctl stop linxai-broker.service linxai-lab-acceptance.service 2>/dev/null || true
rm -f /etc/systemd/system/linxai-broker.service /etc/systemd/system/linxai-lab-acceptance.service
rm -f /usr/share/polkit-1/actions/org.linxai.service.policy /etc/linxai/broker.json
rmdir /etc/linxai 2>/dev/null || true
rm -rf /usr/lib/linxai-trusted
[ "${1:-}" = "--purge" ] && rm -rf /var/lib/linxai-broker
systemctl daemon-reload
echo "removed"
