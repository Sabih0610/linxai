#!/bin/bash
# Stops and removes the lab sensor unit. Keeps /var/lib/linxai-sensor (event
# evidence) unless --purge. The trusted bundle stays for the broker; use
# uninstall-broker.sh to remove everything.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
systemctl stop linxai-sensor.service 2>/dev/null || true
rm -f /etc/systemd/system/linxai-sensor.service
[ "${1:-}" = "--purge" ] && rm -rf /var/lib/linxai-sensor
systemctl daemon-reload
echo "sensor removed"
