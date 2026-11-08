#!/bin/bash
# ONE admin step for the isolated LINxAI test VM. Run at the VM console:
#     sudo bash ~/linxai-lab/admin-session.sh
# Deploys the current development build (new broker actions + polkit policy) and the
# root BCC sensor. Nothing is enabled at boot. Undo: uninstall-sensor.sh / uninstall-broker.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
cd "$(dirname "$0")"
[ -f linxai-trusted-dev.tar ] || { echo "missing linxai-trusted-dev.tar"; exit 1; }
[ -f linxai-broker-gateB.tar ] || cp linxai-broker.tar linxai-broker-gateB.tar   # keep Gate B bundle
cp linxai-trusted-dev.tar linxai-broker.tar
bash deploy-broker.sh
bash deploy-sensor.sh linxai-trusted-dev.tar
pkaction --action-id org.linxai.process.manage --verbose | grep implicit
echo "ADMIN SESSION DONE. Tell Claude 'deployed'."
