#!/bin/bash
# Run INSIDE the VM console (not SSH) after admin-session.sh: one password prompt (restore).
set -uo pipefail
cd "$(dirname "$0")/src-dev"
LINXAI_TEST_BROKER_LAB=1 /bin/bash -c '
  pkttyagent --process $$ --fallback &
  sleep 1
  exec /usr/bin/python3 -B scripts/accept_restore.py
'
rc=$?
pkill -u "$(id -u)" -x pkttyagent 2>/dev/null
cp -f restore-acceptance.json ../runs/ 2>/dev/null
echo "== accept_restore exit code: $rc (result in ~/linxai-lab/runs/restore-acceptance.json)"
