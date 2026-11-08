#!/bin/bash
# Run INSIDE the VM's own console window (not over SSH): polkit only offers a
# password prompt to an active local session. Type your own password at each
# prompt; four prompts are expected (start, restart, stop, restore).
set -uo pipefail
cd "$(dirname "$0")"
LAB="$(pwd)"
echo "== session check"
loginctl show-session "${XDG_SESSION_ID:-}" -p Id -p Type -p Remote -p Active -p Seat 2>&1
systemctl is-active linxai-broker.service
echo "== fixture before: $(systemctl is-active linxai-lab-acceptance.service)"
rm -f "$LAB/src/broker-acceptance.json" "$LAB/broker-acceptance.json"
cd src
# polkit asks the agent registered for the exact requesting process (pid + start
# time). The inner shell registers a text agent for its own pid, then execs the
# acceptance client, which keeps that same pid and start time.
LINXAI_TEST_BROKER_LAB=1 /bin/bash -c '
  pkttyagent --process $$ --fallback &
  sleep 1
  exec /usr/bin/python3 -B scripts/accept_broker.py
'
rc=$?
pkill -u "$(id -u)" -x pkttyagent 2>/dev/null
echo "== accept_broker exit code: $rc"
echo "== fixture after: $(systemctl is-active linxai-lab-acceptance.service)"
[ -f broker-acceptance.json ] && cp broker-acceptance.json "$LAB/broker-acceptance.json" && echo "result: ~/linxai-lab/broker-acceptance.json"
exit $rc
