#!/bin/bash
# Lab validation of the medallion baseline on real kernel capture (run in ~/linxai-lab/src-dev).
set -u
MON='import sys; sys.path.insert(0, "."); from security.monitor import main; main()'
restart_monitor() {
  systemctl --user stop linxai-monitor-lab 2>/dev/null; systemctl --user reset-failed linxai-monitor-lab 2>/dev/null
  systemd-run --user -q --unit=linxai-monitor-lab --working-directory="$PWD" /usr/bin/python3 -B -c "$MON"; sleep 3
}
restart_monitor
for chunk in 1 2 3; do
  for i in $(seq 1 500); do /usr/bin/true; sleep 0.01; done
  sleep 6
  python3 -B -m security.lake | python3 -c 'import json,sys; s=json.load(sys.stdin); print("cycle", s["last_cycle"], "ready", s["ready"])'
done
restart_monitor                       # reload the trained gold baseline
/usr/bin/factor 1234567 >/dev/null    # behaviour this account has never shown
sleep 8
python3 -B - <<'PY'
import json, sys
sys.path.insert(0, ".")
from pathlib import Path
from operations.store import Store
s = Store(Path.home() / ".linxai/security.sqlite")
anomalies = [a for a in s.list("anomaly", 50) if a["uid"] == 1000]
incidents = [i for i in s.list("incident", 50) if i["evidence"]["target"].get("path") == "/usr/bin/factor"]
status = s.get("monitor", "status"); s.close()
print("anomalies for uid 1000:", json.dumps([{k: a[k] for k in ("key", "score_bits", "baseline_events", "severity")} for a in anomalies[:5]]))
print("incidents for /usr/bin/factor:", len(incidents), "| monitor:", {k: status.get(k) for k in ("state", "events", "incidents", "anomalies")})
PY
