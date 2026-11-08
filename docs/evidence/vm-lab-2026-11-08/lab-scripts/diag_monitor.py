"""DIAGNOSTIC (not acceptance): same actions as scripts/accept_monitor.py, but it
does not require sensor health 'ready' and waits longer, to see whether real
capture -> independent monitor -> incident works while the sensor is degraded."""
import json, os, sys, tempfile, time
from pathlib import Path
sys.path.insert(0, ".")
from security.sensor import SensorClient
from operations.store import Store

uid = os.getuid()
client = SensorClient()
start = client.poll(0, None)
cursor, epoch = start["cursor"], start["epoch"]
# Skip the backlog so we only look at what happens after our actions.
while True:
    b = client.poll(cursor, epoch)
    cursor, epoch = b["cursor"], b["epoch"]
    if not b["events"]:
        break
health_before = b["health"]
t_action = time.monotonic_ns()
with tempfile.TemporaryDirectory(prefix="linxai-benign-capture-") as temp:
    script = Path(temp) / "controlled-hello"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o700)
    os.spawnv(os.P_WAIT, str(script), [str(script)])
    try:
        os.close(os.open("/etc/shadow", os.O_RDONLY))
    except PermissionError:
        pass
    wanted = {str(script), "/etc/shadow"}
    seen, incidents = [], []
    deadline = time.monotonic() + 90
    db = Path.home() / ".linxai/security.sqlite"
    while time.monotonic() < deadline:
        b = client.poll(cursor, epoch)
        cursor, epoch = b["cursor"], b["epoch"]
        seen += [e for e in b["events"] if e["uid"] == uid and e["target"].get("path") in wanted]
        if db.exists() and seen:
            store = Store(db)
            try:
                ids = {e["id"] for e in seen}
                incidents = [r for r in store.list("incident", 200) if r["event_id"] in ids]
                status = store.get("monitor", "status")
            finally:
                store.close()
        if len({e["kind"] for e in seen}) >= 2 and len(incidents) >= 2:
            break
        if not b["events"]:
            time.sleep(0.2)
    health_after = b["health"]
result = {
    "kind": "DIAGNOSTIC real kernel capture while sensor degraded; not acceptance",
    "health_before": health_before, "health_after": health_after,
    "seen_kinds": sorted({e["kind"] for e in seen}),
    "events": seen,
    "capture_delay_ms": [round((e["received_ns"] - e["monotonic_ns"]) / 1e6) for e in seen if e["monotonic_ns"]],
    "incidents": [{k: r[k] for k in ("rule", "severity", "state", "event_id", "interpretation")} for r in incidents],
    "monitor_status": {k: status.get(k) for k in ("state", "events", "incidents", "invalid", "gaps")} if seen and db.exists() else None,
}
Path("monitor-diagnostic.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({k: result[k] for k in ("seen_kinds", "capture_delay_ms", "incidents", "monitor_status")}, indent=1))
print("identity_quality:", sorted({e["identity_quality"] for e in seen}))
