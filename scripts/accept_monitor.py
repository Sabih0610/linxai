"""Controlled real target capture/incident acceptance; never provisions kernel hooks."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main():
    if os.environ.get("LINXAI_TEST_KERNEL") != "1":
        print("PENDING: LINXAI_TEST_KERNEL=1 on a prepared target with running protected sensor/monitor")
        return 3
    from security.sensor import SensorClient
    from operations.supervised import SupervisedLinuxAdapter
    from operations.store import Store
    identity = SupervisedLinuxAdapter().resolve_identity()
    if not identity.ordinary(): raise PermissionError("Ordinary test owner required")
    client = SensorClient()
    before = client.poll(0, None)
    if before["health"]["state"] != "ready": raise RuntimeError("Real kernel capture not ready")
    cursor, epoch = before["cursor"], before["epoch"]
    with tempfile.TemporaryDirectory(prefix="linxai-benign-capture-") as temp:
        script = Path(temp) / "controlled-hello"
        script.write_text("#!/bin/sh\nexit 0\n")
        script.chmod(0o700)
        subprocess.run([str(script)], shell=False, check=True, timeout=3)
        try:
            fd = os.open("/etc/shadow", os.O_RDONLY)
        except PermissionError:
            pass
        else:
            os.close(fd)  # Never read credential contents, even if target permissions differ.
        seen, incident_seen = [], False
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            batch = client.poll(cursor, epoch)
            cursor, epoch = batch["cursor"], batch["epoch"]
            seen.extend(event for event in batch["events"] if event["uid"] == identity.uid and event["target"].get("path") in {str(script), "/etc/shadow"})
            database = Path.home() / ".linxai/security.sqlite"
            if database.exists():
                store = Store(database)
                try:
                    incident_seen = any(row["event_id"] in {event["id"] for event in seen} for row in store.list("incident", 100))
                finally: store.close()
            if len({event["kind"] for event in seen}) >= 2 and incident_seen: break
            time.sleep(0.1)
    result = {"kind": "actual target kernel capture, not enforcement", "events": seen, "incident_seen": incident_seen}
    Path("monitor-acceptance.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if incident_seen and len({event["kind"] for event in seen}) >= 2 and all(event["identity_quality"] == "kernel_start_identity" for event in seen) else 1


if __name__ == "__main__":
    raise SystemExit(main())
