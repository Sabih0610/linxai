"""Explicit real target acceptance of process.priority.restore (requirement 49).

Ordinary owner only, on the prepared isolated target with the broker deployed:
an owned child is lowered through the unprivileged typed action, then restored to
nice 0 through the root broker after polkit admin authentication. Also checks that
restoring above the nice-0 floor is refused before dispatch.
    LINXAI_TEST_BROKER_LAB=1 python3 -B scripts/accept_restore.py
"""
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main():
    if os.environ.get("LINXAI_TEST_BROKER_LAB") != "1":
        print("PENDING: opt in with LINXAI_TEST_BROKER_LAB=1 on the prepared isolated target")
        return 3
    from operations.broker import BrokerClient
    from operations.registry import ActionRegistry, InvalidParameters
    from operations.service import LocalPolicy, OperationService
    from operations.system import proc_stat
    from operations.workflows import WorkflowSystem
    from test_application import MemoryAudit
    uid = os.getuid()
    if uid == 0:
        raise PermissionError("Run lab client as ordinary owner")
    service = OperationService(ActionRegistry(actor_uid=uid), WorkflowSystem(), LocalPolicy(uid), MemoryAudit())
    child = subprocess.Popen(["/usr/bin/sleep", "600"])
    record = {"pid": child.pid}
    try:
        start = proc_stat(child.pid)[0]
        lowered = service.run({"action": "process.priority.lower", "parameters": {"pid": child.pid, "start_ticks": start, "nice": 10}})
        record["lower"] = {"status": lowered.status, "verified": lowered.verified, "nice_after": proc_stat(child.pid)[1]}
        refused = {}
        for label, params in {"above_floor": {"pid": child.pid, "start_ticks": start, "nice": -5}}.items():
            try:
                ActionRegistry(actor_uid=uid).prepare("process.priority.restore", params)
                refused[label] = "NOT REFUSED"
            except (InvalidParameters, ValueError, PermissionError) as exc:
                refused[label] = f"refused: {type(exc).__name__}"
        record["refusals"] = refused
        restored = BrokerClient().run({"action": "process.priority.restore",
                                       "parameters": {"pid": child.pid, "start_ticks": start, "nice": 0}})
        record["restore"] = asdict(restored)
        record["nice_final"] = proc_stat(child.pid)[1]
    finally:
        child.kill(); child.wait()
        Path("restore-acceptance.json").write_text(json.dumps(record, indent=2, default=str) + "\n")
    ok = (record["lower"]["nice_after"] == 10 and record["restore"]["status"] == "succeeded"
          and record["restore"]["verified"] and record["nice_final"] == 0
          and all(v.startswith("refused") for v in record["refusals"].values()))
    print("PASS" if ok else "FAIL", json.dumps({k: record[k] for k in ("lower", "refusals", "nice_final")}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
