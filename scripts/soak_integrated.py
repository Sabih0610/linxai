"""Integrated soak / availability run (original requirement 72).

Every interval: typed reads through the real OperationService, sensor health,
independent monitor status, lake status and RSS of the sensor/monitor processes.
Every probe interval: a harmless detection probe (owned /tmp script exec and an
/etc/shadow open attempt without reading) must produce monitor incidents.
Writes one JSON line per cycle and a summary file at the end. Ordinary user only:
    setsid nohup python3 -B scripts/soak_integrated.py --hours 24 --out soak.jsonl &
"""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def rss_kb(match):
    for name in os.listdir("/proc"):
        if name.isdigit():
            try:
                if match in Path(f"/proc/{name}/cmdline").read_bytes():
                    for line in Path(f"/proc/{name}/status").read_text().splitlines():
                        if line.startswith("VmRSS:"):
                            return int(line.split()[1])
            except OSError:
                continue
    return None


def probe(store_path, timeout=45):
    from operations.store import Store
    with tempfile.TemporaryDirectory(prefix="linxai-soak-probe-") as temp:
        script = Path(temp) / "probe"
        script.write_text("#!/bin/sh\nexit 0\n"); script.chmod(0o700)
        started = time.time()
        subprocess.run([str(script)], check=True, timeout=5)
        try: os.close(os.open("/etc/shadow", os.O_RDONLY))
        except PermissionError: pass
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(2)
            store = Store(store_path)
            try: rows = store.list("incident", 50)
            finally: store.close()
            rules = {r["rule"] for r in rows if r.get("created", 0) >= started - 1}
            if {"temporary_executable_attempt", "sensitive_file_attempt"} <= rules:
                return round(time.time() - started, 1)
    return None


def main(argv=None):
    from operations.registry import ActionRegistry
    from operations.service import LocalPolicy, OperationService
    from operations.store import Store
    from operations.workflows import WorkflowSystem
    from security.sensor import SensorClient
    from test_application import MemoryAudit
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hours", type=float, default=24.0)
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--probe-every", type=float, default=3600.0)
    parser.add_argument("--state", default=str(Path.home() / ".linxai"))
    parser.add_argument("--out", default="soak.jsonl")
    parser.add_argument("--components", default="ops,sensor,monitor",
                        help="components that must be up for a cycle to count as available; "
                             "use 'ops' for an unprivileged operations-only run (no root sensor)")
    args = parser.parse_args(argv)
    required = set(args.components.split(","))
    uid, state, out = os.getuid(), Path(args.state), Path(args.out)
    service = OperationService(ActionRegistry(actor_uid=uid), WorkflowSystem(), LocalPolicy(uid), MemoryAudit())
    end, next_probe, cycle = time.monotonic() + args.hours * 3600, time.monotonic(), 0
    with out.open("a") as log:
        while time.monotonic() < end:
            started, record = time.monotonic(), {"cycle": cycle, "time": time.time(), "ops": {}}
            actions = ["memory.usage", "disk.usage", "process.list"] + (["resource.forecast"] if cycle % 10 == 0 else [])
            for action in actions:
                t = time.monotonic()
                try:
                    params = {"samples": 5} if action == "resource.forecast" else {}
                    r = service.run({"action": action, "parameters": params})
                    record["ops"][action] = {"ok": r.status == "succeeded" and r.verified, "s": round(time.monotonic() - t, 3)}
                except Exception as exc:
                    record["ops"][action] = {"ok": False, "error": type(exc).__name__}
            try:
                health = SensorClient().poll(0, None)["health"]
                record["sensor"] = {k: health.get(k) for k in ("state", "kernel_lost", "queue_dropped", "invalid", "store_errors", "filtered")}
            except Exception as exc:
                record["sensor"] = {"state": "unreachable", "error": type(exc).__name__}
            try:
                store = Store(state / "security.sqlite")
                try: status = store.get("monitor", "status") or {}
                finally: store.close()
                record["monitor"] = {k: status.get(k) for k in ("state", "events", "incidents", "anomalies", "invalid", "gaps")}
                record["monitor"]["age_s"] = round(time.time() - status.get("updated", 0), 1)
            except Exception as exc:
                record["monitor"] = {"state": "unreadable", "error": type(exc).__name__}
            record["rss_kb"] = {"sensor": rss_kb(b"broker_entry.py\x00sensor"), "monitor": rss_kb(b"security.monitor")}
            if "monitor" in required and time.monotonic() >= next_probe:
                record["probe_s"] = probe(state / "security.sqlite")
                next_probe = time.monotonic() + args.probe_every
            up = {"ops": all(o.get("ok") for o in record["ops"].values()),
                  "sensor": record["sensor"].get("state") == "ready",
                  "monitor": record["monitor"].get("state") == "ready" and record["monitor"].get("age_s", 1e9) < 120}
            record["available"] = all(up[c] for c in required)
            log.write(json.dumps(record) + "\n"); log.flush()
            cycle += 1
            time.sleep(max(0.0, args.interval - (time.monotonic() - started)))
    rows = [json.loads(line) for line in out.read_text().splitlines() if line.strip()]
    probes = [r["probe_s"] for r in rows if "probe_s" in r]
    latencies = sorted(o["s"] for r in rows for o in r["ops"].values() if "s" in o)
    rss = [r["rss_kb"]["sensor"] for r in rows if r["rss_kb"].get("sensor")]
    # Host pauses (PC sleep / VM starvation) show up as cycle gaps; report them apart
    # from service unavailability instead of hiding or blaming either.
    gaps = [b["time"] - a["time"] for a, b in zip(rows, rows[1:]) if b["time"] - a["time"] > 3 * args.interval]
    summary = {"components": sorted(required), "cycles": len(rows), "hours": round((rows[-1]["time"] - rows[0]["time"]) / 3600, 2) if rows else 0,
               "availability_pct": round(100 * sum(r["available"] for r in rows) / len(rows), 2) if rows else 0,
               "detection_probes": len(probes), "detection_success": sum(p is not None for p in probes),
               "detection_latency_median_s": statistics.median([p for p in probes if p]) if any(probes) else None,
               "op_latency_p95_s": latencies[int(len(latencies) * 0.95) - 1] if latencies else None,
               "sensor_rss_kb_first_last_max": [rss[0], rss[-1], max(rss)] if rss else None,
               "sensor_loss_final": rows[-1]["sensor"] if rows else None,
               "host_pauses": len(gaps), "host_pause_seconds": round(sum(gaps), 1)}
    Path(str(out) + ".summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
