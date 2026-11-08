"""Resource optimization benchmark (original requirement 51) and sensor CPU overhead (44).

Five background-load scenarios, sized per pinned CPU. For each, foreground responsiveness is measured
(a) without background load, (b) with background load at nice 0 and (c) after the
background processes were deprioritized through the real typed
`process.priority.lower` action (OperationService, identity-bound, verified).

Foreground metrics: wall time of a fixed CPU task and p95 wake-up latency of
5 ms sleeps. If a root sensor is running, its user-space CPU share during the
whole run is reported (kernel-side probe cost is charged to the traced tasks and
is not separated here). Run as an ordinary user on the target:
    python3 -B scripts/bench_resources.py --out bench.json
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

HOG = "import hashlib\nwhile True: hashlib.sha256(b'x' * 65536).digest()"
IO = "import os\nwhile True:\n    with open(os.devnull, 'wb') as f: f.write(os.urandom(1 << 20))"
BURST = "import time, hashlib\nwhile True:\n    end = time.time() + 0.2\n    while time.time() < end: hashlib.sha256(b'x').digest()\n    time.sleep(0.2)"


def scenarios(n):
    """Background load sized relative to the n CPUs the benchmark is pinned to."""
    return {"one_hog_per_cpu": [HOG] * n, "two_hogs_per_cpu": [HOG] * (2 * n),
            "four_hogs_per_cpu": [HOG] * (4 * n), "mixed_cpu_io": [HOG] * n + [IO] * n,
            "bursty": [BURST] * (2 * n)}


def foreground(repeats=3):
    walls, wakes = [], []
    for _ in range(repeats):
        start = time.perf_counter()
        data = b"y" * (1 << 20)
        for _ in range(40):
            data = hashlib.sha256(data).digest() * 32768
        walls.append(time.perf_counter() - start)
        for _ in range(60):
            t = time.perf_counter(); time.sleep(0.005)
            wakes.append((time.perf_counter() - t - 0.005) * 1000)
    wakes.sort()
    return {"cpu_task_s": round(statistics.median(walls), 4), "wake_p95_ms": round(wakes[int(len(wakes) * 0.95) - 1], 3)}


def cpu_ticks(pid):
    with open(f"/proc/{pid}/stat") as f:
        rest = f.read().rsplit(")", 1)[1].split()
    return int(rest[11]) + int(rest[12])


def sensor_pid():
    for name in os.listdir("/proc"):
        if name.isdigit():
            try:
                if b"broker_entry.py\x00sensor" in Path(f"/proc/{name}/cmdline").read_bytes():
                    return int(name)
            except OSError:
                continue
    return None


def main(argv=None):
    from operations.registry import ActionRegistry
    from operations.service import LocalPolicy, OperationService
    from operations.system import proc_stat
    from operations.workflows import WorkflowSystem
    from test_application import MemoryAudit
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="bench-resources.json")
    parser.add_argument("--cpus", type=int, default=2,
                        help="pin foreground and background to this many CPUs so contention is real but bounded")
    args = parser.parse_args(argv)
    pinned = sorted(os.sched_getaffinity(0))[:max(1, args.cpus)]
    os.sched_setaffinity(0, pinned)  # children inherit the mask
    uid = os.getuid()
    service = OperationService(ActionRegistry(actor_uid=uid), WorkflowSystem(), LocalPolicy(uid), MemoryAudit())
    sensor = sensor_pid()
    sensor_start, wall_start = (cpu_ticks(sensor) if sensor else None), time.monotonic()
    results = {"cpus": os.cpu_count(), "pinned_cpus": pinned, "idle": foreground(), "scenarios": {}}
    for name, programs in scenarios(len(pinned)).items():
        procs = [subprocess.Popen([sys.executable, "-c", p]) for p in programs]
        try:
            time.sleep(1.0)
            loaded = foreground()
            lowered = []
            for proc in procs:
                start = proc_stat(proc.pid)[0]
                r = service.run({"action": "process.priority.lower", "parameters": {"pid": proc.pid, "start_ticks": start, "nice": 19}})
                lowered.append(r.status == "succeeded" and r.verified)
            time.sleep(0.5)
            optimized = foreground()
        finally:
            for proc in procs:
                proc.kill(); proc.wait()
        gain = lambda key: round(100 * (loaded[key] - optimized[key]) / loaded[key], 1) if loaded[key] else None
        results["scenarios"][name] = {"background": len(procs), "loaded": loaded, "optimized": optimized,
                                      "lowered_verified": all(lowered),
                                      "cpu_task_improvement_pct": gain("cpu_task_s"), "wake_p95_improvement_pct": gain("wake_p95_ms")}
        print(name, json.dumps(results["scenarios"][name]), flush=True)
    if sensor:
        elapsed = time.monotonic() - wall_start
        used = (cpu_ticks(sensor) - sensor_start) / os.sysconf("SC_CLK_TCK")
        results["sensor_overhead"] = {"pid": sensor, "cpu_seconds": round(used, 2), "wall_seconds": round(elapsed, 1),
                                      "percent_of_one_cpu": round(100 * used / elapsed, 2),
                                      "percent_of_all_cpus": round(100 * used / elapsed / os.cpu_count(), 2),
                                      "scope": "sensor user-space process only; in-kernel probe cost not separated"}
    Path(args.out).write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({"idle": results["idle"], "sensor_overhead": results.get("sensor_overhead")}))


if __name__ == "__main__":
    main()
