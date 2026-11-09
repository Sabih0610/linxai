"""Bounded process lineage for incidents (original requirement 42).

The kernel sensor records the acting task's (pid, start time, uid). At detection
time the monitor walks the parent chain from procfs (world-readable stat/status
only, never memory or environment), up to MAX_HOPS ancestors. The first hop is
bound to the event by comparing the procfs start time with the kernel start time,
so a recycled PID is reported as `unverified`, never silently trusted. A task that
already exited is reported as `exited`; lineage is evidence, not authority.
"""
import os

MAX_HOPS = 8
TOLERANCE_NS = 50_000_000      # procfs start time has clock-tick (10 ms) granularity


def _stat(proc_root, pid):
    with open(f"{proc_root}/{pid}/stat", "rb") as stream:
        raw = stream.read(4096).decode(errors="replace")
    comm = raw[raw.index("(") + 1:raw.rindex(")")][:64]
    rest = raw[raw.rindex(")") + 2:].split()
    uid = None
    try:
        with open(f"{proc_root}/{pid}/status", "rb") as stream:
            for line in stream.read(8192).decode(errors="replace").splitlines():
                if line.startswith("Uid:"):
                    uid = int(line.split()[1]); break
    except OSError:
        pass
    return {"pid": pid, "comm": comm, "ppid": int(rest[1]), "start_ticks": int(rest[19]), "uid": uid}


def lineage(event, *, proc_root="/proc", hz=None):
    hz = hz or os.sysconf("SC_CLK_TCK")
    pid = event.get("pid")
    try:
        first = _stat(proc_root, pid)
    except (OSError, ValueError, IndexError):
        return {"identity": "exited", "chain": [], "source": "procfs_at_detection"}
    start_ns = event.get("start_ns")
    if start_ns is None:
        identity = "unverified"
    else:
        identity = "verified" if abs(first["start_ticks"] * 1_000_000_000 // hz - start_ns) <= TOLERANCE_NS else "unverified"
    chain, current = [first], first
    while current["ppid"] > 0 and len(chain) <= MAX_HOPS:
        try:
            current = _stat(proc_root, current["ppid"])
        except (OSError, ValueError, IndexError):
            chain.append({"pid": current["ppid"], "comm": None, "exited": True}); break
        chain.append(current)
    for hop in chain:
        hop.pop("ppid", None)
    return {"identity": identity, "chain": chain, "truncated": len(chain) > MAX_HOPS,
            "source": "procfs_at_detection",
            "interpretation": "Ancestors observed when the incident was processed; PIDs are bound by start time only for the first hop"}
