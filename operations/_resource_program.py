"""Fixed /proc resource worker run with `python3 -I -c`; never receives shell text."""
# Pure forecasting math, shared verbatim with tests (requirement 50).
FORECAST_MATH = r'''
def trend(values, dt):
    """Least-squares slope per second and EWMA level of evenly spaced samples."""
    n = len(values)
    xs = [i * dt for i in range(n)]
    mx, my = sum(xs) / n, sum(values) / n
    var = sum((x - mx) ** 2 for x in xs)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, values)) / var if var else 0.0
    level = values[0]
    for v in values[1:]:
        level = 0.5 * v + 0.5 * level
    return slope, level
def forecast(values, dt, horizon, low=0.0, high=100.0):
    slope, level = trend(values, dt)
    return max(low, min(high, level + slope * horizon)), slope, level
'''
RESOURCE_PROGRAM = FORECAST_MATH + r'''
import json, os, sys, time
INTERACTIVE = {"gnome-shell", "Xorg", "Xwayland", "firefox", "chrome", "chromium", "code",
               "gnome-terminal-", "konsole", "plasmashell", "kwin_x11", "kwin_wayland"}
def stat(pid, tid=None):
    path = f"/proc/{pid}/stat" if tid is None else f"/proc/{pid}/task/{tid}/stat"
    with open(path, "rb") as f: text = f.read(4096).decode("utf-8", "replace")
    rest = text[text.rindex(")") + 2:].split()
    return {"comm": text[text.index("(") + 1:text.rindex(")")][:64], "state": rest[0], "ppid": int(rest[1]),
            "tty": int(rest[4]), "ticks": int(rest[11]) + int(rest[12]), "nice": int(rest[16]),
            "threads": int(rest[17]), "start": int(rest[19])}
def owner_of(pid):
    with open(f"/proc/{pid}/status", "rb") as f:
        for line in f.read(8192).decode("utf-8", "replace").splitlines():
            if line.startswith("Uid:"): return int(line.split()[1])
    raise ValueError("uid unavailable")
def classify(s, owner):
    if owner < 1000 or s["ppid"] in (0, 2): return "system"
    return "interactive" if s["tty"] != 0 or s["comm"] in INTERACTIVE else "background"
def identity(pid, start, owner):
    s = stat(pid)
    if s["start"] != start or owner_of(pid) != owner: raise PermissionError("process identity changed")
    return s
def tids(pid):
    names = os.listdir(f"/proc/{pid}/task")
    if len(names) > 1024: raise ValueError("thread count exceeds bound")
    return [int(n) for n in names]
def cpu_total():
    with open("/proc/stat", "rb") as f: v = [int(x) for x in f.readline().split()[1:]]
    return sum(v), v[3] + (v[4] if len(v) > 4 else 0)
cmd = sys.argv[1]
if cmd == "list":
    limit = int(sys.argv[2])
    pids = [int(n) for n in os.listdir("/proc") if n.isdigit()][:4096]
    def sample():
        out = {}
        for p in pids:
            try: out[p] = stat(p)
            except (OSError, ValueError, IndexError): pass
        return out
    t1, i1 = cpu_total(); a = sample(); time.sleep(0.5); t2, i2 = cpu_total(); b = sample()
    span, ncpu = max(t2 - t1, 1), os.cpu_count() or 1
    procs = []
    for p, s in b.items():
        if p not in a or a[p]["start"] != s["start"]: continue
        try: owner = owner_of(p)
        except (OSError, ValueError): continue
        procs.append({"pid": p, "start_ticks": s["start"], "uid": owner, "comm": s["comm"], "nice": s["nice"],
                      "state": s["state"], "threads": s["threads"], "class": classify(s, owner),
                      "cpu_percent": round(100.0 * (s["ticks"] - a[p]["ticks"]) * ncpu / span, 1)})
    procs.sort(key=lambda r: r["cpu_percent"], reverse=True)
    with open("/proc/loadavg") as f: load = [float(x) for x in f.read().split()[:3]]
    memory = {}
    with open("/proc/meminfo") as f:
        for line in f:
            key, value = line.split(":", 1)
            if key in ("MemTotal", "MemAvailable"): memory[key] = int(value.split()[0]) * 1024
    print(json.dumps({"cpu_percent": round(100.0 * (1 - (i2 - i1) / span), 1), "cpus": ncpu, "load": load,
                      "memory": memory, "observed": len(procs), "processes": procs[:limit]}))
elif cmd in ("lower", "restore"):
    pid, start, nice, owner = map(int, sys.argv[2:6])
    if cmd == "lower" and os.getuid() != owner: raise PermissionError("lowering runs as the process owner")
    prior = identity(pid, start, owner)["nice"]
    if cmd == "lower" and not nice > prior: raise ValueError("lowering priority requires a higher nice value")
    if cmd == "restore" and not nice < prior: raise ValueError("restoration requires a lower nice value")
    changed = failed = 0
    for tid in tids(pid):
        try:
            os.setpriority(os.PRIO_PROCESS, tid, nice); changed += 1
        except ProcessLookupError: pass
        except PermissionError: failed += 1
    after = identity(pid, start, owner)
    remaining = []
    for tid in tids(pid):
        try: remaining.append(stat(pid, tid)["nice"])
        except FileNotFoundError: pass
    verified = failed == 0 and after["nice"] == nice and all(n == nice for n in remaining)
    result = {"verified": verified, "pid": pid, "start_ticks": start, "prior_nice": prior, "nice": after["nice"],
              "threads_changed": changed, "threads_failed": failed}
    if cmd == "lower" and verified and prior >= 0:
        result["restoration"] = {"action": "process.priority.restore",
                                 "parameters": {"pid": pid, "start_ticks": start, "nice": prior}}
    print(json.dumps(result))
    sys.exit(0 if verified else 1)
elif cmd == "forecast":
    samples, horizon, dt = int(sys.argv[2]), int(sys.argv[3]), 0.5
    def mem_available():
        with open("/proc/meminfo") as f:
            values = {k: int(v.split()[0]) * 1024 for k, v in (line.split(":", 1) for line in f)}
        return values["MemTotal"], values["MemAvailable"]
    cpu, mem = [], []
    last = cpu_total()
    total = mem_available()[0]
    for _ in range(samples):
        time.sleep(dt)
        now = cpu_total()
        span = max(now[0] - last[0], 1)
        cpu.append(round(100.0 * (1 - (now[1] - last[1]) / span), 2))
        mem.append(100.0 * (1 - mem_available()[1] / total))
        last = now
    cpu_pred, cpu_slope, cpu_level = forecast(cpu, dt, horizon)
    mem_pred, mem_slope, mem_level = forecast(mem, dt, horizon)
    risks = []
    if cpu_pred >= 80: risks.append("cpu_pressure_expected")
    if mem_pred >= 90: risks.append("memory_pressure_expected")
    seconds_to_full = round((100 - mem_level) / mem_slope) if mem_slope > 0 else None
    candidates = []
    if risks:
        me = os.getuid()
        for name in os.listdir("/proc")[:4096]:
            if not name.isdigit(): continue
            try:
                s, owner = stat(int(name)), owner_of(int(name))
            except (OSError, ValueError, IndexError): continue
            if owner == me and classify(s, owner) == "background" and s["nice"] < 19:
                candidates.append({"pid": int(name), "start_ticks": s["start"], "comm": s["comm"], "nice": s["nice"], "ticks": s["ticks"]})
        candidates = sorted(candidates, key=lambda c: c["ticks"], reverse=True)[:5]
    print(json.dumps({"samples": samples, "interval_s": dt, "horizon_s": horizon,
                      "cpu": {"observed": cpu, "level": round(cpu_level, 2), "slope_per_s": round(cpu_slope, 4), "predicted": round(cpu_pred, 2)},
                      "memory": {"level": round(mem_level, 2), "slope_per_s": round(mem_slope, 5), "predicted": round(mem_pred, 2),
                                 "seconds_to_exhaustion": seconds_to_full},
                      "risks": risks, "recommendations": candidates,
                      "interpretation": "Short-window trend forecast; recommendations require an explicit process.priority.lower preview"}))
elif cmd == "path":
    # Requirement 18: read-only metadata of an absolute path and its parents; never
    # follows the final symlink and never reads file contents.
    import pwd, grp, stat
    target = sys.argv[2]
    def name_of(fn, ident):
        try: return fn(ident)[0]
        except KeyError: return None
    def describe(path):
        info = os.lstat(path)
        kind = ("symlink" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode)
                else "file" if stat.S_ISREG(info.st_mode) else "other")
        row = {"path": path, "type": kind, "uid": info.st_uid, "owner": name_of(pwd.getpwuid, info.st_uid),
               "gid": info.st_gid, "group": name_of(grp.getgrgid, info.st_gid), "mode": oct(stat.S_IMODE(info.st_mode)),
               "size": info.st_size if kind == "file" else None,
               "world_writable": bool(info.st_mode & 0o002) and kind != "symlink",
               "sticky": bool(info.st_mode & stat.S_ISVTX)}
        if kind == "symlink": row["link_target"] = os.readlink(path)[:4096]
        return row
    parts = [target] + [str(p) for p in __import__("pathlib").PurePosixPath(target).parents]
    chain, exists = [], True
    for p in parts:
        try: chain.append(describe(p))
        except FileNotFoundError:
            if p == target: exists = False
        except PermissionError:
            chain.append({"path": p, "type": "unreadable"})
    access = {m: os.access(target, f, follow_symlinks=False) for m, f in (("read", os.R_OK), ("write", os.W_OK), ("execute", os.X_OK))} if exists else None
    risks = [r["path"] for r in chain[1:] if r.get("world_writable") and not r.get("sticky")]
    print(json.dumps({"observed": True, "path": target, "exists": exists, "chain": chain[:64], "actor_access": access,
                      "unsafe_parents": risks, "interpretation": "Metadata only; contents are never read"}))
elif cmd == "user":
    # Requirement 18: account facts from the passwd/group databases (no shadow access).
    import pwd, grp
    key = sys.argv[2]
    try:
        entry = pwd.getpwuid(int(key)) if key.isdigit() else pwd.getpwnam(key)
    except KeyError:
        print(json.dumps({"observed": True, "query": key, "exists": False})); raise SystemExit(0)
    groups = sorted({g.gr_name for g in grp.getgrall() if entry.pw_name in g.gr_mem} | {name for name in [
        next((g.gr_name for g in grp.getgrall() if g.gr_gid == entry.pw_gid), None)] if name})
    print(json.dumps({"observed": True, "query": key, "exists": True, "name": entry.pw_name, "uid": entry.pw_uid,
                      "gid": entry.pw_gid, "home": entry.pw_dir, "shell": entry.pw_shell, "groups": groups[:128],
                      "administrative_groups": sorted(set(groups) & {"sudo", "adm", "wheel", "admin", "root"}),
                      "login_shell": not entry.pw_shell.endswith(("nologin", "/false")),
                      "is_actor": entry.pw_uid == os.getuid()}))
else:
    raise SystemExit("unsupported resource command")
'''
