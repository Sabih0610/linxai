"""Service conflict analysis and alternatives (original requirements 19-21).

Runs at preview time with ordinary-user, read-only systemd queries (fixed argv,
shell=False, bounded time). It yields approve / warn / block plus typed
alternative suggestions. "block" is reserved for outcomes that are certain to
fail (missing or masked unit, missing required dependency); confirmation is then
refused. Firewall rules are root-only; an ordinary account can only learn
whether ufw is enabled, which is reported as a warning, never guessed further.
"""
import difflib
import re
import subprocess
from pathlib import Path

SERVICE_ACTIONS = frozenset({"service.start", "service.stop", "service.restart"})
_PROPS = "Id,LoadState,ActiveState,UnitFileState,Requires,Requisite,BindsTo,Conflicts"
UNIT_DIRS = ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system")


def _systemctl(*args, runner=None):
    argv = ("/usr/bin/systemctl", "--no-pager", *args)
    if runner:
        return runner(argv)
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=15, shell=False)
    except (subprocess.TimeoutExpired, OSError):
        return None                          # unknown, never treated as "missing"
    return result.stdout if result.returncode == 0 else ""


def _props(unit, runner):
    text = _systemctl("show", f"--property={_PROPS}", "--", unit, runner=runner)
    if text is None:
        return None
    values = {}
    for line in text.splitlines()[:32]:
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def _units(value):
    return [u for u in value.split() if re.fullmatch(r"[A-Za-z0-9@_.:-]{1,255}", u)][:32]


def ufw_enabled(path="/etc/ufw/ufw.conf"):
    try:
        text = Path(path).read_text()[:65536]
    except OSError:
        return None
    return bool(re.search(r"^\s*ENABLED\s*=\s*yes\s*$", text, re.MULTILINE | re.IGNORECASE))


def free_ports(start, occupied, count=3):
    ports, candidate = [], start + 1
    while len(ports) < count and candidate <= 65535:
        if candidate not in occupied:
            ports.append(candidate)
        candidate += 1
    return ports


def listening_ports(paths=("/proc/net/tcp", "/proc/net/tcp6")):
    ports = set()
    for path in paths:
        try:
            for line in Path(path).read_text().splitlines()[1:4096]:
                fields = line.split()
                if len(fields) > 3 and fields[3] == "0A":            # LISTEN
                    ports.add(int(fields[1].rsplit(":", 1)[1], 16))
        except OSError:
            continue
    return ports


def analyze(action, parameters, *, runner=None, firewall=ufw_enabled, ports=listening_ports):
    """Return {"decision", "findings", "alternatives"} for a typed request."""
    findings, alternatives, block = [], [], False
    if action not in SERVICE_ACTIONS and action != "service.status":
        return {"decision": "approve", "findings": [], "alternatives": []}
    unit = parameters.get("service", "")
    props = _props(unit, runner)
    if props is None or not props.get("LoadState"):
        return {"decision": "warn", "findings": [{"level": "warn", "code": "analysis_unavailable",
                                                  "detail": "systemd state could not be read in time"}], "alternatives": []}
    if props.get("LoadState") == "not-found":
        block = action in SERVICE_ACTIONS
        findings.append({"level": "block" if block else "warn", "code": "unit_not_found", "detail": f"{unit} is not installed"})
        if runner:
            listing = runner(("/usr/bin/systemctl", "--no-pager", "list-unit-files", "--type=service", "--no-legend")) or ""
            names = [line.split()[0] for line in listing.splitlines()[:4096] if line.split()]
        else:
            names = sorted({p.name for d in UNIT_DIRS if Path(d).is_dir() for p in list(Path(d).glob("*.service"))[:4096]})
        for name in difflib.get_close_matches(unit, names, n=3, cutoff=0.6):
            alternatives.append({"reason": "similar installed unit", "request": {"action": action, "parameters": {"service": name}}})
    elif props.get("UnitFileState", "").startswith("masked") and action in {"service.start", "service.restart"}:
        block = True
        findings.append({"level": "block", "code": "unit_masked", "detail": f"{unit} is masked and cannot start"})
    if action in {"service.start", "service.restart"} and props.get("LoadState") == "loaded":
        for dependency in _units(props.get("Requires", "")) + _units(props.get("Requisite", "")) + _units(props.get("BindsTo", "")):
            state = _props(dependency, runner) or {}
            if state.get("LoadState") == "not-found":
                block = True
                findings.append({"level": "block", "code": "dependency_missing", "detail": f"required {dependency} is not installed"})
            elif state.get("ActiveState") == "failed":
                findings.append({"level": "warn", "code": "dependency_failed", "detail": f"required {dependency} is in failed state"})
                if dependency.endswith(".service"):
                    alternatives.append({"reason": "restart the failed dependency first",
                                         "request": {"action": "service.restart", "parameters": {"service": dependency}}})
        for other in _units(props.get("Conflicts", "")):
            if (_props(other, runner) or {}).get("ActiveState") == "active":
                findings.append({"level": "warn", "code": "conflicting_unit_active",
                                 "detail": f"starting {unit} will stop the active conflicting unit {other}"})
        if firewall():
            findings.append({"level": "warn", "code": "firewall_enabled",
                             "detail": "ufw is enabled; inbound access to this service may be blocked (rules are readable only by an administrator)"})
        wanted = parameters.get("port_free")
        if isinstance(wanted, int):
            occupied = ports()
            if wanted in occupied:
                findings.append({"level": "warn", "code": "port_occupied", "detail": f"port {wanted} is already listening; the mandatory port check will fail"})
                for port in free_ports(wanted, occupied):
                    alternatives.append({"reason": "free port", "request": {"action": action, "parameters": {**parameters, "port_free": port}}})
    decision = "block" if block else "warn" if findings else "approve"
    return {"decision": decision, "findings": findings[:16], "alternatives": alternatives[:6]}
