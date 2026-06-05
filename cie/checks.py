# cie/checks.py
# Individual system state readers for the Command Intelligence Engine.
# Each function reads ONE specific fact from the live Linux system.
# All reads go directly to the kernel — /proc, systemctl, ss, iptables.
# Nothing is cached. Every call reflects the state at the moment it runs.
#
# Return contract for every check function:
# {
#   "check":   str   — the check type that was run
#   "status":  str   — "ok" | "conflict" | "warning" | "error"
#   "found":   any   — what was actually found (port owner, pid, etc.)
#   "reason":  str   — human-readable explanation
#   "detail":  dict  — raw data for logging
# }

import os
import re
import subprocess
import socket
import struct
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 5) -> tuple:
    """
    Run a subprocess command safely.
    Returns (stdout, stderr, returncode).
    Never raises — returns ("", error_msg, -1) on failure.
    """
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s: {cmd}", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -1
    except Exception as e:
        return "", str(e), -1


def _hex_to_ip(hex_ip: str) -> str:
    """Convert /proc/net/tcp hex IP to dotted decimal. Handles little-endian."""
    try:
        packed = int(hex_ip, 16).to_bytes(4, 'little')
        return socket.inet_ntoa(packed)
    except Exception:
        return hex_ip


def _hex_to_port(hex_port: str) -> int:
    """Convert /proc/net/tcp hex port to integer."""
    try:
        return int(hex_port, 16)
    except Exception:
        return 0


def _read_proc_net_tcp(ipv6: bool = False) -> list:
    """
    Reads /proc/net/tcp (and optionally /proc/net/tcp6).
    Returns list of dicts with local_ip, local_port, remote_ip, remote_port, state, inode.
    State 0A = LISTEN, 01 = ESTABLISHED.
    """
    entries = []
    paths = ["/proc/net/tcp"]
    if ipv6:
        paths.append("/proc/net/tcp6")

    for path in paths:
        try:
            with open(path, "r") as f:
                lines = f.readlines()[1:]  # skip header
            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local = parts[1].split(":")
                remote = parts[2].split(":")
                entries.append({
                    "local_ip":    _hex_to_ip(local[0]),
                    "local_port":  _hex_to_port(local[1]),
                    "remote_ip":   _hex_to_ip(remote[0]),
                    "remote_port": _hex_to_port(remote[1]),
                    "state":       parts[3],
                    "inode":       parts[9],
                })
        except Exception as e:
            logger.debug(f"Could not read {path}: {e}")

    return entries


def _inode_to_pid(inode: str) -> Optional[int]:
    """
    Maps a socket inode to a PID by scanning /proc/*/fd/*.
    Returns PID int or None if not found.
    """
    try:
        target = f"socket:[{inode}]"
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            fd_dir = f"/proc/{pid_dir}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    link = os.readlink(f"{fd_dir}/{fd}")
                    if link == target:
                        return int(pid_dir)
            except (PermissionError, FileNotFoundError):
                continue
    except Exception:
        pass
    return None


def _pid_to_name(pid: int) -> str:
    """Returns process name for a PID from /proc/[pid]/comm."""
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except Exception:
        return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Port checks
# ─────────────────────────────────────────────────────────────────────────────

def check_port_free(port: int) -> dict:
    """
    Check if a TCP port is free (not listening).
    Reads /proc/net/tcp directly — no external tools needed.

    Returns conflict if port is in LISTEN state (0A).
    """
    entries = _read_proc_net_tcp(ipv6=True)
    listening = [
        e for e in entries
        if e["local_port"] == port and e["state"] == "0A"
    ]

    if not listening:
        return {
            "check": "port_free",
            "status": "ok",
            "found": None,
            "reason": f"Port {port} is free — nothing is listening on it.",
            "detail": {"port": port, "listening_entries": []}
        }

    # Find which process owns this port
    inode = listening[0]["inode"]
    pid = _inode_to_pid(inode)
    name = _pid_to_name(pid) if pid else "unknown"

    try:
        from system.state import SystemStateRegistry
        _state = SystemStateRegistry()
        rich_msg = _state.format_port_conflict(port)
    except Exception:
        rich_msg = (
            f"Port {port} is already occupied by '{name}' "
            f"(PID {pid}). Starting a new service on this port will fail."
        )
    return {
        "check": "port_free",
        "status": "conflict",
        "found": {"pid": pid, "name": name, "port": port},
        "reason": rich_msg,
        "detail": {"port": port, "pid": pid, "process": name, "inode": inode}
    }


def check_port_occupied(port: int) -> dict:
    """
    Check if a TCP port IS occupied (has something listening).
    Used for commands that require a service to already be running on a port.
    """
    entries = _read_proc_net_tcp(ipv6=True)
    listening = [
        e for e in entries
        if e["local_port"] == port and e["state"] == "0A"
    ]

    if listening:
        inode = listening[0]["inode"]
        pid = _inode_to_pid(inode)
        name = _pid_to_name(pid) if pid else "unknown"
        return {
            "check": "port_occupied",
            "status": "ok",
            "found": {"pid": pid, "name": name, "port": port},
            "reason": f"Port {port} is occupied by '{name}' (PID {pid}) as expected.",
            "detail": {"port": port, "pid": pid, "process": name}
        }

    return {
        "check": "port_occupied",
        "status": "conflict",
        "found": None,
        "reason": f"Port {port} is not occupied — expected a service to be running on it.",
        "detail": {"port": port}
    }


def check_port_range(start: int, end: int) -> dict:
    """
    Check if any port in a range is in use.
    Returns list of occupied ports in the range.
    """
    entries = _read_proc_net_tcp(ipv6=True)
    occupied = []
    for e in entries:
        if start <= e["local_port"] <= end and e["state"] == "0A":
            pid = _inode_to_pid(e["inode"])
            name = _pid_to_name(pid) if pid else "unknown"
            occupied.append({"port": e["local_port"], "pid": pid, "name": name})

    if not occupied:
        return {
            "check": "port_range",
            "status": "ok",
            "found": [],
            "reason": f"No ports occupied in range {start}–{end}.",
            "detail": {"range": [start, end], "occupied": []}
        }

    return {
        "check": "port_range",
        "status": "warning",
        "found": occupied,
        "reason": (
            f"{len(occupied)} port(s) occupied in range {start}–{end}: "
            + ", ".join(str(p["port"]) for p in occupied)
        ),
        "detail": {"range": [start, end], "occupied": occupied}
    }


# ─────────────────────────────────────────────────────────────────────────────
# Service checks
# ─────────────────────────────────────────────────────────────────────────────

def check_service_exists(service: str) -> dict:
    """
    Verify a systemd service unit exists on this system.
    Uses systemctl is-enabled which works for both active and inactive services.
    """
    stdout, stderr, code = _run(["systemctl", "list-unit-files", f"{service}.service"])

    # list-unit-files returns the unit if it exists regardless of state
    if service in stdout:
        return {
            "check": "service_exists",
            "status": "ok",
            "found": service,
            "reason": f"Service '{service}' exists on this system.",
            "detail": {"service": service, "raw": stdout}
        }

    return {
        "check": "service_exists",
        "status": "conflict",
        "found": None,
        "reason": (
            f"Service '{service}' does not exist on this system. "
            f"It may not be installed. Try: apt install {service}"
        ),
        "detail": {"service": service}
    }


def check_service_running(service: str) -> dict:
    """
    Check if a service is currently active (running).
    Uses systemctl is-active for a clean true/false answer.
    """
    stdout, stderr, code = _run(["systemctl", "is-active", service])
    state = stdout.strip()

    if state == "active":
        return {
            "check": "service_running",
            "status": "ok",
            "found": {"service": service, "state": state},
            "reason": f"Service '{service}' is active and running.",
            "detail": {"service": service, "state": state}
        }

    return {
        "check": "service_running",
        "status": "conflict",
        "found": {"service": service, "state": state},
        "reason": (
            f"Service '{service}' is not running (state: {state}). "
            f"Start it first with: systemctl start {service}"
        ),
        "detail": {"service": service, "state": state}
    }


def check_service_stopped(service: str) -> dict:
    """
    Check if a service is currently stopped (inactive).
    Used before operations that require the service to not be running.
    """
    stdout, stderr, code = _run(["systemctl", "is-active", service])
    state = stdout.strip()

    if state in ("inactive", "dead", "failed"):
        return {
            "check": "service_stopped",
            "status": "ok",
            "found": {"service": service, "state": state},
            "reason": f"Service '{service}' is stopped (state: {state}) as required.",
            "detail": {"service": service, "state": state}
        }

    return {
        "check": "service_stopped",
        "status": "conflict",
        "found": {"service": service, "state": state},
        "reason": (
            f"Service '{service}' is currently {state}. "
            f"Stop it first with: systemctl stop {service}"
        ),
        "detail": {"service": service, "state": state}
    }


def check_service_enabled(service: str) -> dict:
    """
    Check if a service is enabled to start on boot.
    """
    stdout, stderr, code = _run(["systemctl", "is-enabled", service])
    state = stdout.strip()

    if state == "enabled":
        return {
            "check": "service_enabled",
            "status": "ok",
            "found": {"service": service, "enabled": True},
            "reason": f"Service '{service}' is enabled to start on boot.",
            "detail": {"service": service, "enabled_state": state}
        }

    return {
        "check": "service_enabled",
        "status": "warning",
        "found": {"service": service, "enabled": False},
        "reason": (
            f"Service '{service}' is not enabled (state: {state}). "
            f"It will not start automatically on reboot."
        ),
        "detail": {"service": service, "enabled_state": state}
    }


# ─────────────────────────────────────────────────────────────────────────────
# Process checks
# ─────────────────────────────────────────────────────────────────────────────

def check_process_running(process: str) -> dict:
    """
    Check if a process by name or PID is currently running.
    Reads /proc directly — no pgrep dependency.

    process: can be a process name (str) or PID (str digit)
    """
    # If it's a PID
    if str(process).isdigit():
        pid = int(process)
        try:
            with open(f"/proc/{pid}/status", "r") as f:
                content = f.read()
            name_match = re.search(r"^Name:\s+(\S+)", content, re.MULTILINE)
            name = name_match.group(1) if name_match else "unknown"
            state_match = re.search(r"^State:\s+(\S+)", content, re.MULTILINE)
            state = state_match.group(1) if state_match else "?"

            return {
                "check": "process_running",
                "status": "ok",
                "found": {"pid": pid, "name": name, "state": state},
                "reason": f"Process {pid} ({name}) is running (state: {state}).",
                "detail": {"pid": pid, "name": name, "state": state}
            }
        except FileNotFoundError:
            return {
                "check": "process_running",
                "status": "conflict",
                "found": None,
                "reason": f"Process with PID {pid} does not exist.",
                "detail": {"pid": pid}
            }

    # Search by name in /proc
    matches = []
    try:
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            try:
                with open(f"/proc/{pid_dir}/comm", "r") as f:
                    comm = f.read().strip()
                if comm == process or comm.startswith(process[:15]):
                    matches.append({"pid": int(pid_dir), "name": comm})
            except (FileNotFoundError, PermissionError):
                continue
    except Exception as e:
        logger.warning(f"Error scanning /proc for process '{process}': {e}")

    if matches:
        return {
            "check": "process_running",
            "status": "ok",
            "found": matches,
            "reason": (
                f"Process '{process}' is running — "
                f"{len(matches)} instance(s) found: "
                + ", ".join(str(m["pid"]) for m in matches[:5])
            ),
            "detail": {"process": process, "matches": matches}
        }

    return {
        "check": "process_running",
        "status": "conflict",
        "found": None,
        "reason": f"Process '{process}' is not running.",
        "detail": {"process": process}
    }


def check_process_not_running(process: str) -> dict:
    """
    Check that a process is NOT running.
    Used before operations that require a clean state.
    """
    result = check_process_running(process)
    if result["status"] == "conflict":
        # Not running = what we want
        return {
            "check": "process_not_running",
            "status": "ok",
            "found": None,
            "reason": f"Process '{process}' is not running as required.",
            "detail": {"process": process}
        }

    return {
        "check": "process_not_running",
        "status": "conflict",
        "found": result["found"],
        "reason": (
            f"Process '{process}' is currently running. "
            f"Stop it before proceeding."
        ),
        "detail": {"process": process, "running": result["found"]}
    }


def check_process_count(process: str, max_count: int = 1) -> dict:
    """
    Check how many instances of a process are running.
    Useful for fork-bomb detection or duplicate service detection.
    """
    result = check_process_running(process)
    if result["status"] == "conflict":
        count = 0
    else:
        found = result["found"]
        count = len(found) if isinstance(found, list) else 1

    if count <= max_count:
        return {
            "check": "process_count",
            "status": "ok",
            "found": count,
            "reason": f"Process '{process}' has {count} instance(s) running (max: {max_count}).",
            "detail": {"process": process, "count": count, "max": max_count}
        }

    return {
        "check": "process_count",
        "status": "warning",
        "found": count,
        "reason": (
            f"Process '{process}' has {count} instances running "
            f"(expected max {max_count}). Possible duplicate or fork issue."
        ),
        "detail": {"process": process, "count": count, "max": max_count}
    }


# ─────────────────────────────────────────────────────────────────────────────
# File system checks
# ─────────────────────────────────────────────────────────────────────────────

def check_file_exists(path: str) -> dict:
    """Check if a file or directory exists at the given path."""
    expanded = os.path.expanduser(path)
    exists = os.path.exists(expanded)
    is_dir = os.path.isdir(expanded) if exists else False
    is_file = os.path.isfile(expanded) if exists else False

    if exists:
        stat = os.stat(expanded)
        return {
            "check": "file_exists",
            "status": "ok",
            "found": {
                "path": expanded,
                "type": "directory" if is_dir else "file",
                "size_bytes": stat.st_size
            },
            "reason": f"{'Directory' if is_dir else 'File'} exists at '{expanded}'.",
            "detail": {"path": expanded, "is_dir": is_dir, "size": stat.st_size}
        }

    return {
        "check": "file_exists",
        "status": "conflict",
        "found": None,
        "reason": f"Path '{expanded}' does not exist.",
        "detail": {"path": expanded}
    }


def check_file_not_exists(path: str) -> dict:
    """Check that a file does NOT exist — used before create operations."""
    result = check_file_exists(path)
    if result["status"] == "conflict":
        return {
            "check": "file_not_exists",
            "status": "ok",
            "found": None,
            "reason": f"Path '{path}' does not exist — safe to create.",
            "detail": {"path": path}
        }

    return {
        "check": "file_not_exists",
        "status": "warning",
        "found": result["found"],
        "reason": f"Path '{path}' already exists. Operation may overwrite it.",
        "detail": {"path": path, "existing": result["found"]}
    }


def check_disk_space(path: str = "/", min_free_gb: float = 1.0) -> dict:
    """
    Check that a path has at least min_free_gb of free disk space.
    Used before package installs, large file operations, etc.
    """
    try:
        stat = os.statvfs(path)
        free_bytes = stat.f_bavail * stat.f_frsize
        total_bytes = stat.f_blocks * stat.f_frsize
        free_gb = free_bytes / (1024 ** 3)
        total_gb = total_bytes / (1024 ** 3)
        used_pct = 100 - (free_bytes / total_bytes * 100)

        if free_gb >= min_free_gb:
            return {
                "check": "disk_space",
                "status": "ok",
                "found": {"free_gb": round(free_gb, 2), "total_gb": round(total_gb, 2)},
                "reason": (
                    f"Disk at '{path}' has {free_gb:.1f}GB free "
                    f"({used_pct:.0f}% used) — sufficient space available."
                ),
                "detail": {"path": path, "free_gb": free_gb, "total_gb": total_gb}
            }

        return {
            "check": "disk_space",
            "status": "conflict",
            "found": {"free_gb": round(free_gb, 2), "total_gb": round(total_gb, 2)},
            "reason": (
                f"Disk at '{path}' only has {free_gb:.2f}GB free "
                f"({used_pct:.0f}% used). Minimum required: {min_free_gb}GB."
            ),
            "detail": {"path": path, "free_gb": free_gb, "min_required": min_free_gb}
        }
    except Exception as e:
        return {
            "check": "disk_space",
            "status": "error",
            "found": None,
            "reason": f"Could not check disk space at '{path}': {e}",
            "detail": {"path": path, "error": str(e)}
        }


def check_path_writable(path: str) -> dict:
    """Check if a path (or its parent directory) is writable by the current user."""
    expanded = os.path.expanduser(path)
    check_path = expanded if os.path.exists(expanded) else os.path.dirname(expanded)

    if os.access(check_path, os.W_OK):
        return {
            "check": "path_writable",
            "status": "ok",
            "found": check_path,
            "reason": f"Path '{check_path}' is writable.",
            "detail": {"path": check_path}
        }

    return {
        "check": "path_writable",
        "status": "conflict",
        "found": check_path,
        "reason": (
            f"Path '{check_path}' is not writable by the current user. "
            f"You may need sudo."
        ),
        "detail": {"path": check_path}
    }


# ─────────────────────────────────────────────────────────────────────────────
# Network checks
# ─────────────────────────────────────────────────────────────────────────────

def check_network_reachable(host: str = "8.8.8.8", port: int = 53,
                             timeout: float = 3.0) -> dict:
    """
    Check basic network reachability by attempting a TCP connection.
    Used before VPS SSH commands, package installs, etc.
    Default target: Google DNS (8.8.8.8:53) — reliable, always available.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return {
            "check": "network_reachable",
            "status": "ok",
            "found": {"host": host, "port": port},
            "reason": f"Network is reachable (connected to {host}:{port}).",
            "detail": {"host": host, "port": port}
        }
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {
            "check": "network_reachable",
            "status": "conflict",
            "found": None,
            "reason": f"Network not reachable — cannot connect to {host}:{port}: {e}",
            "detail": {"host": host, "port": port, "error": str(e)}
        }


def check_firewall_allows_port(port: int, protocol: str = "tcp") -> dict:
    """
    Check if ufw or iptables is blocking a port.
    Checks ufw status first, falls back to iptables if ufw not active.
    Returns warning (not conflict) since firewall rules are complex.
    """
    # Try ufw first
    stdout, stderr, code = _run(["ufw", "status", "verbose"])
    if code == 0 and "Status: active" in stdout:
        port_str = str(port)
        if port_str in stdout or f"{port}/{protocol}" in stdout:
            return {
                "check": "firewall_allows_port",
                "status": "ok",
                "found": {"port": port, "firewall": "ufw"},
                "reason": f"ufw allows port {port}/{protocol}.",
                "detail": {"port": port, "protocol": protocol, "firewall": "ufw"}
            }
        else:
            return {
                "check": "firewall_allows_port",
                "status": "warning",
                "found": {"port": port, "firewall": "ufw"},
                "reason": (
                    f"ufw is active and port {port}/{protocol} does not appear "
                    f"in the allow rules. Traffic may be blocked."
                ),
                "detail": {"port": port, "protocol": protocol}
            }

    # ufw not active or not installed — check iptables
    stdout, stderr, code = _run(
        ["iptables", "-L", "INPUT", "-n", "--line-numbers"]
    )
    if code == 0:
        if str(port) in stdout:
            return {
                "check": "firewall_allows_port",
                "status": "ok",
                "found": {"port": port, "firewall": "iptables"},
                "reason": f"iptables has a rule referencing port {port}.",
                "detail": {"port": port}
            }

    # No active firewall found — port is not blocked
    return {
        "check": "firewall_allows_port",
        "status": "ok",
        "found": {"port": port, "firewall": "none"},
        "reason": f"No active firewall detected. Port {port} is not blocked.",
        "detail": {"port": port}
    }


# ─────────────────────────────────────────────────────────────────────────────
# System resource checks
# ─────────────────────────────────────────────────────────────────────────────

def check_memory_available(min_free_mb: float = 256.0) -> dict:
    """
    Check available system memory from /proc/meminfo.
    MemAvailable is the best measure — accounts for page cache.
    """
    try:
        with open("/proc/meminfo", "r") as f:
            content = f.read()

        available_kb = 0
        total_kb = 0
        for line in content.splitlines():
            if line.startswith("MemAvailable:"):
                available_kb = int(line.split()[1])
            elif line.startswith("MemTotal:"):
                total_kb = int(line.split()[1])

        available_mb = available_kb / 1024
        total_mb = total_kb / 1024
        used_pct = 100 - (available_mb / total_mb * 100)

        if available_mb >= min_free_mb:
            return {
                "check": "memory_available",
                "status": "ok",
                "found": {"available_mb": round(available_mb), "total_mb": round(total_mb)},
                "reason": (
                    f"{available_mb:.0f}MB RAM available "
                    f"({used_pct:.0f}% used) — sufficient."
                ),
                "detail": {"available_mb": available_mb, "total_mb": total_mb}
            }

        return {
            "check": "memory_available",
            "status": "warning",
            "found": {"available_mb": round(available_mb), "total_mb": round(total_mb)},
            "reason": (
                f"Only {available_mb:.0f}MB RAM available "
                f"({used_pct:.0f}% used). Minimum recommended: {min_free_mb}MB."
            ),
            "detail": {"available_mb": available_mb, "min_required": min_free_mb}
        }
    except Exception as e:
        return {
            "check": "memory_available",
            "status": "error",
            "found": None,
            "reason": f"Could not read memory info: {e}",
            "detail": {"error": str(e)}
        }


def check_cpu_load(max_load_pct: float = 90.0) -> dict:
    """
    Check current CPU load from /proc/stat.
    Computes CPU usage over a 200ms window for accuracy.
    """
    import time

    def read_cpu_times():
        with open("/proc/stat", "r") as f:
            line = f.readline()
        values = list(map(int, line.split()[1:]))
        idle = values[3]
        total = sum(values)
        return idle, total

    try:
        idle1, total1 = read_cpu_times()
        time.sleep(0.2)
        idle2, total2 = read_cpu_times()

        idle_delta = idle2 - idle1
        total_delta = total2 - total1

        if total_delta == 0:
            usage_pct = 0.0
        else:
            usage_pct = 100.0 * (1.0 - idle_delta / total_delta)

        if usage_pct <= max_load_pct:
            return {
                "check": "cpu_load",
                "status": "ok",
                "found": {"cpu_pct": round(usage_pct, 1)},
                "reason": f"CPU usage is {usage_pct:.1f}% — within acceptable range.",
                "detail": {"cpu_pct": usage_pct, "max": max_load_pct}
            }

        return {
            "check": "cpu_load",
            "status": "warning",
            "found": {"cpu_pct": round(usage_pct, 1)},
            "reason": (
                f"CPU usage is {usage_pct:.1f}% (above {max_load_pct}%). "
                f"System may be under heavy load."
            ),
            "detail": {"cpu_pct": usage_pct, "max": max_load_pct}
        }
    except Exception as e:
        return {
            "check": "cpu_load",
            "status": "error",
            "found": None,
            "reason": f"Could not measure CPU load: {e}",
            "detail": {"error": str(e)}
        }


# ─────────────────────────────────────────────────────────────────────────────
# User / permission checks
# ─────────────────────────────────────────────────────────────────────────────

def check_user_exists(username: str) -> dict:
    """Check if a user account exists on this system by reading /etc/passwd."""
    try:
        with open("/etc/passwd", "r") as f:
            users = [line.split(":")[0] for line in f if line.strip()]

        if username in users:
            return {
                "check": "user_exists",
                "status": "ok",
                "found": username,
                "reason": f"User '{username}' exists on this system.",
                "detail": {"username": username}
            }

        return {
            "check": "user_exists",
            "status": "conflict",
            "found": None,
            "reason": f"User '{username}' does not exist on this system.",
            "detail": {"username": username}
        }
    except Exception as e:
        return {
            "check": "user_exists",
            "status": "error",
            "found": None,
            "reason": f"Could not check user existence: {e}",
            "detail": {"error": str(e)}
        }


def check_running_as_root() -> dict:
    """Check if the current process has root privileges."""
    is_root = os.geteuid() == 0
    if is_root:
        return {
            "check": "running_as_root",
            "status": "ok",
            "found": True,
            "reason": "Running as root — sudo operations will succeed.",
            "detail": {"euid": 0}
        }

    return {
        "check": "running_as_root",
        "status": "warning",
        "found": False,
        "reason": (
            f"Not running as root (euid={os.geteuid()}). "
            f"Commands requiring sudo will need authentication."
        ),
        "detail": {"euid": os.geteuid()}
    }


def check_package_installed(package: str) -> dict:
    """
    Check if a package is installed via dpkg.
    Uses dpkg-query for reliable installed/not-installed status.
    """
    stdout, stderr, code = _run(
        ["dpkg-query", "-W", "-f=${Status}", package]
    )

    if code == 0 and "install ok installed" in stdout:
        return {
            "check": "package_installed",
            "status": "ok",
            "found": package,
            "reason": f"Package '{package}' is installed.",
            "detail": {"package": package, "dpkg_status": stdout}
        }

    return {
        "check": "package_installed",
        "status": "conflict",
        "found": None,
        "reason": f"Package '{package}' is not installed.",
        "detail": {"package": package}
    }