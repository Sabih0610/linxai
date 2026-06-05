# system/state.py
# LINxAI System State Registry
# Maintains a live snapshot of ports, services, processes, and resources.
# Updates on-demand with 30-second cache.
# Fed into CIE for rich conflict messages and chat responder for answers.

import os
import re
import socket
import struct
import subprocess
import threading
import time
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Known port → (description, criticality)
PORT_MAP = {
    21:    ("FTP",               "MEDIUM"),
    22:    ("SSH",               "CRITICAL"),
    23:    ("Telnet",            "HIGH"),
    25:    ("SMTP",              "MEDIUM"),
    53:    ("DNS",               "HIGH"),
    80:    ("HTTP web server",   "HIGH"),
    443:   ("HTTPS web server",  "HIGH"),
    3306:  ("MySQL database",    "HIGH"),
    5432:  ("PostgreSQL database","HIGH"),
    27017: ("MongoDB database",  "HIGH"),
    6379:  ("Redis cache",       "MEDIUM"),
    8080:  ("HTTP alternate",    "MEDIUM"),
    8443:  ("HTTPS alternate",   "MEDIUM"),
    3000:  ("Development server","LOW"),
    5000:  ("Development server","LOW"),
    8000:  ("Development server","LOW"),
    9000:  ("Development server","LOW"),
    11434: ("Ollama AI server",  "LOW"),
}

CRITICALITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def _run(cmd: list, timeout: int = 5) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _hex_to_ip(hex_ip: str) -> str:
    try:
        packed = int(hex_ip, 16).to_bytes(4, 'little')
        return socket.inet_ntoa(packed)
    except Exception:
        return hex_ip


def _hex_to_port(hex_port: str) -> int:
    try:
        return int(hex_port, 16)
    except Exception:
        return 0


def _inode_to_pid(inode: str):
    try:
        target = f"socket:[{inode}]"
        for pid_dir in os.listdir("/proc"):
            if not pid_dir.isdigit():
                continue
            fd_dir = f"/proc/{pid_dir}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        link = os.readlink(f"{fd_dir}/{fd}")
                        if link == target:
                            return int(pid_dir)
                    except Exception:
                        continue
            except (PermissionError, FileNotFoundError):
                continue
    except Exception:
        pass
    return None


def _pid_to_name(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except Exception:
        return "unknown"


def _pid_uptime_seconds(pid: int) -> int:
    try:
        with open("/proc/uptime", "r") as f:
            uptime_s = float(f.read().split()[0])
        with open(f"/proc/{pid}/stat", "r") as f:
            stat = f.read().split()
        starttime_ticks = int(stat[21])
        ticks_per_sec = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        starttime_s = starttime_ticks / ticks_per_sec
        return int(uptime_s - starttime_s)
    except Exception:
        return 0


def _format_uptime(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m"
    elif seconds < 86400:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        return f"{h}h {m}m"
    else:
        d = seconds // 86400
        h = (seconds % 86400) // 3600
        return f"{d}d {h}h"


def _read_listening_ports() -> list:
    entries = []
    for path in ["/proc/net/tcp", "/proc/net/tcp6"]:
        try:
            with open(path, "r") as f:
                lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue
                if parts[3] != "0A":
                    continue
                local = parts[1].split(":")
                port = _hex_to_port(local[1])
                inode = parts[9]
                pid = _inode_to_pid(inode)
                name = _pid_to_name(pid) if pid else "unknown"
                uptime = _pid_uptime_seconds(pid) if pid else 0
                entries.append({
                    "port": port,
                    "pid": pid,
                    "process": name,
                    "uptime_seconds": uptime,
                    "inode": inode,
                })
        except Exception:
            continue
    seen = {}
    for e in entries:
        if e["port"] not in seen:
            seen[e["port"]] = e
    return list(seen.values())


def _read_resources() -> dict:
    cpu_pct = 0.0
    try:
        def read_cpu():
            with open("/proc/stat", "r") as f:
                line = f.readline()
            vals = list(map(int, line.split()[1:]))
            return vals[3], sum(vals)
        idle1, total1 = read_cpu()
        time.sleep(0.2)
        idle2, total2 = read_cpu()
        delta_total = total2 - total1
        delta_idle = idle2 - idle1
        if delta_total > 0:
            cpu_pct = round(100.0 * (1.0 - delta_idle / delta_total), 1)
    except Exception:
        pass

    mem_pct = 0.0
    try:
        with open("/proc/meminfo", "r") as f:
            content = f.read()
        total = int(re.search(r"MemTotal:\s+(\d+)", content).group(1))
        available = int(re.search(r"MemAvailable:\s+(\d+)", content).group(1))
        mem_pct = round(100.0 * (total - available) / total, 1)
    except Exception:
        pass

    disk_pct = 0.0
    try:
        import shutil
        total_d, used_d, free_d = shutil.disk_usage("/")
        disk_pct = round(100.0 * used_d / total_d, 1)
    except Exception:
        pass

    return {"cpu_pct": cpu_pct, "memory_pct": mem_pct, "disk_pct": disk_pct}


class SystemStateRegistry:

    def __init__(self, cache_ttl_seconds: int = 30):
        self.cache_ttl = cache_ttl_seconds
        self._snapshot = {}
        self._last_update = 0.0
        self._lock = threading.Lock()
        self.refresh()
        logger.info("System state registry ready")

    def refresh(self):
        with self._lock:
            ports = {}
            for entry in _read_listening_ports():
                p = entry["port"]
                desc, crit = PORT_MAP.get(p, (f"port {p}", "UNKNOWN"))
                ports[p] = {
                    "process":         entry["process"],
                    "pid":             entry["pid"],
                    "criticality":     crit,
                    "description":     desc,
                    "uptime_seconds":  entry["uptime_seconds"],
                    "uptime_human":    _format_uptime(entry["uptime_seconds"]),
                }

            resources = _read_resources()

            if resources["cpu_pct"] > 90:
                health = "CRITICAL"
            elif resources["cpu_pct"] > 70 or resources["memory_pct"] > 85:
                health = "WARNING"
            elif resources["disk_pct"] > 90:
                health = "WARNING"
            else:
                health = "HEALTHY"

            self._snapshot = {
                "ports":      ports,
                "resources":  resources,
                "health":     health,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            self._last_update = time.time()
            logger.info(f"System state refreshed — {len(ports)} ports, health={health}")

    def get_snapshot(self) -> dict:
        if time.time() - self._last_update > self.cache_ttl:
            self.refresh()
        return self._snapshot

    def get_port_info(self, port: int) -> dict:
        snapshot = self.get_snapshot()
        return snapshot["ports"].get(port)

    def get_all_ports(self) -> dict:
        return self.get_snapshot()["ports"]

    def get_resources(self) -> dict:
        return self.get_snapshot()["resources"]

    def get_health(self) -> str:
        return self.get_snapshot()["health"]

    def format_port_conflict(self, port: int) -> str:
        info = self.get_port_info(port)
        if not info:
            return f"Port {port} is in use."
        lines = [
            f"Port {port} is occupied by '{info['process']}' (PID {info['pid']})",
            f"  Criticality : {info['criticality']} — {info['description']}",
            f"  Running for : {info['uptime_human']}",
        ]
        if info["criticality"] in ("CRITICAL", "HIGH"):
            lines.append(f"  Warning     : Stopping this may break critical system functionality")
        return "\n".join(lines)

    def format_health_summary(self) -> str:
        snap = self.get_snapshot()
        res = snap["resources"]
        ports = snap["ports"]
        lines = [
            f"System Health: {snap['health']}",
            f"  CPU: {res['cpu_pct']}%  |  Memory: {res['memory_pct']}%  |  Disk: {res['disk_pct']}%",
            f"  Active ports: {len(ports)}",
        ]
        critical = [p for p, info in ports.items() if info["criticality"] == "CRITICAL"]
        high = [p for p, info in ports.items() if info["criticality"] == "HIGH"]
        if critical:
            lines.append(f"  CRITICAL: {', '.join(str(p) + '/' + ports[p]['process'] for p in critical)}")
        if high:
            lines.append(f"  HIGH    : {', '.join(str(p) + '/' + ports[p]['process'] for p in high)}")
        return "\n".join(lines)

    def is_port_suspicious(self, port: int) -> bool:
        if port in PORT_MAP:
            return False
        info = self.get_port_info(port)
        if not info:
            return False
        suspicious_processes = {"nc", "ncat", "netcat", "socat", "perl", "ruby", "python3"}
        return info["process"] in suspicious_processes
