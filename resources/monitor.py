# resource/monitor.py
# System resource monitor for LINxAI.
# Polls CPU, RAM, and per-process metrics every second.
# Auto-renices background processes when CPU exceeds threshold.
#
# Run standalone: python3 resource/monitor.py
# Integrated: ResourceManager runs as background thread in main.py

import os
import time
import logging
import threading
import psutil
from datetime import datetime, timezone
from typing import Optional, Callable

logger = logging.getLogger(__name__)

# CPU threshold — when aggregate usage exceeds this, renice background procs
CPU_THRESHOLD_PCT   = 80.0

# Nice values
BACKGROUND_NICE     = 10    # applied to background procs under load
FOREGROUND_NICE     = 0     # restored when load drops

# Poll interval in seconds
POLL_INTERVAL_S     = 1.0

# Processes classified as foreground — never renice these
FOREGROUND_NAMES = {
    "python3", "python", "ollama", "nginx", "apache2",
    "postgresql", "mysql", "redis", "node", "java",
    "linxai", "main", "uvicorn", "gunicorn",
}

# Processes always treated as background
BACKGROUND_NAMES = {
    "snapd", "update-notifier", "apt", "dpkg",
    "unattended-upgr", "packagekitd", "fwupd",
    "logrotate", "cron", "rsyslogd", "systemd-journal",
    "irqbalance", "thermald", "accounts-daemon",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _classify_process(proc: psutil.Process) -> str:
    """
    Classify a process as 'foreground', 'background', or 'system'.
    Returns one of: 'foreground', 'background', 'system'
    """
    try:
        name = proc.name().lower()
        username = proc.username()

        # System processes — owned by root, very low PID
        if proc.pid < 100:
            return "system"

        # Explicit foreground
        if any(fn in name for fn in FOREGROUND_NAMES):
            return "foreground"

        # Explicit background
        if any(bn in name for bn in BACKGROUND_NAMES):
            return "background"

        # Root-owned daemon processes — treat as system
        if username == "root" and proc.pid > 1:
            return "system"

        # User processes default to foreground
        return "foreground"

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "system"


class ResourceManager:
    """
    Monitors system resources and automatically optimises process priorities.

    When CPU usage exceeds CPU_THRESHOLD_PCT:
      - Background processes are reniced to BACKGROUND_NICE (lower priority)
      - This frees CPU time for foreground processes

    When CPU usage drops below threshold:
      - Reniced background processes are restored to FOREGROUND_NICE

    Usage:
        rm = ResourceManager(log_callback=audit_logger.log_resource_event)
        rm.start()      # starts background monitoring thread
        rm.stop()       # clean shutdown
        rm.get_stats()  # current metrics snapshot
    """

    def __init__(self,
                 cpu_threshold: float = CPU_THRESHOLD_PCT,
                 poll_interval: float = POLL_INTERVAL_S,
                 log_callback: Optional[Callable] = None):
        self.cpu_threshold  = cpu_threshold
        self.poll_interval  = poll_interval
        self.log_callback   = log_callback
        self.running        = False
        self._thread        = None
        self._reniced_pids  = {}   # pid → original_nice
        self._lock          = threading.Lock()
        self._stats         = {
            "cpu_pct":          0.0,
            "memory_pct":       0.0,
            "memory_used_mb":   0,
            "memory_total_mb":  0,
            "renice_count":     0,
            "restore_count":    0,
            "last_updated":     None,
        }

    def _log(self, event_type: str, data: dict):
        """Send event to audit logger if callback is set."""
        if self.log_callback:
            try:
                self.log_callback(event_type, data)
            except Exception as e:
                logger.error(f"Resource log callback error: {e}")

    def _read_cpu(self) -> float:
        """Read current CPU usage percentage (1-second interval)."""
        return psutil.cpu_percent(interval=None)

    def _read_memory(self) -> dict:
        """Read current memory stats from /proc/meminfo via psutil."""
        mem = psutil.virtual_memory()
        return {
            "total_mb":     mem.total    // (1024 * 1024),
            "used_mb":      mem.used     // (1024 * 1024),
            "available_mb": mem.available // (1024 * 1024),
            "percent":      mem.percent,
        }

    def _renice_background_processes(self):
        """
        Find background processes and lower their priority.
        Only renices processes that are actually consuming CPU.
        Records original nice values for later restoration.
        """
        reniced = []
        for proc in psutil.process_iter(['pid', 'name', 'nice', 'cpu_percent']):
            try:
                pid = proc.info['pid']
                if pid in self._reniced_pids:
                    continue   # already reniced

                classification = _classify_process(proc)
                if classification != "background":
                    continue

                original_nice = proc.nice()
                if original_nice >= BACKGROUND_NICE:
                    continue   # already low priority

                # Only renice if it's using some CPU
                cpu = proc.cpu_percent(interval=0.1)
                if cpu < 0.5:
                    continue

                os.nice   # check available
                proc.nice(BACKGROUND_NICE)
                self._reniced_pids[pid] = original_nice

                reniced.append({
                    "pid":           pid,
                    "name":          proc.name(),
                    "original_nice": original_nice,
                    "new_nice":      BACKGROUND_NICE,
                })

                logger.info(
                    f"Reniced '{proc.name()}' (PID {pid}): "
                    f"{original_nice} → {BACKGROUND_NICE}"
                )

            except (psutil.NoSuchProcess, psutil.AccessDenied,
                    ProcessLookupError):
                continue

        if reniced:
            self._stats["renice_count"] += len(reniced)
            self._log("renice_applied", {
                "reason":   f"CPU above {self.cpu_threshold}%",
                "reniced":  reniced,
                "count":    len(reniced),
            })

        return reniced

    def _restore_priorities(self):
        """
        Restore original nice values for all previously reniced processes.
        Called when CPU load drops below threshold.
        """
        restored = []
        stale_pids = []

        for pid, original_nice in list(self._reniced_pids.items()):
            try:
                proc = psutil.Process(pid)
                proc.nice(original_nice)
                restored.append({
                    "pid":           pid,
                    "name":          proc.name(),
                    "restored_nice": original_nice,
                })
                logger.info(
                    f"Restored '{proc.name()}' (PID {pid}) "
                    f"nice → {original_nice}"
                )
            except (psutil.NoSuchProcess, ProcessLookupError):
                stale_pids.append(pid)
            except psutil.AccessDenied:
                pass

        # Remove pids that no longer exist
        for pid in stale_pids + [r["pid"] for r in restored]:
            self._reniced_pids.pop(pid, None)

        if restored:
            self._stats["restore_count"] += len(restored)
            self._log("priority_restored", {
                "reason":   f"CPU below {self.cpu_threshold}%",
                "restored": restored,
                "count":    len(restored),
            })

        return restored

    def _poll_once(self):
        """One monitoring cycle — read metrics, decide, act."""
        cpu_pct = self._read_cpu()
        mem     = self._read_memory()

        with self._lock:
            self._stats.update({
                "cpu_pct":         cpu_pct,
                "memory_pct":      mem["percent"],
                "memory_used_mb":  mem["used_mb"],
                "memory_total_mb": mem["total_mb"],
                "last_updated":    _now(),
            })

        # Act on CPU threshold
        if cpu_pct >= self.cpu_threshold:
            self._renice_background_processes()
        elif self._reniced_pids:
            # CPU dropped — restore priorities
            self._restore_priorities()

    def _run(self):
        """Main monitoring loop."""
        logger.info(
            f"ResourceManager started — "
            f"threshold={self.cpu_threshold}%, "
            f"poll={self.poll_interval}s"
        )
        print(
            f"[Resource] Monitor running — "
            f"CPU threshold: {self.cpu_threshold}%"
        )

        # Prime CPU percentage (first call always returns 0.0)
        psutil.cpu_percent(interval=None)
        time.sleep(self.poll_interval)

        while self.running:
            try:
                self._poll_once()
            except Exception as e:
                logger.error(f"ResourceManager poll error: {e}")
            time.sleep(self.poll_interval)

        logger.info("ResourceManager stopped.")

    def start(self):
        """Start monitoring in a background daemon thread."""
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="linxai-resource"
        )
        self._thread.start()

    def stop(self):
        """Stop monitoring and restore all reniced processes."""
        self.running = False
        if self._reniced_pids:
            self._restore_priorities()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        print("[Resource] Monitor stopped.")

    def get_stats(self) -> dict:
        """Return current resource snapshot."""
        with self._lock:
            return dict(self._stats)

    def get_top_processes(self, n: int = 10) -> list:
        """
        Return top N processes by CPU usage.
        Used by main.py to show resource status.
        """
        procs = []
        for proc in psutil.process_iter(
            ['pid', 'name', 'cpu_percent', 'memory_percent', 'nice']
        ):
            try:
                procs.append({
                    "pid":        proc.info['pid'],
                    "name":       proc.info['name'],
                    "cpu_pct":    round(proc.info['cpu_percent'], 1),
                    "mem_pct":    round(proc.info['memory_percent'], 1),
                    "nice":       proc.info['nice'],
                    "class":      _classify_process(proc),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return sorted(procs, key=lambda p: p["cpu_pct"], reverse=True)[:n]


# ── Standalone run ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import signal

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s [%(name)s] %(message)s"
    )

    print("=" * 55)
    print("  LINxAI Resource Manager — Live Monitor")
    print(f"  CPU threshold: {CPU_THRESHOLD_PCT}%")
    print(f"  Poll interval: {POLL_INTERVAL_S}s")
    print("  Press Ctrl+C to stop")
    print("=" * 55)
    print()

    rm = ResourceManager()
    rm.start()

    signal.signal(signal.SIGINT, lambda s, f: rm.stop())

    try:
        while rm.running:
            time.sleep(3)
            stats = rm.get_stats()
            print(
                f"  CPU: {stats['cpu_pct']:5.1f}%  "
                f"RAM: {stats['memory_pct']:5.1f}%  "
                f"({stats['memory_used_mb']}MB / "
                f"{stats['memory_total_mb']}MB)  "
                f"reniced: {stats['renice_count']}  "
                f"restored: {stats['restore_count']}"
            )
    except KeyboardInterrupt:
        rm.stop()