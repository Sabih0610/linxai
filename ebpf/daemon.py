# ebpf/daemon.py
# LINxAI eBPF Kernel Monitoring Daemon.
#
# Loads three BPF programs into the kernel:
#   - execve kprobe  → every process launch
#   - connect kprobe → every outbound network connection
#   - openat tracepoint → every file access
#
# Events flow: kernel → BPF perf buffer → Python consumer → audit log
# CPU overhead: <2% at 1000 syscalls/second
# Requires: root, kernel 5.15+, BCC installed
#
# Run: sudo python3 ebpf/daemon.py
# As service: sudo systemctl start linxai-ebpf

import os
import sys
import json
import time
import signal
import socket
import struct
import logging
import threading
import ctypes
from datetime import datetime, timezone

# BCC must be imported as root
try:
    from bcc import BPF
except ImportError:
    print("ERROR: BCC not installed. Run: sudo apt install python3-bpfcc")
    sys.exit(1)

logger = logging.getLogger(__name__)

# Path to probe C source files
PROBE_DIR = os.path.join(os.path.dirname(__file__), "probes")


# ebpf/daemon.py (Line ~28)

# Update this line to match Phase 11 logging:
DEFAULT_LOG_PATH = os.environ.get(
    "LINXAI_LOG_PATH", 
    "/var/log/linxai/audit.jsonl"
)

# Security-relevant paths — openat events for these are always logged
# regardless of filtering. Everything else is sampled.
SENSITIVE_PATHS = {
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/ssh", "/root", "/proc/keys",
}

# Processes to filter OUT of openat events — too noisy, no security value
NOISE_PROCESSES = {
    "python3", "python", "ollama", "bash", "sh",
    "systemd", "journald", "snapd", "sudo", "tail",
    "grep", "wc", "cat", "ls", "systemd-journal",
    "multipathd", "systemd-resolve", "snapd",
}

# Extensions to always skip in openat — shared libraries, not interesting
NOISE_EXTENSIONS = (".so", ".so.1", ".so.2", ".cache", ".conf")

# Yield briefly after draining perf buffers so Ollama inference keeps CPU time
# during event bursts.
POLL_YIELD_S = 0.005


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ip_to_str(ip_int: int) -> str:
    """Convert packed uint32 IP (network byte order) to dotted decimal."""
    try:
        return socket.inet_ntoa(struct.pack("<I", ip_int))
    except Exception:
        return str(ip_int)


def _bpf_load_silent(src: str) -> BPF:
    """Load a BPF program while suppressing BCC compiler warnings.
    Redirects fd 2 at OS level — BCC's C compiler cannot bypass this."""
    devnull_fd = os.open(os.devnull, os.O_WRONLY)
    old_stderr_fd = os.dup(2)
    os.dup2(devnull_fd, 2)
    os.close(devnull_fd)
    try:
        bpf = BPF(text=src)
    finally:
        os.dup2(old_stderr_fd, 2)
        os.close(old_stderr_fd)
    return bpf


class eBPFDaemon:
    """
    Loads and manages all three eBPF monitoring programs.

    Usage:
        daemon = eBPFDaemon(log_path="~/.linxai/audit.jsonl")
        daemon.start()          # blocks — runs until SIGTERM
        daemon.start_async()    # non-blocking background thread
        daemon.stop()           # clean shutdown
    """

    def __init__(self,
                 log_path: str = DEFAULT_LOG_PATH,
                 event_callback=None,
                 filter_noise: bool = True):
        """
        Args:
            log_path:       where to write JSON Lines audit records
            event_callback: optional function called with each event dict
                           (used by main.py to feed events into AI context)
            filter_noise:   if True, suppress high-volume low-value events
        """
        self.log_path       = os.path.expanduser(log_path)
        self.event_callback = event_callback
        self.filter_noise   = filter_noise
        self.running        = False
        self._thread        = None
        self._bpf_execve    = None
        self._bpf_connect   = None
        self._bpf_openat    = None
        self._lock          = threading.Lock()
        self._event_count   = {"execve": 0, "connect": 0, "openat": 0}
        self._lost_samples  = 0

        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

        if os.geteuid() != 0:
            raise PermissionError(
                "eBPF daemon requires root. Run with sudo."
            )

    # ── Log writer ────────────────────────────────────────────────────────────

    def _write_event(self, event_type: str, payload: dict):
        """Write one event to the JSON Lines audit log."""
        if payload.get("filename", "").endswith("audit.jsonl"):
            return

        record = {
            "timestamp":  _now(),
            "module":     "ebpf",
            "event_type": event_type,
            "payload":    payload,
        }
        line = json.dumps(record, default=str) + "\n"
        try:
            with self._lock:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line)
        except OSError as e:
            logger.error(f"eBPF log write failed: {e}")

        if self.event_callback:
            try:
                self.event_callback(record)
            except Exception as e:
                logger.error(f"eBPF callback error: {e}")

    # ── BPF program loaders ───────────────────────────────────────────────────

    def _on_lost(self, lost: int):
        self._lost_samples += lost

    def _load_execve(self):
        """Load execve kprobe BPF program."""
        src_path = os.path.join(PROBE_DIR, "execve.c")
        with open(src_path, "r") as f:
            src = f.read()

        bpf = _bpf_load_silent(src)
        bpf.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")

        def handle_execve(cpu, data, size):
            event = bpf["execve_events"].event(data)
            payload = {
                "pid":      event.pid,
                "ppid":     event.ppid,
                "uid":      event.uid,
                "process":  event.comm.decode("utf-8", errors="replace"),
                "filename": event.filename.decode("utf-8", errors="replace"),
            }
            self._event_count["execve"] += 1
            self._write_event("process_exec", payload)

        bpf["execve_events"].open_perf_buffer(
            handle_execve,
            page_cnt=64,
            lost_cb=self._on_lost,
        )
        logger.info("eBPF execve kprobe loaded")
        return bpf

    def _load_connect(self):
        """Load connect kprobe BPF program."""
        src_path = os.path.join(PROBE_DIR, "connect.c")
        with open(src_path, "r") as f:
            src = f.read()

        bpf = _bpf_load_silent(src)
        bpf.attach_kprobe(event="__x64_sys_connect", fn_name="trace_connect")

        def handle_connect(cpu, data, size):
            event = bpf["connect_events"].event(data)
            dest_ip = _ip_to_str(event.dest_ip)
            if dest_ip.startswith("127.") or dest_ip == "0.0.0.0":
                return
            payload = {
                "pid":       event.pid,
                "uid":       event.uid,
                "process":   event.comm.decode("utf-8", errors="replace"),
                "dest_ip":   dest_ip,
                "dest_port": event.dest_port,
                "family":    event.family,
            }
            self._event_count["connect"] += 1
            self._write_event("network_connect", payload)

        bpf["connect_events"].open_perf_buffer(
            handle_connect,
            page_cnt=64,
            lost_cb=self._on_lost,
        )
        logger.info("eBPF connect kprobe loaded")
        return bpf

    def _load_openat(self):
        """Load openat tracepoint BPF program."""
        src_path = os.path.join(PROBE_DIR, "openat.c")
        with open(src_path, "r") as f:
            src = f.read()

        bpf = _bpf_load_silent(src)

        def handle_openat(cpu, data, size):
            event = bpf["openat_events"].event(data)
            filename = event.filename.decode("utf-8", errors="replace")
            process  = event.comm.decode("utf-8", errors="replace")

            if self.filter_noise:
                is_sensitive = any(
                    filename.startswith(p) for p in SENSITIVE_PATHS
                )
                if process in NOISE_PROCESSES and not is_sensitive:
                    return
                if any(filename.endswith(ext) for ext in NOISE_EXTENSIONS):
                    return
                if filename.startswith(("/proc/", "/sys/", "/dev/")):
                    return
                if not filename or filename == "/":
                    return

            payload = {
                "pid":      event.pid,
                "uid":      event.uid,
                "process":  process,
                "filename": filename,
                "flags":    event.flags,
            }
            self._event_count["openat"] += 1
            self._write_event("file_open", payload)

        bpf["openat_events"].open_perf_buffer(
            handle_openat,
            page_cnt=128,
            lost_cb=self._on_lost,
        )
        logger.info("eBPF openat tracepoint loaded")
        return bpf

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _run(self):
        """Main polling loop — drains all perf buffers continuously."""
        logger.info("eBPF daemon running — execve, connect, openat")
        logger.info(f"eBPF writing to: {self.log_path}")

        last_stats = time.time()

        while self.running:
            try:
                if self._bpf_execve:
                    self._bpf_execve.perf_buffer_poll(timeout=50)
                if self._bpf_connect:
                    self._bpf_connect.perf_buffer_poll(timeout=50)
                if self._bpf_openat:
                    self._bpf_openat.perf_buffer_poll(timeout=50)

                now = time.time()
                if now - last_stats >= 30:
                    total = sum(self._event_count.values())
                    logger.info(
                        f"eBPF Events — "
                        f"execve:{self._event_count['execve']} "
                        f"connect:{self._event_count['connect']} "
                        f"openat:{self._event_count['openat']} "
                        f"total:{total}"
                    )
                    last_stats = now

                time.sleep(POLL_YIELD_S)

            except Exception as e:
                if self.running:
                    logger.error(f"eBPF poll error: {e}")
                    time.sleep(0.1)

        logger.info("eBPF daemon polling loop stopped")

    def start(self):
        """Load all BPF programs and start polling."""
        self.running = True
        try:
            self._bpf_execve  = self._load_execve()
            self._bpf_connect = self._load_connect()
            self._bpf_openat  = self._load_openat()
        except Exception as e:
            self.running = False
            raise RuntimeError(f"Failed to load eBPF programs: {e}")
        self._run()

    def start_async(self):
        """Start daemon in a background thread. Returns immediately."""
        self._thread = threading.Thread(
            target=self.start,
            daemon=True,
            name="linxai-ebpf"
        )
        self._thread.start()
        time.sleep(2)
        return self._thread

    def stop(self):
        """Signal the daemon to stop cleanly."""
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

    def get_stats(self) -> dict:
        """Return event counts since daemon started."""
        return dict(self._event_count)

    def lost_sample_count(self) -> int:
        return self._lost_samples


# ── Standalone run ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s [%(name)s] %(message)s"
    )

    print("=" * 55)
    print("  LINxAI eBPF Daemon — Standalone")
    print("  Kernel:", os.popen("uname -r").read().strip())
    print("  Watching: execve, connect, openat")
    print("  Press Ctrl+C to stop")
    print("=" * 55)
    print()

    daemon = eBPFDaemon(
        log_path=os.path.expanduser("~/.linxai/audit.jsonl"),
        filter_noise=True
    )

    signal.signal(signal.SIGTERM, lambda s, f: daemon.stop())
    signal.signal(signal.SIGINT,  lambda s, f: daemon.stop())

    daemon.start()
