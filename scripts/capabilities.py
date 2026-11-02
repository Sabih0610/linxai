"""Passive capability inventory; flags/UID are evidence, never proof of BPF control."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.util
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def command(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5, cwd=ROOT)
        return {"returncode": result.returncode, "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"unavailable": str(exc)}


def kernel_flags():
    paths = [Path("/proc/config.gz"), Path(f"/boot/config-{platform.release()}")]
    for path in paths:
        try:
            text = gzip.open(path, "rt").read() if path.suffix == ".gz" else path.read_text()
            names = ("CONFIG_BPF", "CONFIG_BPF_SYSCALL", "CONFIG_BPF_LSM", "CONFIG_BPF_EVENTS", "CONFIG_KPROBES")
            return {"source": str(path), **{name: next((line.split("=", 1)[1] for line in text.splitlines() if line.startswith(name + "=")), "unset_or_unknown") for name in names}}
        except (OSError, UnicodeError):
            pass
    return {"status": "unavailable; no kernel support inferred"}


def report():
    from operations.registry import ACTIONS
    proc = Path("/proc/self/status")
    status = proc.read_text() if proc.exists() else ""
    fields = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status.splitlines() if line.startswith(("CapEff:", "NoNewPrivs:"))}
    pid1 = Path("/proc/1/comm")
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", "/nonexistent"))
    packages = {}
    for name in ("linxai", "uv", "PyYAML", "psutil", "requests", "PySide6"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = None
    snapshot_path = ROOT / "SOURCE_SNAPSHOT.json"
    snapshot = json.loads(snapshot_path.read_text()) if snapshot_path.exists() else None
    if snapshot:
        files = snapshot.pop("files")
        snapshot["files_checked"] = len(files)
        snapshot["mismatches"] = [name for name, expected in files.items()
                                  if not (ROOT / name).is_file() or hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected]
    return {
        "recorded_utc": datetime.now(timezone.utc).isoformat(),
        "environment_kind": "WSL" if "microsoft" in platform.release().lower() else "local_or_hosted_unclassified",
        "os": platform.platform(), "release": platform.release(),
        "os_release": Path("/etc/os-release").read_text() if Path("/etc/os-release").exists() else None,
        "python": {"version": sys.version, "executable": sys.executable, "isolated": sys.prefix != sys.base_prefix},
        "installed_distributions": packages,
        "working_source_snapshot": snapshot,
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "tools": {name: shutil.which(name) for name in ("git", "uv", "pip", "systemctl", "df", "free", "ss", "ollama", "bpftool")},
        "pid1": pid1.read_text().strip() if pid1.exists() else None,
        "systemd_runtime": Path("/run/systemd/system").is_dir(),
        "gui": {"display_configured": bool(os.environ.get("DISPLAY")), "wayland_configured": bool(os.environ.get("WAYLAND_DISPLAY")),
                "x11_socket_present": Path("/tmp/.X11-unix/X0").exists(),
                "wayland_socket_present": (runtime / os.environ.get("WAYLAND_DISPLAY", "missing")).exists(),
                "usable": "not tested by passive inventory"},
        "camera_nodes": [str(p) for p in Path("/dev").glob("video*")] if Path("/dev").exists() else [],
        "kernel": {"flags": kernel_flags(), "btf_vmlinux": Path("/sys/kernel/btf/vmlinux").is_file(),
                   "securityfs_lsm": Path("/sys/kernel/security/lsm").read_text().strip() if os.access("/sys/kernel/security/lsm", os.R_OK) else None,
                   "process_status": fields, "attach_or_enforcement": "NOT TESTED; root/capabilities/config flags do not prove dedicated-kernel control"},
        "optional_imports": {name: importlib.util.find_spec(name) is not None for name in ("bcc", "PySide6", "cv2", "sounddevice", "faster_whisper", "requests")},
        "revision": command(["git", "rev-parse", "HEAD"]),
        "worktree": command(["git", "status", "--short"]),
        "actions": sorted(ACTIONS),
        "operations_sha256": {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT / "operations").glob("*.py"))},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    text = json.dumps(report(), indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
