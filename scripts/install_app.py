"""Install only the ordinary-user typed application into a dedicated user prefix.

No OS packages, system services, models, PAM or shell profiles are modified.
Existing prefixes are refused; uninstall explicitly before replacing an install.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
RECEIPT = ".linxai-install.json"


def ordinary_user():
    if sys.platform != "linux":
        raise ValueError("Installation requires Linux; Windows supports offline development only")
    if os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        raise ValueError("Run as an ordinary user, without sudo or set-ID context")


def safe_chain(path):
    """Reject symlinks, foreign owners and writable ancestor directories."""
    for item in reversed((path, *path.parents)):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise ValueError(f"Unsafe installation directory: {item}")


def prefix_path(value):
    raw = Path(value).expanduser()
    if not raw.is_absolute() or ".." in raw.parts:
        raise ValueError("Prefix must be an absolute path without traversal")
    if raw == Path(raw.anchor) or raw == Path.home() or raw == ROOT or ROOT.is_relative_to(raw):
        raise ValueError("Prefix must be a dedicated application directory")
    return raw


def launcher(python, module="operations.cli"):
    if module not in {"operations.cli", "operations.agent", "ui.desktop", "security.monitor"}:
        raise ValueError("Unsupported installed launcher")
    # Guard before importing any user-owned Python code. "$@" preserves each argument.
    return f'''#!/bin/sh
set -eu
uid=$(/usr/bin/id -u)
if [ "$uid" = 0 ] || [ "$uid" != "$(/usr/bin/id -ur)" ] || [ "$(/usr/bin/id -g)" != "$(/usr/bin/id -gr)" ]; then
    echo 'LINxAI requires an ordinary user; sudo/set-ID startup is refused.' >&2
    exit 2
fi
unset PYTHONPATH PYTHONHOME
exec {shlex.quote(str(python))} -I -B -m {module} "$@"
'''


def uninstall(prefix):
    safe_chain(prefix)
    info = prefix.lstat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Installation prefix must be private and owned by the caller")
    receipt = prefix / RECEIPT
    info = receipt.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        raise ValueError("Unsafe installation receipt")
    data = json.loads(receipt.read_text())
    if data.get("schema") != 1 or data.get("prefix") != str(prefix) or data.get("uid") != os.getuid():
        raise ValueError("Installation receipt does not match prefix/caller")
    if set(p.name for p in prefix.iterdir()) - {RECEIPT, "venv", "bin"}:
        raise ValueError("Unrelated files in prefix; review before uninstalling")
    # rmtree must use fd-based symlink protection. Never follow an altered venv/bin.
    if not shutil.rmtree.avoids_symlink_attacks:
        raise ValueError("Safe recursive removal unavailable on this platform")
    for name in ("bin", "venv"):
        child = prefix / name
        if child.is_symlink():
            raise ValueError(f"Refusing altered installation symlink: {child}")
        if child.exists():
            shutil.rmtree(child)
    receipt.unlink()
    prefix.rmdir()


def install(prefix, offline=False, desktop=False, voice=False):
    # Only create missing parents under a verified chain; do not repair permissions.
    missing = []
    parent = prefix.parent
    while not parent.exists() and not parent.is_symlink():
        missing.append(parent)
        parent = parent.parent
    safe_chain(parent)
    for item in reversed(missing):
        item.mkdir(mode=0o700)
        safe_chain(item)
    safe_chain(prefix.parent)
    prefix.mkdir(mode=0o700)  # Exclusive: preserve every existing install/unrelated file.
    receipt = {"schema": 1, "prefix": str(prefix), "uid": os.getuid(), "state": "incomplete",
               "lock_sha256": hashlib.sha256((ROOT / "uv.lock").read_bytes()).hexdigest()}
    (prefix / RECEIPT).write_text(json.dumps(receipt, indent=2) + "\n")
    target = prefix / "venv"
    command = [sys.executable, "-I", str(ROOT / "scripts/setup_dev.py"), "--venv", str(target), "--no-editable"]
    if desktop:
        command.extend(["--extra", "desktop"])
    if voice:
        command.extend(["--extra", "voice"])
    if offline:
        command.append("--offline")
    subprocess.run(command, check=True, timeout=600)
    python = target / "bin/python"
    # Run outside the checkout; prove imports come from the installed wheel.
    probe = subprocess.check_output([str(python), "-I", "-c", "import operations; print(operations.__file__)"],
                                    cwd=prefix, text=True, timeout=20).strip()
    if not Path(probe).resolve().is_relative_to(target.resolve()):
        raise ValueError("Application import did not resolve inside the installed environment")
    directory = prefix / "bin"
    directory.mkdir(mode=0o700)
    for name, module in (("linxai", "operations.cli"), ("linxai-ops", "operations.cli"), ("linxai-agent", "operations.agent"), ("linxai-desktop", "ui.desktop"), ("linxai-monitor", "security.monitor")):
        path = directory / name
        path.write_text(launcher(python, module))
        path.chmod(0o700)
    receipt.update(state="installed", operations_module=probe, profiles=[name for name,selected in (("desktop",desktop),("voice",voice)) if selected])
    (prefix / RECEIPT).write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Installed typed CLI: {directory / 'linxai'}\nAdd {directory} to your PATH explicitly if desired.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", default=str(Path.home() / ".local/share/linxai"))
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--desktop", action="store_true", help="Explicitly install the pinned Qt desktop profile")
    parser.add_argument("--voice",action="store_true",help="Explicit pinned voice packages; never downloads model weights or opens microphone")
    parser.add_argument("--uninstall", action="store_true", help="Remove only this managed application prefix; retain audit/configuration")
    args = parser.parse_args(argv)
    try:
        ordinary_user()
        prefix = prefix_path(args.prefix)
        if args.uninstall:
            uninstall(prefix)
        else:
            install(prefix, args.offline, args.desktop, args.voice)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"LINxAI installation refused/failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
