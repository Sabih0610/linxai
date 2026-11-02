"""Create only an isolated app environment; never provision host services/devices."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import venv

UV_VERSION = "0.13.3"
ROOT = Path(__file__).resolve().parent.parent


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--venv", default=".venv")
    parser.add_argument("--extra", action="append", choices=["ai", "desktop", "remote", "hardware", "voice", "sensor"], default=[])
    parser.add_argument("--offline", action="store_true", help="Require already cached tooling and packages")
    parser.add_argument("--no-editable", action="store_true", help="Install a wheel independent of the checkout")
    args = parser.parse_args(argv)
    if not (3, 11) <= sys.version_info[:2] < (3, 14):
        parser.error("Use CPython 3.11–3.13; primary tested Linux version is 3.12")
    target = Path(args.venv).absolute()
    if target == ROOT or target == Path(target.anchor):
        parser.error("Environment must be a dedicated directory, not the source or filesystem root")
    binary = target / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    available = shutil.which("uv")
    if available:
        try:
            host_version = subprocess.check_output([available, "--version"], text=True).split()
            if len(host_version) < 2 or host_version[1] != UV_VERSION:
                available = None  # Bootstrap in isolation rather than changing host tooling.
        except (OSError, subprocess.CalledProcessError):
            available = None
    uv_command = [available] if available else [str(binary), "-m", "uv"]
    if not available:
        if args.offline and not binary.exists():
            parser.error("uv unavailable and no cached environment; perform the initial online setup first")
        if not binary.exists():
            venv.EnvBuilder(with_pip=True).create(target)
        probe = subprocess.run([str(binary), "-m", "uv", "--version"], capture_output=True, text=True)
        if probe.returncode or probe.stdout.split()[:2] != ["uv", UV_VERSION]:
            if args.offline:
                parser.error("Pinned uv is not installed in the environment")
            subprocess.run([str(binary), "-m", "pip", "install", "--disable-pip-version-check",
                            "--index-url", "https://pypi.org/simple", f"uv=={UV_VERSION}"], check=True)
    version = subprocess.check_output([*uv_command, "--version"], text=True).split()
    if len(version) < 2 or version[1] != UV_VERSION:
        parser.error(f"Use uv {UV_VERSION}; found {' '.join(version)}")
    env = dict(os.environ, UV_PROJECT_ENVIRONMENT=str(target), UV_PYTHON_DOWNLOADS="never")
    command = [*uv_command, "sync", "--locked", "--group", "test", "--python", sys.executable]
    if args.no_editable:
        command.append("--no-editable")
    for extra in args.extra:
        command += ["--extra", extra]
    if args.offline:
        command.append("--offline")
    subprocess.run(command, cwd=ROOT, env=env, check=True)
    subprocess.run([str(binary), "-I", "-B", "-m", "operations.cli", "--help"], cwd=ROOT, check=True)
    print(f"Ready: {binary}")
    if not args.no_editable:
        print(f"Offline tests: {binary} -B scripts/test.py offline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
