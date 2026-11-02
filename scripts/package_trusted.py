"""Build a reviewable broker deployment archive; never install or enable it."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent.parent


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    files = {"usr/lib/linxai-trusted/broker_entry.py": ROOT / "deployment/broker_entry.py",
             "usr/share/polkit-1/actions/org.linxai.service.policy": ROOT / "deployment/org.linxai.service.policy",
             "usr/lib/systemd/system/linxai-broker.service": ROOT / "deployment/linxai-broker.service",
             "usr/share/doc/linxai/broker.example.json": ROOT / "deployment/broker.example.json"}
    for path in sorted((ROOT / "operations").glob("*.py")):
        files["usr/lib/linxai-trusted/operations/" + path.name] = path
    files["usr/lib/systemd/system/linxai-sensor.service"] = ROOT / "deployment/linxai-sensor.service"
    for package in ("security", "ebpf"):
        for path in sorted((ROOT / package).rglob("*")):
            if path.is_file() and path.suffix in {".py", ".c"}:
                files["usr/lib/linxai-trusted/" + path.relative_to(ROOT).as_posix()] = path
    manifest = {}
    with tarfile.open(args.output, "x") as archive:
        for name, source in files.items():
            if source.is_symlink():
                raise ValueError("Symlink source refused")
            data = source.read_bytes()
            manifest[name] = hashlib.sha256(data).hexdigest()
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.uid, info.gid, info.mtime = len(data), 0o644, 0, 0, 0
            archive.addfile(info, io.BytesIO(data))
        data = json.dumps(manifest, sort_keys=True, indent=2).encode()
        info = tarfile.TarInfo("usr/share/doc/linxai/broker-manifest.json")
        info.size, info.mode = len(data), 0o644
        archive.addfile(info, io.BytesIO(data))
    print(f"Built {args.output}; review root-owned extraction/configuration before isolated lab deployment")


if __name__ == "__main__":
    main()
