"""Offline vendor knowledge base: public vendor YANG data through a medallion pipeline.

Bronze  manifest of every source file used (path, size, SHA-256); file bytes stay in the
        downloaded tree, which is treated as untrusted DATA (parsed, never executed).
Silver  one row per vendor platform/release: advertised modules and parsed deviations;
        unreadable or empty sources go to quarantine instead.
Gold    predicted LINxAI feature support per platform, with the evidence for each verdict.

Sources (public, no account): YangModels/yang (Cisco IOS-XR/XE/NX-OS hello capability
lists + deviation modules), Juniper/yang (OpenConfig models + deviations per Junos
release), Huawei/yang (models + deviations per router platform/version).
    python3 -m discovery.kb --root ~/kb-data --out ~/kb-data/linxai-kb.sqlite
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from xml.etree import ElementTree as ET

from .capability import RELEVANT_ROOTS as RELEVANT, evaluate_all, parse_capabilities, parse_deviations

SCHEMA = """
CREATE TABLE bronze_file (path TEXT PRIMARY KEY, vendor TEXT, bytes INTEGER, sha256 TEXT);
CREATE TABLE silver_platform (id INTEGER PRIMARY KEY, vendor TEXT, os TEXT, version TEXT, platform TEXT,
                              products TEXT, source TEXT, modules INTEGER, deviations INTEGER);
CREATE TABLE silver_module (platform_id INTEGER, module TEXT, revision TEXT);
CREATE TABLE silver_deviation (platform_id INTEGER, path TEXT, deviate TEXT, module TEXT);
CREATE TABLE quarantine (source TEXT, reason TEXT);
CREATE TABLE gold_support (platform_id INTEGER, feature TEXT, status TEXT, evidence TEXT);
CREATE INDEX module_by_platform ON silver_module(platform_id);
CREATE INDEX support_by_feature ON gold_support(feature, status);
"""
MAX_FILE = 8 * 1024 * 1024


class Builder:
    def __init__(self, out):
        out = Path(out)
        if out.exists():
            out.unlink()
        self.db = sqlite3.connect(out)
        self.db.executescript(SCHEMA)
        self.seen = set()

    def read(self, path, vendor):
        """Bronze: record provenance once; return text, or None (quarantined) if unusable."""
        try:
            data = path.read_bytes() if path.is_file() and path.stat().st_size <= MAX_FILE else None
            if data is None:
                raise ValueError("missing, not a regular file, or larger than 8 MiB")
            text = data.decode("utf-8")
        except (OSError, ValueError) as exc:
            self.db.execute("INSERT INTO quarantine VALUES (?,?)", (str(path), str(exc)[:200]))
            return None
        if str(path) not in self.seen:
            self.seen.add(str(path))
            self.db.execute("INSERT INTO bronze_file VALUES (?,?,?,?)", (str(path), vendor, len(data), hashlib.sha256(data).hexdigest()))
        return text

    def platform(self, vendor, os_, version, platform, products, source, modules, deviations):
        """Silver + gold for one platform/release."""
        if not modules:
            self.db.execute("INSERT INTO quarantine VALUES (?,?)", (source, "no modules found"))
            return
        relevant = [d for d in deviations if RELEVANT.match(d["path"])]
        cur = self.db.execute("INSERT INTO silver_platform VALUES (NULL,?,?,?,?,?,?,?,?)",
                              (vendor, os_, version, platform, json.dumps(products), source, len(modules), len(relevant)))
        pid = cur.lastrowid
        self.db.executemany("INSERT INTO silver_module VALUES (?,?,?)", [(pid, m, r) for m, r in sorted(modules.items())])
        self.db.executemany("INSERT INTO silver_deviation VALUES (?,?,?,?)",
                            [(pid, d["path"], ",".join(d["deviate"]), d["module"]) for d in relevant])
        self.db.executemany("INSERT INTO gold_support VALUES (?,?,?,?)",
                            [(pid, r["feature"], r["status"], json.dumps(r["evidence"])) for r in evaluate_all(set(modules), relevant)])

    def deviations(self, files, vendor):
        found = []
        for path in files:
            text = self.read(path, vendor)
            if text is not None:
                found += parse_deviations(text, path.stem)
        return found

    def cisco(self, root):
        base = root / "yang" / "vendor" / "cisco"
        meta = {}
        for path in base.rglob("platform-metadata.json"):
            text = self.read(path, "cisco")
            try:
                for p in json.loads(text or "{}").get("platforms", {}).get("platform", []):
                    meta[p.get("module-list-file", {}).get("path", "")] = p
            except (ValueError, AttributeError):
                self.db.execute("INSERT INTO quarantine VALUES (?,?)", (str(path), "unreadable platform metadata"))
        family = {"xr": "iosxr", "xe": "iosxe", "nx": "nxos"}
        for path in sorted(base.rglob("*.xml")):
            if "capabilit" not in path.name.lower():
                continue
            text = self.read(path, "cisco")
            try:
                hello = ET.fromstring(text) if text else None
            except ET.ParseError:
                hello = None
            if hello is None:
                self.db.execute("INSERT INTO quarantine VALUES (?,?)", (str(path), "unparsable capability list"))
                continue
            caps = parse_capabilities(c.text or "" for c in hello.iter() if c.tag.split("}")[-1] == "capability")
            named = {d for m in caps.values() for d in m["deviations"]}
            devfiles = [f for f in path.parent.glob("*.yang") if f.stem.split("@")[0] in named]
            rel = str(path.relative_to(root / "yang"))
            info = meta.get(rel, {})
            os_ = family.get(path.relative_to(base).parts[0], "unknown")
            name = re.sub(r"^(net(conf)?-)?capabilit(y|ies)-?", "", path.stem) or "all"
            self.platform("cisco", os_, info.get("software-version", path.parent.name), info.get("name", name),
                          info.get("product-ids", []), rel, {m: v["revision"] for m, v in caps.items()},
                          self.deviations(devfiles, "cisco"))

    def listed(self, root, vendor):
        files = (root / f"{vendor}.files.txt").read_text().split()
        return [f for f in files if f.endswith(".yang")]

    def juniper(self, root):
        files = self.listed(root, "juniper")
        releases = sorted({"/".join(f.split("/")[:2]) for f in files if "/openconfig/models/" in f})
        for release in releases:
            prefix = f"{release}/openconfig/models/"
            modules = {Path(f).stem.split("@")[0]: "" for f in files if f.startswith(prefix) and "/" not in f[len(prefix):]}
            devs = sorted((root / "juniper" / prefix / "deviations").glob("*.yang"))
            self.platform("juniper", "junos-evo" if release.endswith("EVO") else "junos", release.split("/")[-1], "all", [],
                          f"Juniper/yang:{prefix}", modules, self.deviations(devs, "juniper"))

    def huawei(self, root):
        files = self.listed(root, "huawei")
        dirs = sorted({str(Path(f).parent) for f in files if f.count("/") >= 3})
        for d in dirs:
            parts = d.split("/")
            modules = {Path(f).stem.split("@")[0]: "" for f in files if str(Path(f).parent) == d}
            devs = sorted((root / "huawei" / d).glob("*deviation*.yang"))
            self.platform("huawei", "vrp", parts[1], "/".join([parts[0]] + parts[2:]), [], f"Huawei/yang:{d}", modules,
                          self.deviations(devs, "huawei"))

    def close(self):
        self.db.commit()
        self.db.close()


def summary(path):
    db = sqlite3.connect(path)
    out = {"platforms": dict(db.execute("SELECT vendor || '/' || os, count(*) FROM silver_platform GROUP BY 1").fetchall()),
           "bronze_files": db.execute("SELECT count(*) FROM bronze_file").fetchone()[0],
           "quarantined": db.execute("SELECT count(*) FROM quarantine").fetchone()[0], "support": {}}
    for vendor_os, feature, status, n in db.execute(
            "SELECT p.vendor || '/' || p.os, g.feature, g.status, count(*) FROM gold_support g JOIN silver_platform p ON p.id=g.platform_id "
            "GROUP BY 1,2,3"):
        out["support"].setdefault(vendor_os, {}).setdefault(feature, {})[status] = n
    db.close()
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    root = Path(args.root).expanduser()
    builder = Builder(Path(args.out).expanduser())
    for vendor in ("cisco", "juniper", "huawei"):
        getattr(builder, vendor)(root)
        builder.db.commit()
    builder.close()
    print(json.dumps(summary(Path(args.out).expanduser()), indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
