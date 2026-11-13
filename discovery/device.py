"""Live device discovery: first contact, then a medallion pipeline to a gold capability profile.

Bronze  each raw reply from `device.discover` (compressed, SHA-256, source, time).
Silver  parsed facts: identity, modules, deviations, interfaces (management flagged),
        LLDP neighbours, config fingerprint; failed or unparsable replies -> quarantine.
Gold    capability profile the AI works from: identity, per-feature support with
        evidence (model, vendor deviation, device validation probe, offline knowledge
        base), safe-change capability, candidate ports, security notes, proposed asset.
Nothing here writes to a device; probes run through the typed `device.config.probe`.
"""
import base64
import ipaddress
import json
from pathlib import Path
import re
import socket
import sqlite3
import time
import zlib
from xml.etree import ElementTree as ET

from .capability import PROTOCOL_NAMES, RELEVANT_ROOTS, evaluate_all, identify, parse_capabilities, parse_deviations

PROBE_PORTS = (22, 23, 80, 443, 830, 5985, 5986, 502, 1883, 8883, 57400)
INSECURE = {23: "telnet (cleartext management)", 80: "HTTP (cleartext management)", 1883: "MQTT without TLS"}
MGMT = re.compile(r"^(mgmt|management|ma|me|fxp|em)\d|^mgmteth|^management", re.IGNORECASE)
SAFE_CHANGE = ("urn:ietf:params:netconf:capability:candidate:1.0", "urn:ietf:params:netconf:capability:confirmed-commit:1.1",
               "urn:ietf:params:netconf:capability:validate:1.")
MAX_RECORD = 190000


def fingerprint(host, ports, timeout=2.0):
    """First contact before login: which management ports answer and what SSH announces."""
    found = []
    for port in sorted(set(ports)):
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                try:
                    banner = sock.recv(256).decode("ascii", "replace").strip()
                except OSError:
                    banner = ""
        except OSError:
            continue
        found.append({"port": port, "banner": banner[:200] if banner.startswith("SSH-") else ""})
    return found


def _unpack(item):
    out = zlib.decompressobj()                       # bounded: a hostile reply cannot inflate without limit
    text = out.decompress(base64.b64decode(item["z"]), 8 * 1024 * 1024)
    if out.unconsumed_tail:
        raise ValueError("decompressed reply exceeds 8 MiB")
    return text.decode("utf-8", "replace")


def _text(node, name):
    for child in node.iter():
        if child.tag.split("}")[-1] == name:
            return (child.text or "").strip()
    return ""


def _children(root, name):
    return [n for n in root.iter() if n.tag.split("}")[-1] == name]


def _state(node):
    for child in node:
        if child.tag.split("}")[-1] == "state":
            return child
    return node


class Discovery:
    def __init__(self, store, kb_path=None, clock=time.time):
        self.store, self.kb_path, self.clock = store, kb_path, clock

    def ingest(self, asset_name, asset, contact, output, probes=()):
        now, raw = self.clock(), {}
        quarantine, writes = [], []
        for item in output.get("discovery", []):
            name = str(item.get("name", ""))[:96]
            if not item.get("ok"):
                quarantine.append({"item": name, "reason": str(item.get("error", ""))[:300]})
                continue
            record = {"asset": asset_name, "item": name, "ingested": now, "sha256": item["sha256"], "bytes": item["bytes"],
                      "z": item.get("z")}
            if len(json.dumps(record)) > MAX_RECORD:
                record["z"] = None
                quarantine.append({"item": name, "reason": "reply too large for the bronze store; manifest kept"})
            writes.append(("disc_bronze", f"{asset_name}:{name}"[:120], record, True, 5000))
            if item.get("z"):
                try:
                    raw[name] = _unpack(item)
                except (ValueError, zlib.error):
                    quarantine.append({"item": name, "reason": "corrupt compressed reply"})
            elif name == "running_config":
                raw[name] = item["sha256"]
        silver, deviations, modules = self._silver(raw, quarantine)
        gold = self._gold(asset_name, asset, contact, silver, deviations, modules, probes, now)
        writes += [("disc_silver", asset_name, silver, True, 500), ("disc_gold", asset_name, gold, True, 500),
                   ("disc_quarantine", asset_name, {"asset": asset_name, "time": now, "items": quarantine}, True, 500),
                   ("disc_history", f"{asset_name}:{int(now)}", {"asset": asset_name, "time": now,
                    "config_sha256": silver.get("config_sha256", "")}, True, 5000)]
        self.store.write_batch(writes)
        return gold

    def _silver(self, raw, quarantine):
        modules = parse_capabilities(raw.get("hello", "").splitlines())
        deviations = []
        for name, text in raw.items():
            if name.startswith("schema:"):
                found = parse_deviations(text, name[7:])
                if not found:
                    quarantine.append({"item": name, "reason": "no deviation statements parsed"})
                deviations += found
        hello = raw.get("hello", "").splitlines()
        facts = {"modules": len(modules), "config_sha256": raw.get("running_config", ""),
                 "netconf": sorted(c.split("?")[0] for c in hello if c.startswith("urn:ietf:params:netconf:capability:"))[:64]}
        parsed = {}
        for name in ("system", "components", "interfaces", "lldp"):
            if name in raw:
                try:
                    parsed[name] = ET.fromstring(raw[name])
                except ET.ParseError:
                    quarantine.append({"item": name, "reason": "unparsable XML"})
        system = parsed.get("system")
        if system is not None:
            facts["hostname"] = _text(system, "hostname")
            facts["software_version"] = _text(system, "software-version")
        facts["components"] = []
        for comp in _children(parsed["components"], "component")[:200] if "components" in parsed else []:
            state = _state(comp)
            facts["components"].append({k: _text(state, k)[:120] for k in ("name", "type", "description", "part-no", "serial-no",
                                                                          "mfg-name", "software-version", "hardware-version")})
        facts["interfaces"] = []
        for node in _children(parsed["interfaces"], "interface")[:512] if "interfaces" in parsed else []:
            name = next((c.text for c in node if c.tag.split("}")[-1] == "name"), "") or ""
            state = _state(node)
            facts["interfaces"].append({"name": name[:64], "type": _text(state, "type").split(":")[-1][:48],
                                        "admin": _text(state, "admin-status"), "oper": _text(state, "oper-status"),
                                        "description": _text(state, "description")[:120],
                                        "management": bool(MGMT.match(name))})
        neighbours = []
        for intf in _children(parsed["lldp"], "interface")[:512] if "lldp" in parsed else []:
            local = next((c.text for c in intf if c.tag.split("}")[-1] == "name"), "")
            for nb in _children(intf, "neighbor"):
                neighbours.append({"local": local, "system": _text(nb, "system-name")[:96], "port": _text(nb, "port-id")[:64]})
        facts["lldp_neighbours"] = neighbours[:256]
        facts["deviations_relevant"] = sum(1 for d in deviations if RELEVANT_ROOTS.match(d["path"]))
        return facts, deviations, modules

    def _kb_prior(self, vendor, os_, version):
        if not self.kb_path or not version:
            return None
        digits = re.sub(r"\D", "", version)
        db = sqlite3.connect(f"file:{self.kb_path}?mode=ro", uri=True)
        try:
            rows = db.execute("SELECT id, version, platform FROM silver_platform WHERE vendor=? AND os=?", (vendor, os_)).fetchall()
            match = [r for r in rows if digits and re.sub(r"\D", "", r[1]).startswith(digits[:3])]
            if not match:
                return {"platforms": 0}
            ids = [r[0] for r in match]
            marks = ",".join("?" * len(ids))
            support = {}
            for feature, status, n in db.execute(f"SELECT feature, status, count(*) FROM gold_support WHERE platform_id IN ({marks}) "
                                                 "GROUP BY 1,2", ids):
                support.setdefault(feature, {})[status] = n
            return {"platforms": len(match), "versions": sorted({r[1] for r in match})[:8], "support": support}
        finally:
            db.close()

    @staticmethod
    def _history(asset):
        """LINxAI's own change history on this device: restored transactions prove a feature committed."""
        counts = {}
        folder = Path(str(asset.get("state_dir", ""))) / "transactions"
        if not folder.is_dir():
            return counts
        for path in sorted(folder.glob("*.json"))[:5000]:
            try:
                row = json.loads(path.read_text()[:300000])
            except (OSError, ValueError):
                continue
            if isinstance(row, dict) and isinstance(row.get("feature"), str):
                state = "restored" if row.get("state") in ("restored", "compensated") else "unfinished"
                counts.setdefault(row["feature"], {"restored": 0, "unfinished": 0})[state] += 1
        return counts

    def _gold(self, asset_name, asset, contact, silver, deviations, modules, probes, now):
        vendor, os_ = identify(modules)
        namespaces = {m["namespace"] for m in modules.values()}
        chassis = next((c for c in silver["components"] if c["type"].split(":")[-1] == "CHASSIS"), {})
        version = silver.get("software_version") or chassis.get("software-version", "")
        features = evaluate_all(set(modules), deviations, namespaces)
        probed, history = {p["feature"]: p for p in probes}, self._history(asset)
        # Fleet evidence: other discovered devices running the same vendor OS and version.
        peers = [g for g in self.store.list("disc_gold", 500) if g.get("asset") != asset_name
                 and (g.get("vendor"), g.get("os"), g.get("version")) == (vendor, os_, version)]
        for row in features:
            h = history.get(row["feature"])
            if h and h["restored"]:
                row["status"], row["proven"] = "proven", f"committed and restored by LINxAI on this device {h['restored']} time(s)"
            elif h and h["unfinished"] >= 2:
                row["warning"] = f"{h['unfinished']} earlier change attempts never completed a restore cycle (likely refused at commit)"
            for peer in peers:
                other = next((r for r in peer.get("features", []) if r.get("feature") == row["feature"]), {})
                if other.get("warning") and "warning" not in row and "proven" not in row:
                    row["warning"] = f"on {peer['asset']} (same {vendor} {os_} {version}): {other['warning']}"
                elif other.get("status") == "proven" and "proven" not in row:
                    row["fleet"] = f"proven on {peer['asset']} (same {vendor} {os_} {version})"
            p = probed.get(row["feature"])
            if p:
                row["probe"] = "validated by device" if p.get("validated") else f"rejected by device: {p.get('device_error', '')[:200]}"
                if not p.get("validated") and row["status"].startswith("supported") and "proven" not in row:
                    row["status"] = "unsupported"
        prior = self._kb_prior(vendor, os_, version)
        ports = [i["name"] for i in silver["interfaces"] if not i["management"]
                 and i["type"] in ("ethernetCsmacd", "ieee8023adLag")][:64]   # untyped entries (e.g. XR SR-TE tunnels) are not ports
        notes = []
        for svc in contact.get("open", []):
            if svc["port"] in INSECURE:
                notes.append(f"port {svc['port']} open: {INSECURE[svc['port']]}")
            if svc.get("banner"):
                notes.append(f"port {svc['port']} announces {svc['banner']}")
        history = [h for h in self.store.list("disc_history", 1000) if h.get("asset") == asset_name]
        previous = next((h["config_sha256"] for h in history if h.get("config_sha256")), "")
        if previous and silver.get("config_sha256") and previous != silver["config_sha256"]:
            notes.append("running configuration changed since the previous discovery")
        safe = [c for c in SAFE_CHANGE if not any(u.startswith(c) for u in silver.get("netconf", []))]
        usable = [r["feature"] for r in features if r["status"] in ("proven", "supported", "supported_with_limits") and "warning" not in r]
        return {"asset": asset_name, "time": now, "vendor": vendor, "os": os_, "version": version,
                "hostname": silver.get("hostname", ""), "model": chassis.get("description") or chassis.get("part-no", ""),
                "serial": chassis.get("serial-no", ""), "safe_changes": not safe, "missing_for_safe_changes": safe,
                "interfaces": silver["interfaces"][:128], "management_interfaces": [i["name"] for i in silver["interfaces"] if i["management"]],
                "lldp_neighbours": silver["lldp_neighbours"][:64], "features": features, "knowledge_base": prior,
                "security_notes": notes,
                "proposed_asset": {"features": usable, "ports": ports,
                                   **({"protocol_names": PROTOCOL_NAMES[(vendor, os_)]} if (vendor, os_) in PROTOCOL_NAMES else {}),
                                   "note": "owner review required; nothing is enabled until the owner approves it"}}

