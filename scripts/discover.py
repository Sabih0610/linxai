"""Discover a registered NETCONF device and build its gold capability profile.

    python3 -B scripts/discover.py --assets assets.json --asset core1 --state ~/.linxai/discovery \
        [--kb ~/kb-data/linxai-kb.sqlite] [--probe] [--out core1-gold.json]

1. First contact: which management ports answer and what SSH announces (registered host only).
2. `device.discover` through the typed service: read-only, pinned host key, audited.
3. Optional `--probe`: for features the model says are supported, ask the device to
   VALIDATE an example edit, which is always discarded; running config is checked unchanged.
4. Bronze/silver/gold in a private store; the gold profile is printed and saved.
Probe failures of features that depend on others are reported, not used to mark the
feature unsupported, because the prerequisite may simply be absent.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
PREREQUISITES = {"bgp.peer_group": "bgp.global", "bgp.neighbor": "bgp.global/peer group", "qos.forwarding_group": "qos.queue",
                 "qos.classifier_term": "forwarding group", "qos.interface_classifier": "classifier",
                 "srl.mac_vrf_evpn": "srl.vxlan_interface", "srl.qos_forwarding_class": "srl.qos_queue",
                 "srl.qos_dscp_rule": "srl.qos_forwarding_class", "srl.qos_interface_policy": "DSCP policy + subinterface",
                 "interface.access_vlan": "vlan", "lag.member": "a LAG interface"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True)
    parser.add_argument("--asset", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--kb")
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    from discovery.capability import SAMPLES, P, P2
    from discovery.device import PROBE_PORTS, Discovery, fingerprint
    from operations.audit import JsonlAudit
    from operations.netconf_features import FEATURES
    from operations.registry import ActionRegistry
    from operations.service import LocalPolicy, OperationService
    from operations.store import Store
    from operations.workflows import WorkflowSystem
    assets, uid = json.loads(Path(args.assets).read_text()), os.getuid()
    asset = assets[args.asset]
    try:
        loopback = ipaddress.ip_address(asset["host"]).is_loopback
    except ValueError:
        loopback = False
    # A loopback lab address is a port-forward: only its own NETCONF port belongs to the device.
    contact = {"open": fingerprint(asset["host"], (asset["port"],) if loopback else PROBE_PORTS + (asset["port"],))}
    state = Path(args.state).expanduser()
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    discovery = Discovery(Store(state / "discovery.sqlite"), args.kb and str(Path(args.kb).expanduser()))
    with tempfile.TemporaryDirectory(prefix="linxai-discover-", dir=Path.home()) as temp:
        os.chmod(temp, 0o700)

        def service(asset_map):
            return OperationService(ActionRegistry(temp, actor_uid=uid, assets_json=json.dumps(asset_map)), WorkflowSystem(),
                                    LocalPolicy(uid), JsonlAudit(Path(temp) / "audit.jsonl"))
        result = service(assets).run({"action": "device.discover", "parameters": {"asset": args.asset}})
        if result.status != "succeeded":
            print(json.dumps({"status": result.status, "reason": result.reason, "error": (result.stderr or "")[-400:]}))
            return 1
        output = json.loads(result.stdout)
        gold = discovery.ingest(args.asset, asset, contact, output)
        if args.probe:
            ports = gold["proposed_asset"]["ports"]
            lags = [i["name"] for i in gold["interfaces"] if i["type"] == "ieee8023adLag"]
            probe_asset = dict(asset, features=sorted(FEATURES), ports=sorted(set(ports[:2] + lags[:1])))
            svc, probes = service({args.asset: probe_asset}), []
            for row in gold["features"]:
                feature = row["feature"]
                if row["status"] not in ("supported", "supported_with_limits") or not ports:
                    continue
                if feature == "lag.member" and not lags:
                    probes.append({"feature": feature, "note": "not probed: the device has no LAG interface"}); continue
                settings = json.loads(json.dumps(SAMPLES[feature]).replace(f'"{P}"', json.dumps(ports[0]))
                                      .replace(f'"{P2}"', json.dumps(lags[0] if lags else ports[0])))
                base = {"asset": args.asset, "feature": feature, "settings": settings}
                read = svc.run({"action": "device.config.read", "parameters": base})
                done = svc.run({"action": "device.config.probe", "parameters": {**base, "expected_revision": json.loads(read.stdout)["revision"]}}) \
                    if read.status == "succeeded" else read
                if done.status != "succeeded":           # a LINxAI-side refusal or failure is not device evidence
                    probes.append({"feature": feature, "note": f"not probed: {done.reason}"[:200]}); continue
                verdict = json.loads(done.stdout)
                if not verdict.get("validated") and feature in PREREQUISITES:
                    verdict["note"] = f"not validated alone (needs {PREREQUISITES[feature]}): {verdict.get('device_error', '')[:160]}"
                probes.append({"feature": feature, **verdict})
                print(("VALID  " if verdict.get("validated") else "REJECT ") + feature, (verdict.get("device_error") or "")[:140], flush=True)
            gold = discovery.ingest(args.asset, asset, contact, output, [p for p in probes if "note" not in p])
            for p in probes:
                if "note" in p:
                    next(r for r in gold["features"] if r["feature"] == p["feature"])["probe"] = p["note"]
    text = json.dumps(gold, indent=1, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n")
    summary = {k: gold[k] for k in ("vendor", "os", "version", "hostname", "model", "safe_changes", "management_interfaces", "security_notes")}
    summary["features"] = {r["feature"]: " | ".join(x for x in (r["status"], r.get("proven", ""), r.get("fleet", ""), r.get("probe", ""), r.get("warning", "")) if x)[:200] for r in gold["features"]}
    summary["proposed_ports"] = gold["proposed_asset"]["ports"][:12]
    summary["knowledge_base"] = {k: v for k, v in (gold["knowledge_base"] or {}).items() if k != "support"}
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
