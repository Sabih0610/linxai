"""Acceptance of typed NETCONF config features against a lab device (commits, then restores).

For every case: read the target (revision R0), set through LINxAI (snapshot, confirmed
commit, read-back), read again independently (desired values present), restore through
the offered typed restoration, and read again (revision back to R0 or target absent as
before), and the WHOLE running config must be byte-identical to the start
(catches collateral changes outside the feature's own node). Cases come from a JSON list of {"feature": ..., "settings": {...}}.
    LINXAI_TEST_NETCONF_LAB=1 python3 -B scripts/accept_netconf_features.py --assets a.json --asset srl1 --cases cases.json
"""
import argparse
import base64
import difflib
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def whole_config(asset):
    """The device's entire running config, read independently (pinned host key checked)."""
    from ncclient import manager
    with manager.connect(host=asset["host"], port=asset["port"], username=asset["username"], key_filename=asset["key_path"],
                         hostkey_verify=False, allow_agent=False, look_for_keys=False, timeout=30) as m:
        key = m._session._transport.get_remote_server_key()
        if "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=") != asset["host_key_sha256"]:
            raise SystemExit("host key mismatch")
        return m.get_config(source="running").data_xml


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True)
    parser.add_argument("--asset", required=True)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--out", default="netconf-features-acceptance.json")
    args = parser.parse_args(argv)
    if os.environ.get("LINXAI_TEST_NETCONF_LAB") != "1":
        print("PENDING: opt in with LINXAI_TEST_NETCONF_LAB=1 against a lab device"); return 3
    from operations.audit import JsonlAudit
    from operations.registry import ActionRegistry
    from operations.service import LocalPolicy, OperationService
    from operations.workflows import WorkflowSystem
    uid, assets, cases, results = os.getuid(), json.loads(Path(args.assets).read_text()), json.loads(Path(args.cases).read_text()), {}
    with tempfile.TemporaryDirectory(prefix="linxai-ncfeat-", dir=Path.home()) as temp:
        os.chmod(temp, 0o700)
        service = OperationService(ActionRegistry(temp, actor_uid=uid, assets_json=json.dumps(assets)), WorkflowSystem(),
                                   LocalPolicy(uid), JsonlAudit(Path(temp) / "audit.jsonl"))
        def run(action, **params):
            r = service.run({"action": action, "parameters": {"asset": args.asset, **params}})
            return r, (json.loads(r.stdout) if r.stdout.strip().startswith("{") else {})
        for case in cases:
            feature, settings, label = case["feature"], case["settings"], case.get("label", case["feature"])
            facts, prereqs, start = {}, [], whole_config(assets[args.asset])
            needs = case.get("requires") or []
            for need in ([needs] if isinstance(needs, dict) else needs):
                _, pb = run("device.config.read", feature=need["feature"], settings=need["settings"])
                pr, out = run("device.config.set", feature=need["feature"], settings=need["settings"],
                              expected_revision=pb.get("revision", "0" * 64), transaction_id=str(uuid4()))
                facts.setdefault("prerequisites", []).append(pr.status); prereqs.append(out)
            before, b = run("device.config.read", feature=feature, settings=settings)
            facts["read"] = before.status
            if before.status != "succeeded":
                results[label] = {"ok": False, **facts, "reason": before.reason, "err": before.stderr[-300:]}; print("FAIL", label, results[label]); continue
            changed, c = run("device.config.set", feature=feature, settings=settings, expected_revision=b["revision"], transaction_id=str(uuid4()))
            facts.update(set=changed.status, verified=changed.verified)
            after, a = run("device.config.read", feature=feature, settings=settings)
            facts["present_after_set"] = a.get("present")
            restored, _ = (service.run(c["restoration"]), None) if c.get("restoration") else (None, None)
            facts["restore"] = getattr(restored, "status", None)
            final, f = run("device.config.read", feature=feature, settings=settings)
            facts["back_to_original"] = f.get("revision") == b["revision"] or (not b.get("present") and not f.get("present"))
            ok = (changed.status == "succeeded" and changed.verified and a.get("present") and restored is not None
                  and restored.status == "succeeded" and restored.verified and facts["back_to_original"])
            if not ok:
                facts["err"] = (changed.stderr or getattr(restored, "stderr", "") or "")[-300:]
            for out in reversed(prereqs):
                if out.get("restoration"):
                    pr = service.run(out["restoration"])
                    facts.setdefault("prerequisites_restored", []).append(pr.status)
                    if pr.status != "succeeded":
                        facts.setdefault("prerequisite_errors", []).append(f"{pr.reason} {(pr.stderr or '')[-200:]}")
            end = whole_config(assets[args.asset]); facts["whole_config_unchanged"] = end == start
            if end != start:
                facts["config_diff"] = [l for l in difflib.unified_diff(start.splitlines(), end.splitlines(), lineterm="", n=1)][2:30]
            ok = ok and facts["whole_config_unchanged"] and all(s == "succeeded" for s in facts.get("prerequisites_restored", []))
            results[label] = {"ok": bool(ok), **facts}
            print(("PASS " if ok else "FAIL ") + label, json.dumps(facts)[:300], flush=True)
    Path(args.out).write_text(json.dumps(results, indent=2) + "\n")
    passed = sum(r["ok"] for r in results.values())
    print(("PASS" if passed == len(results) else "FAIL"), f"{passed}/{len(results)} features")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
