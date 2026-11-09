"""Coordinated multi-device change acceptance (device.config.batch) on two lab devices.

1. A batch that both devices accept: both confirmed, verified by independent reads,
   then each restored through its offered typed restoration.
2. A batch where the second device rejects its change at commit: the batch fails and
   the FIRST device must be back exactly as before (its provisional commit cancelled).
    LINXAI_TEST_NETCONF_LAB=1 python3 -B scripts/accept_netconf_batch.py --assets a.json --first srl1 --second srl2 \
        --ok-change '{"feature": "system.hostname", "settings": {"hostname": "x"}}' \
        --bad-change '{"feature": "system.ntp_server", "settings": {"address": "192.0.2.123"}}'
"""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("--assets", "--first", "--second", "--ok-change", "--bad-change"):
        parser.add_argument(name, required=True)
    parser.add_argument("--out", default="netconf-batch-acceptance.json")
    args = parser.parse_args(argv)
    if os.environ.get("LINXAI_TEST_NETCONF_LAB") != "1":
        print("PENDING: opt in with LINXAI_TEST_NETCONF_LAB=1 against lab devices"); return 3
    from operations.audit import JsonlAudit
    from operations.registry import ActionRegistry
    from operations.service import LocalPolicy, OperationService
    from operations.workflows import WorkflowSystem
    from scripts.accept_netconf_features import whole_config
    uid, assets, steps = os.getuid(), json.loads(Path(args.assets).read_text()), {}
    ok_change, bad_change = json.loads(args.ok_change), json.loads(args.bad_change)

    def step(label, ok, **facts):
        steps[label] = {"ok": bool(ok), **facts}
        print(("PASS " if ok else "FAIL ") + label, json.dumps(facts, default=str)[:280], flush=True)

    with tempfile.TemporaryDirectory(prefix="linxai-batch-", dir=Path.home()) as temp:
        os.chmod(temp, 0o700)
        service = OperationService(ActionRegistry(temp, actor_uid=uid, assets_json=json.dumps(assets)), WorkflowSystem(),
                                   LocalPolicy(uid), JsonlAudit(Path(temp) / "audit.jsonl"))

        def read(asset, change):
            r = service.run({"action": "device.config.read", "parameters": {"asset": asset, **change}})
            return json.loads(r.stdout) if r.stdout.strip().startswith("{") else {}

        def batch(changes):
            entries = [{"asset": a, **c, "expected_revision": read(a, c).get("revision", "0" * 64)} for a, c in changes]
            r = service.run({"action": "device.config.batch", "parameters": {"changes": entries, "transaction_id": str(uuid4())}})
            return r, (json.loads(r.stdout) if r.stdout.strip().startswith("{") else {})

        second_ok = {"feature": ok_change["feature"], "settings": {**ok_change["settings"],
                     **({"hostname": ok_change["settings"]["hostname"] + "-2"} if "hostname" in ok_change["settings"] else {})}}
        whole = {a: whole_config(assets[a]) for a in (args.first, args.second)}
        before = {a: read(a, c).get("revision") for a, c in ((args.first, ok_change), (args.second, second_ok))}
        result, out = batch([(args.first, ok_change), (args.second, second_ok)])
        after = {a: read(a, c) for a, c in ((args.first, ok_change), (args.second, second_ok))}
        step("batch_applied_and_verified_on_both", result.status == "succeeded" and result.verified
             and all(v.get("revision") != before[a] for a, v in after.items()), status=result.status, reason=result.reason,
             err=(result.stderr or "")[-200:])
        restored = [service.run(r) for r in out.get("restorations", [])]
        back = {a: read(a, c).get("revision") for a, c in ((args.first, ok_change), (args.second, second_ok))}
        step("each_device_restored", len(restored) == 2 and all(r.status == "succeeded" and r.verified for r in restored)
             and back == before
             and all(whole_config(assets[a]) == h for a, h in whole.items()), restores=[r.status for r in restored])

        first_before = read(args.first, ok_change).get("revision")
        failed, _ = batch([(args.first, ok_change), (args.second, bad_change)])
        first_after = read(args.first, ok_change).get("revision")
        first_after = first_after if whole_config(assets[args.first]) == whole[args.first] else "whole-config-changed"
        step("rejected_batch_leaves_first_device_unchanged", failed.status != "succeeded" and first_after == first_before,
             status=failed.status, first_unchanged=first_after == first_before, err=(failed.stderr or "")[-160:])

    Path(args.out).write_text(json.dumps(steps, indent=2, default=str) + "\n")
    passed = all(s["ok"] for s in steps.values())
    print(("PASS" if passed else "FAIL"), f"{sum(s['ok'] for s in steps.values())}/{len(steps)} steps")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
