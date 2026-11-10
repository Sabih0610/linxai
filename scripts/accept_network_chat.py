"""End to end: chat sentence -> gold-grounded plan -> typed change on a lab device -> restore.

    LINXAI_TEST_NETCONF_LAB=1 python3 -B scripts/accept_network_chat.py --assets a.json --asset srl1 \
        --discovery ~/.linxai-discovery/discovery.sqlite

Uses the device's real gold profile (written by scripts/discover.py), the same typed
read -> set -> verify -> restore path as the agent's preview/confirm, and checks the
device's whole running config is identical after the restore. Also checks that requests
the profile rules out are refused before anything reaches the device.
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
    parser.add_argument("--assets", required=True)
    parser.add_argument("--asset", required=True)
    parser.add_argument("--discovery", required=True)
    parser.add_argument("--out", default="network-chat-acceptance.json")
    args = parser.parse_args(argv)
    if os.environ.get("LINXAI_TEST_NETCONF_LAB") != "1":
        print("PENDING: opt in with LINXAI_TEST_NETCONF_LAB=1 against a lab device"); return 3
    from ai.network_planner import NetworkPlanner
    from operations.audit import JsonlAudit
    from operations.registry import ActionRegistry, UnsupportedAction
    from operations.service import LocalPolicy, OperationService
    from operations.store import Store
    from operations.workflows import WorkflowSystem
    from scripts.accept_netconf_features import whole_config
    assets, uid, steps = json.loads(Path(args.assets).read_text()), os.getuid(), {}
    profiles = Store(Path(args.discovery).expanduser())

    def step(label, ok, **facts):
        steps[label] = {"ok": bool(ok), **facts}
        print(("PASS " if ok else "FAIL ") + label, json.dumps(facts, default=str)[:260], flush=True)

    with tempfile.TemporaryDirectory(prefix="linxai-chat-", dir=Path.home()) as temp:
        os.chmod(temp, 0o700)
        registry = ActionRegistry(temp, actor_uid=uid, assets_json=json.dumps(assets))
        service = OperationService(registry, WorkflowSystem(), LocalPolicy(uid), JsonlAudit(Path(temp) / "audit.jsonl"))
        planner = NetworkPlanner(registry, lambda name: profiles.get("disc_gold", name))
        start = whole_config(assets[args.asset])
        for text in (f"set the hostname of {args.asset} to chat-lab", f"add dns server 192.0.2.153 on {args.asset}"):
            kind, base, plan = planner.plan(text)
            read = service.run({"action": "device.config.read", "parameters": base})
            before = json.loads(read.stdout)["revision"]
            changed = service.run({"action": "device.config.set", "parameters": {**base, "expected_revision": before, "transaction_id": str(uuid4())}})
            out = json.loads(changed.stdout) if changed.stdout.strip().startswith("{") else {}
            restored = service.run(out["restoration"]) if out.get("restoration") else None
            after = json.loads(service.run({"action": "device.config.read", "parameters": base}).stdout)["revision"]
            step(f"chat: {text}", kind == "change" and changed.status == "succeeded" and changed.verified and restored is not None
                 and restored.status == "succeeded" and after == before, feature=base["feature"], evidence=plan["workflow"][:120],
                 set=changed.status, restore=getattr(restored, "status", None))
        step("whole running config identical after the chat changes", whole_config(assets[args.asset]) == start)
        for text in (f"create vlan 40 on {args.asset}", f"add ntp server 192.0.2.1 on {args.asset}"):
            try:
                planner.plan(text)
                step(f"refused before the device: {text}", False)
            except UnsupportedAction as exc:
                step(f"refused before the device: {text}", True, reason=str(exc)[:160])
        kind, answer = planner.plan(f"what can {args.asset} do")
        step("capability answer from the gold profile", kind == "answer" and answer["identity"]["model"], model=answer["identity"]["model"],
             proven=len(answer["proven"]))
    profiles.close()
    Path(args.out).write_text(json.dumps(steps, indent=2) + "\n")
    passed = all(s["ok"] for s in steps.values())
    print(("PASS" if passed else "FAIL"), f"{sum(s['ok'] for s in steps.values())}/{len(steps)} steps")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
