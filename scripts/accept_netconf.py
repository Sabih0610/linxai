"""NETCONF device acceptance (network-device extension) against a lab device.

Ordinary owner; `--assets` is a private JSON file with one configured `netconf`
asset (see docs/NETWORK_DEVICES.md). Uses the real OperationService, typed device
actions and the fixed worker; an independent NETCONF session reads the device
back after every change. Nothing outside the allowlisted interface is touched.
    LINXAI_TEST_NETCONF_LAB=1 python3 -B scripts/accept_netconf.py --assets assets.json --asset lab
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OC = "http://openconfig.net/yang/interfaces"


def independent_enabled(asset, name):
    from ncclient import manager
    from xml.etree import ElementTree as ET
    with manager.connect(host=asset["host"], port=asset["port"], username=asset["username"], key_filename=asset["key_path"],
                         hostkey_verify=False, allow_agent=False, look_for_keys=False, timeout=20) as m:
        data = ET.fromstring(m.get_config(source="running", filter=("subtree", f'<interfaces xmlns="{OC}"/>')).data_xml)
        for node in data.iter(f"{{{OC}}}interface"):
            if node.findtext(f"{{{OC}}}name") == name:
                return node.findtext(f"{{{OC}}}config/{{{OC}}}enabled") == "true"
    return None


def device_rollback_demo(asset, name, before):
    """Device-side safety nets for an unconfirmed confirmed-commit: it reverts when the
    timer expires (session kept open) and immediately when the session drops (RFC 6241)."""
    from ncclient import manager
    xml = (f'<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"><interfaces xmlns="{OC}"><interface><name>{name}</name>'
           f'<config><name>{name}</name><enabled>{"false" if before else "true"}</enabled></config></interface></interfaces></nc:config>')
    connect = lambda: manager.connect(host=asset["host"], port=asset["port"], username=asset["username"], key_filename=asset["key_path"],
                                      hostkey_verify=False, allow_agent=False, look_for_keys=False, timeout=20)
    result = {"original": before}
    with connect() as m:
        # Lock-free on purpose: some devices (SR Linux) reject confirmed commits under a lock.
        m.discard_changes(); m.edit_config(target="candidate", config=xml); m.commit(confirmed=True, timeout="10")
        result["timer_during_unconfirmed"] = independent_enabled(asset, name)
        time.sleep(25)
        result["timer_after_expiry"] = independent_enabled(asset, name)
    with connect() as m:
        m.discard_changes(); m.edit_config(target="candidate", config=xml); m.commit(confirmed=True, timeout="120")
        result["drop_during_unconfirmed"] = independent_enabled(asset, name)
    time.sleep(3)
    result["drop_after_session_close"] = independent_enabled(asset, name)
    flipped = not before
    result["ok"] = (result["timer_during_unconfirmed"] is flipped and result["timer_after_expiry"] is before
                    and result["drop_during_unconfirmed"] is flipped and result["drop_after_session_close"] is before)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True)
    parser.add_argument("--asset", required=True)
    parser.add_argument("--out", default="netconf-acceptance.json")
    args = parser.parse_args(argv)
    if os.environ.get("LINXAI_TEST_NETCONF_LAB") != "1":
        print("PENDING: opt in with LINXAI_TEST_NETCONF_LAB=1 against a lab device"); return 3
    from operations.audit import JsonlAudit
    from operations.registry import ActionRegistry
    from operations.service import LocalPolicy, OperationService
    from operations.workflows import WorkflowSystem
    uid = os.getuid()
    assets = json.loads(Path(args.assets).read_text())
    asset, name = assets[args.asset], assets[args.asset]["ports"][0]
    steps = {}

    def step(label, ok, **facts):
        steps[label] = {"ok": bool(ok), **facts}
        print(("PASS " if ok else "FAIL ") + label, json.dumps(facts, default=str)[:240], flush=True)

    with tempfile.TemporaryDirectory(prefix="linxai-netconf-", dir=Path.home()) as temp:
        os.chmod(temp, 0o700)
        def service_for(values):
            registry = ActionRegistry(temp, actor_uid=uid, assets_json=json.dumps(values))
            return registry, OperationService(registry, WorkflowSystem(), LocalPolicy(uid), JsonlAudit(Path(temp) / "audit.jsonl"))
        registry, service = service_for(assets)
        run = lambda action, **p: service.run({"action": action, "parameters": {"asset": args.asset, **p}})

        from ncclient import manager
        connect = lambda: manager.connect(host=asset["host"], port=asset["port"], username=asset["username"], key_filename=asset["key_path"],
                                          hostkey_verify=False, allow_agent=False, look_for_keys=False, timeout=20)
        with connect() as m:
            m.discard_changes()                 # lab reset only: clear edits left by earlier lab runs

        inspected = run("device.inspect")
        value = json.loads(inspected.stdout) if inspected.stdout.strip().startswith("{") else {}
        before = value.get("device", {}).get("interfaces", {}).get(name, {}).get("enabled")
        step("inspect", inspected.status == "succeeded" and inspected.verified and before is not None,
             before=before, capabilities=len(value.get("capabilities", [])), reason=inspected.reason)
        revision = value.get("revision")

        token = str(uuid4())
        changed = run("device.interface.set", interface=name, enabled=not before, expected_revision=revision, transaction_id=token)
        out = json.loads(changed.stdout) if changed.stdout.strip().startswith("{") else {}
        step("set_verified_with_restoration", changed.status == "succeeded" and changed.verified
             and changed.recovery == "available_for_review" and "restoration" in out, diff=out.get("diff"), reason=changed.reason, err=changed.stderr[-300:])
        step("independent_read_after_set", independent_enabled(asset, name) is (not before))

        replay = run("device.interface.set", interface=name, enabled=before, expected_revision=out.get("revision"), transaction_id=token)
        step("reused_transaction_refused", replay.status != "succeeded" and not replay.executed, status=replay.status)
        stale = run("device.interface.set", interface=name, enabled=before, expected_revision="0" * 64, transaction_id=str(uuid4()))
        step("stale_revision_refused", stale.status != "succeeded" and not stale.executed, status=stale.status)

        # Another operator holds uncommitted edits: LINxAI must refuse, not discard them.
        with connect() as other:
            other.edit_config(target="candidate", config=(f'<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">'
                              f'<interfaces xmlns="{OC}"><interface><name>{name}</name><config><name>{name}</name>'
                              f'<description>pending edit by another operator</description></config></interface></interfaces></nc:config>'))
            now = json.loads(run("device.inspect").stdout)["revision"]
            blocked = run("device.interface.set", interface=name, enabled=before, expected_revision=now, transaction_id=str(uuid4()))
            step("pending_foreign_edits_refused_not_discarded", blocked.status != "succeeded"
                 and independent_enabled(asset, name) is (not before), status=blocked.status)
            other.discard_changes()

        restored = service.run(out["restoration"]) if out.get("restoration") else None
        step("restore_verified", restored is not None and restored.status == "succeeded" and restored.verified,
             reason=getattr(restored, "reason", None))
        step("independent_read_after_restore", independent_enabled(asset, name) is before)

        try:
            registry.prepare("device.interface.set", {"asset": args.asset, "interface": "ethernet-9/99", "enabled": True,
                                                      "expected_revision": "0" * 64, "transaction_id": str(uuid4())})
            step("non_allowlisted_interface_refused", False)
        except ValueError as exc:
            step("non_allowlisted_interface_refused", True, error=type(exc).__name__)

        wrong = dict(asset, host_key_sha256="SHA256:" + base64.b64encode(hashlib.sha256(b"not-the-device").digest()).decode().rstrip("="))
        _, bad_service = service_for({args.asset: wrong})
        bad = bad_service.run({"action": "device.inspect", "parameters": {"asset": args.asset}})
        step("pinned_host_key_mismatch_refused", bad.status != "succeeded" and not bad.verified, status=bad.status)

        demo = device_rollback_demo(asset, name, before)
        step("device_auto_rollback_of_unconfirmed_commit", demo.pop("ok"), **demo)

    Path(args.out).write_text(json.dumps(steps, indent=2, default=str) + "\n")
    passed = all(s["ok"] for s in steps.values())
    print(("PASS" if passed else "FAIL"), f"{sum(s['ok'] for s in steps.values())}/{len(steps)} steps")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
