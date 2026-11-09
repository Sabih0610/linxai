"""Non-disruptive NETCONF validation for SHARED devices (e.g. Cisco DevNet always-on).

Nothing is ever committed. Through LINxAI: `device.inspect` and the prerequisite check
of a `device.interface.set` (prepared, never executed). Directly: the handshake refuses
a wrong pinned host key before authentication, and the exact OpenConfig edit LINxAI
would send is staged in the candidate under OUR lock, validated and discarded. If the
candidate is locked or holds someone else's edits, staging is skipped, never forced.
    LINXAI_TEST_NETCONF_SHARED=1 python3 -B scripts/validate_netconf_shared.py --assets a.json --asset xr
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OC = "http://openconfig.net/yang/interfaces"


def connect(asset):
    from ncclient import manager
    auth = {"key_filename": asset["key_path"]} if "key_path" in asset else {"password": Path(asset["password_file"]).read_text().strip()}
    pin = (dict(hostkey_verify=True, hostkey_b64=asset["host_key"].split()[1], unknown_host_cb=lambda *_: False)
           if "host_key" in asset else dict(hostkey_verify=False))
    return manager.connect(host=asset["host"], port=asset["port"], username=asset["username"], allow_agent=False,
                           look_for_keys=False, timeout=30, **auth, **pin)


def running_digest(m):
    data = m.get_config(source="running", filter=("subtree", f'<interfaces xmlns="{OC}"/>')).data_xml
    return hashlib.sha256(data.encode()).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True)
    parser.add_argument("--asset", required=True)
    parser.add_argument("--out", default="netconf-shared-validation.json")
    args = parser.parse_args(argv)
    if os.environ.get("LINXAI_TEST_NETCONF_SHARED") != "1":
        print("PENDING: opt in with LINXAI_TEST_NETCONF_SHARED=1"); return 3
    from operations.audit import JsonlAudit
    from operations.registry import ActionRegistry
    from operations.service import Approval, LocalPolicy, OperationService
    from operations.workflows import WorkflowSystem
    uid, assets, steps = os.getuid(), json.loads(Path(args.assets).read_text()), {}
    asset, name = assets[args.asset], assets[args.asset]["ports"][0]

    def step(label, ok, **facts):
        steps[label] = {"ok": bool(ok), **facts}
        print(("PASS " if ok else "FAIL ") + label, json.dumps(facts, default=str)[:260], flush=True)

    with tempfile.TemporaryDirectory(prefix="linxai-ncshared-", dir=Path.home()) as temp:
        os.chmod(temp, 0o700)
        registry = ActionRegistry(temp, actor_uid=uid, assets_json=json.dumps(assets))
        service = OperationService(registry, WorkflowSystem(), LocalPolicy(uid), JsonlAudit(Path(temp) / "audit.jsonl"))
        inspected = service.run({"action": "device.inspect", "parameters": {"asset": args.asset}})
        view = json.loads(inspected.stdout) if inspected.stdout.strip().startswith("{") else {}
        enabled = view.get("device", {}).get("interfaces", {}).get(name, {}).get("enabled")
        step("inspect_via_linxai", inspected.status == "succeeded" and inspected.verified and enabled is not None,
             interface=name, enabled=enabled, writable=view.get("writable"), capabilities=view.get("capabilities"), reason=inspected.reason)

        request = {"action": "device.interface.set", "parameters": {"asset": args.asset, "interface": name, "enabled": not enabled,
                   "expected_revision": view.get("revision", "0" * 64), "transaction_id": str(uuid4())}}
        approval = service.prepare(request)              # runs every prerequisite; nothing is executed
        if view.get("writable"):
            step("change_prerequisites_pass_without_execution", isinstance(approval, Approval))
        else:
            step("change_refused_on_device_without_safe_commit", not isinstance(approval, Approval),
                 status=getattr(approval, "status", None))

        blob = bytes.fromhex("0000000b7373682d6564323535313900000020") + os.urandom(32)
        fake = dict(asset, host_key="ssh-ed25519 " + base64.b64encode(blob).decode(),
                    host_key_sha256="SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("="))
        try:
            connect(fake).close_session(); step("wrong_host_key_refused_before_auth", False)
        except Exception as exc:
            step("wrong_host_key_refused_before_auth", "auth" not in type(exc).__name__.lower(), error=type(exc).__name__)

        xml = (f'<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"><interfaces xmlns="{OC}"><interface>'
               f'<name>{name}</name><config><name>{name}</name><enabled>{"false" if enabled else "true"}</enabled></config>'
               f'</interface></interfaces></nc:config>')
        with connect(asset) as m:
            before = running_digest(m)
            if not view.get("writable"):
                step("staged_edit_validated_and_discarded", True, skipped="device has no candidate datastore")
            else:
                try:
                    m.lock("candidate")
                except Exception as exc:
                    step("staged_edit_validated_and_discarded", True, skipped="candidate busy: " + str(exc).strip()[:80])
                else:
                    try:
                        m.edit_config(target="candidate", config=xml)
                        m.validate(source="candidate")
                        validated = True
                    except Exception as exc:
                        validated = str(exc).strip()[:160]
                    finally:
                        m.discard_changes(); m.unlock("candidate")
                    step("staged_edit_validated_and_discarded", validated is True, error=None if validated is True else validated)
            step("running_config_unchanged", running_digest(m) == before)

    Path(args.out).write_text(json.dumps(steps, indent=2, default=str) + "\n")
    passed = all(s["ok"] for s in steps.values())
    print(("PASS" if passed else "FAIL"), f"{sum(s['ok'] for s in steps.values())}/{len(steps)} steps")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
