"""Agentless Windows acceptance: typed operations on a Windows host WITHOUT LINxAI.

Ordinary owner on a Linux controller; `--assets` has one `windows_agentless` asset
(pinned known_hosts, key-only login to the Windows OpenSSH server). The service under
test (default Spooler) is returned to its original state at the end.
    LINXAI_TEST_WINDOWS_LAB=1 python3 -B scripts/accept_windows_agentless.py --assets assets.json --asset win
"""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True)
    parser.add_argument("--asset", required=True)
    parser.add_argument("--service", default="Spooler")
    parser.add_argument("--out", default="windows-agentless-acceptance.json")
    args = parser.parse_args(argv)
    if os.environ.get("LINXAI_TEST_WINDOWS_LAB") != "1":
        print("PENDING: opt in with LINXAI_TEST_WINDOWS_LAB=1 against a lab Windows host"); return 3
    from operations.audit import JsonlAudit
    from operations.registry import ActionRegistry
    from operations.service import LocalPolicy, OperationService
    from operations.workflows import WorkflowSystem
    uid, assets, steps = os.getuid(), json.loads(Path(args.assets).read_text()), {}

    def step(label, ok, **facts):
        steps[label] = {"ok": bool(ok), **facts}
        print(("PASS " if ok else "FAIL ") + label, json.dumps(facts, default=str)[:220], flush=True)

    with tempfile.TemporaryDirectory(prefix="linxai-win-", dir=Path.home()) as temp:
        os.chmod(temp, 0o700)
        def service_for(values):
            registry = ActionRegistry(temp, actor_uid=uid, assets_json=json.dumps(values))
            return registry, OperationService(registry, WorkflowSystem(), LocalPolicy(uid), JsonlAudit(Path(temp) / "audit.jsonl"))
        registry, service = service_for(assets)

        def remote(action, **params):
            r = service.run({"action": "remote.operation", "parameters": {"asset": args.asset, "action": action, "parameters": params}})
            return r, (json.loads(r.stdout) if r.stdout.strip().startswith("{") else {})

        disk, d = remote("disk.usage"); mem, m = remote("memory.usage"); ports, p = remote("ports.listen", port=22)
        status, s = remote("service.status", service=args.service)
        step("windows_reads_verified", all(r.status == "succeeded" and r.verified for r in (disk, mem, ports, status))
             and any(f["mount"] == "C:" for f in d["result"]["filesystems"]) and 0 < m["result"]["used_pct"] < 100
             and any(x["port"] == 22 for x in p["result"]["listening"]) and s["result"]["Id"].lower() == args.service.lower(),
             c_drive=next((f for f in d.get("result", {}).get("filesystems", []) if f["mount"] == "C:"), None),
             memory_pct=m.get("result", {}).get("used_pct"), service=s.get("result"), reason=status.reason)
        original = s.get("result", {}).get("ActiveState")

        if original == "Running":
            sequence = (("service.restart", "Running"), ("service.stop", "Stopped"), ("service.start", "Running"))
        else:
            sequence = (("service.start", "Running"), ("service.restart", "Running"), ("service.stop", "Stopped"))
        for action, expected in sequence:
            r, out = remote(action, service=args.service)
            facts = {"after": out.get("after", {}).get("ActiveState"), "reason": r.reason}
            if action == "service.restart":
                facts["proof"] = out.get("restart_proof")
            step(f"{action}_verified", r.status == "succeeded" and r.verified and out.get("after", {}).get("ActiveState") == expected, **facts)
        final = remote("service.status", service=args.service)[1].get("result", {}).get("ActiveState")
        step("service_returned_to_original_state", final == original, original=original, final=final)

        missing, _ = remote("service.status", service="LinxaiNoSuchService")
        step("unknown_service_refused_at_check", missing.status != "succeeded" and not missing.executed, status=missing.status)
        refused = {}
        for label, params in {"powershell_injection": {"action": "service.status", "parameters": {"service": "Spooler'; Stop-Computer"}},
                              "raw_command": {"action": "shell", "parameters": {"command": "whoami"}},
                              "file_write": {"action": "file.create", "parameters": {"path": "x", "content": "y"}}}.items():
            try:
                registry.prepare("remote.operation", {"asset": args.asset, **params}); refused[label] = "NOT REFUSED"
            except ValueError as exc:
                refused[label] = "refused: " + type(exc).__name__
        step("injection_raw_and_file_actions_refused", all(v.startswith("refused") for v in refused.values()), **refused)

        bogus = Path(temp) / "known_hosts"
        entry = assets[args.asset]["host"] if assets[args.asset]["port"] == 22 else f"[{assets[args.asset]['host']}]:{assets[args.asset]['port']}"
        bogus.write_text(entry + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZrZXlGa2V5RmtleUZrZXlGa2V5RmtleUZrZXlGa2V5\n"); bogus.chmod(0o644)
        _, bad_service = service_for({args.asset: dict(assets[args.asset], known_hosts=str(bogus))})
        bad = bad_service.run({"action": "remote.operation", "parameters": {"asset": args.asset, "action": "memory.usage", "parameters": {}}})
        step("host_key_mismatch_refused", bad.status != "succeeded" and not bad.verified, status=bad.status)

    Path(args.out).write_text(json.dumps(steps, indent=2, default=str) + "\n")
    passed = all(s["ok"] for s in steps.values())
    print(("PASS" if passed else "FAIL"), f"{sum(s['ok'] for s in steps.values())}/{len(steps)} steps")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
