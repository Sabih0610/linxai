"""Agentless Linux acceptance: typed operations on targets WITHOUT LINxAI installed.

Ordinary owner; `--assets` is a private JSON file with `linux_agentless` assets
(pinned known_hosts, key-only login). The targets need nothing but sshd, coreutils,
iproute2 and systemd. A harmless user unit `linxai-agentless-demo.service` must
exist on the user-scope target (see lab-scripts/agentless-setup.sh).
    LINXAI_TEST_AGENTLESS_LAB=1 python3 -B scripts/accept_agentless.py --assets assets.json \
        --system vmloop --user vmloop-user --second vmnat
"""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
DEMO = "linxai-agentless-demo.service"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True)
    parser.add_argument("--system", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--second", required=True)
    parser.add_argument("--system-fixture", default="linxai-lab-acceptance.service")
    parser.add_argument("--out", default="agentless-acceptance.json")
    args = parser.parse_args(argv)
    if os.environ.get("LINXAI_TEST_AGENTLESS_LAB") != "1":
        print("PENDING: opt in with LINXAI_TEST_AGENTLESS_LAB=1 against lab targets"); return 3
    from operations.audit import JsonlAudit
    from operations.registry import ActionRegistry
    from operations.service import LocalPolicy, OperationService
    from operations.workflows import WorkflowSystem
    uid, assets, steps = os.getuid(), json.loads(Path(args.assets).read_text()), {}

    def step(label, ok, **facts):
        steps[label] = {"ok": bool(ok), **facts}
        print(("PASS " if ok else "FAIL ") + label, json.dumps(facts, default=str)[:220], flush=True)

    with tempfile.TemporaryDirectory(prefix="linxai-agentless-", dir=Path.home()) as temp:
        os.chmod(temp, 0o700)
        def service_for(values):
            registry = ActionRegistry(temp, actor_uid=uid, assets_json=json.dumps(values))
            return registry, OperationService(registry, WorkflowSystem(), LocalPolicy(uid), JsonlAudit(Path(temp) / "audit.jsonl"))
        registry, service = service_for(assets)

        def remote(asset, action, **params):
            r = service.run({"action": "remote.operation", "parameters": {"asset": asset, "action": action, "parameters": params}})
            return r, (json.loads(r.stdout) if r.stdout.strip().startswith("{") else {})

        for asset in (args.system, args.second):
            disk, d = remote(asset, "disk.usage")
            mem, m = remote(asset, "memory.usage")
            ports, p = remote(asset, "ports.listen", port=22)
            status, s = remote(asset, "service.status", service="ssh")
            step(f"{asset}_reads_verified",
                 all(r.status == "succeeded" and r.verified for r in (disk, mem, ports, status))
                 and any(f["mount"] == "/" for f in d["result"]["filesystems"]) and 0 < m["result"]["used_pct"] < 100
                 and any(x["port"] == 22 for x in p["result"]["listening"]) and s["result"]["ActiveState"] == "active",
                 root=next((f for f in d.get("result", {}).get("filesystems", []) if f["mount"] == "/"), None),
                 memory_pct=m.get("result", {}).get("used_pct"), ssh=s.get("result", {}).get("ActiveState"))

        started, a = remote(args.user, "service.start", service=DEMO)
        step("user_service_start_verified", started.status == "succeeded" and started.verified and a["after"]["ActiveState"] == "active",
             before=a.get("before", {}).get("ActiveState"), after=a.get("after", {}).get("ActiveState"), reason=started.reason)
        restarted, b = remote(args.user, "service.restart", service=DEMO)
        step("user_service_restart_new_activation", restarted.status == "succeeded" and restarted.verified
             and b["after"]["ActiveEnterTimestampMonotonic"] != b["before"]["ActiveEnterTimestampMonotonic"],
             before=b.get("before", {}).get("ActiveEnterTimestampMonotonic"), after=b.get("after", {}).get("ActiveEnterTimestampMonotonic"))
        stopped, c = remote(args.user, "service.stop", service=DEMO)
        step("user_service_stop_verified", stopped.status == "succeeded" and stopped.verified and c["after"]["ActiveState"] == "inactive",
             after=c.get("after", {}).get("ActiveState"))

        denied, _ = remote(args.system, "service.restart", service=args.system_fixture)
        step("system_change_needs_target_sudo_policy", denied.status != "succeeded" and not denied.verified
             and "sudo policy" in (denied.stderr or ""), status=denied.status, stderr=(denied.stderr or "")[-160:])

        missing, _ = remote(args.system, "service.status", service="linxai-no-such-unit")
        step("unloaded_unit_refused_at_check", missing.status != "succeeded" and not missing.executed, status=missing.status)

        refused = {}
        for label, params in {"shell_injection": {"action": "service.status", "parameters": {"service": "ssh; reboot"}},
                              "raw_command": {"action": "shell", "parameters": {"command": "id"}},
                              "file_write": {"action": "file.create", "parameters": {"path": "x", "content": "y"}}}.items():
            try:
                registry.prepare("remote.operation", {"asset": args.system, **params}); refused[label] = "NOT REFUSED"
            except ValueError as exc:
                refused[label] = "refused: " + type(exc).__name__
        step("injection_raw_and_file_actions_refused", all(v.startswith("refused") for v in refused.values()), **refused)

        bogus = Path(temp) / "known_hosts"
        bogus.write_text("127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZrZXlGa2V5RmtleUZrZXlGa2V5RmtleUZrZXlGa2V5\n"); bogus.chmod(0o644)
        _, bad_service = service_for({args.system: dict(assets[args.system], known_hosts=str(bogus))})
        bad = bad_service.run({"action": "remote.operation", "parameters": {"asset": args.system, "action": "memory.usage", "parameters": {}}})
        step("host_key_mismatch_refused", bad.status != "succeeded" and not bad.verified, status=bad.status)

    Path(args.out).write_text(json.dumps(steps, indent=2, default=str) + "\n")
    passed = all(s["ok"] for s in steps.values())
    print(("PASS" if passed else "FAIL"), f"{sum(s['ok'] for s in steps.values())}/{len(steps)} steps")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
