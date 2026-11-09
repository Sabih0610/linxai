"""Real SSH acceptance of typed remote operations (requirements 52-57).

Ordinary owner on a prepared target. `--assets` names a private JSON file of
configured linux_ssh assets (pinned key, pinned known_hosts, peer interpreter with
LINxAI importable). For every asset: typed reads and a service status run through
the real OperationService -> /usr/bin/ssh (strict host key, batch mode, no agent or
forwarding) -> operations.remote_peer -> peer OperationService, and are verified.
Negative checks: a host-key mismatch fails closed, non-admitted/nested actions are
refused before SSH, and replaying an operation id is refused by the peer.
    LINXAI_TEST_REMOTE_LAB=1 python3 -B scripts/accept_remote.py --assets assets.json
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", required=True)
    parser.add_argument("--out", default="remote-acceptance.json")
    args = parser.parse_args(argv)
    if os.environ.get("LINXAI_TEST_REMOTE_LAB") != "1":
        print("PENDING: opt in with LINXAI_TEST_REMOTE_LAB=1 on the prepared target"); return 3
    from operations.audit import JsonlAudit
    from operations.registry import ActionRegistry
    from operations.service import LocalPolicy, OperationService
    from operations.workflows import WorkflowSystem
    uid = os.getuid()
    if uid == 0:
        raise PermissionError("Run as the ordinary owner")
    assets = json.loads(Path(args.assets).read_text())
    record = {"assets": {}, "negative": {}}
    with tempfile.TemporaryDirectory(prefix="linxai-remote-", dir=Path.home()) as temp:
        workspace = Path(temp) / "workspace"; workspace.mkdir(mode=0o700)
        def service_for(values):
            registry = ActionRegistry(str(workspace), actor_uid=uid, assets_json=json.dumps(values))
            return registry, OperationService(registry, WorkflowSystem(), LocalPolicy(uid), JsonlAudit(Path(temp) / "audit.jsonl"))
        registry, service = service_for(assets)
        for name in assets:
            runs = []
            for action, params in (("memory.usage", {}), ("disk.usage", {}), ("service.status", {"service": "ssh.service"})):
                started = time.monotonic()
                result = service.run({"action": "remote.operation", "parameters": {"asset": name, "action": action, "parameters": params}})
                peer = json.loads(result.stdout).get("result", {}) if result.stdout.strip().startswith("{") else {}
                runs.append({"action": action, "status": result.status, "verified": result.verified,
                             "peer_status": peer.get("status"), "peer_verified": peer.get("verified"),
                             "seconds": round(time.monotonic() - started, 2)})
                print(name, runs[-1], flush=True)
            record["assets"][name] = runs
        first = next(iter(assets))
        # Host-key mismatch: same asset, known_hosts pinned to a different (fresh) key.
        bogus_key = Path(temp) / "bogus"; subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(bogus_key)], check=True)
        bogus_hosts = Path(temp) / "known_hosts"
        host = assets[first]["host"]; port = assets[first]["port"]
        entry = host if port == 22 else f"[{host}]:{port}"
        bogus_hosts.write_text(entry + " " + " ".join(Path(str(bogus_key) + ".pub").read_text().split()[:2]) + "\n"); bogus_hosts.chmod(0o644)
        _, bad_service = service_for({first: {**assets[first], "known_hosts": str(bogus_hosts)}})
        bad = bad_service.run({"action": "remote.operation", "parameters": {"asset": first, "action": "memory.usage", "parameters": {}}})
        record["negative"]["host_key_mismatch"] = {"status": bad.status, "verified": bad.verified,
                                                   "stderr_has_host_key_error": "host key" in bad.stderr.lower() or "host key" in (bad.reason or "").lower()}
        refused = {}
        for label, params in {"raw_shell": {"asset": first, "action": "shell", "parameters": {"command": "id"}},
                              "nested_remote": {"asset": first, "action": "remote.operation", "parameters": {}},
                              "unknown_asset": {"asset": "nope", "action": "memory.usage", "parameters": {}}}.items():
            try:
                registry.prepare("remote.operation", params); refused[label] = "NOT REFUSED"
            except (ValueError, PermissionError) as exc:
                refused[label] = "refused: " + type(exc).__name__
        record["negative"]["refused_before_ssh"] = refused
        # Replay: send the same envelope twice over the real SSH path; the peer must refuse the second.
        prepared = registry.prepare("remote.operation", {"asset": first, "action": "memory.usage", "parameters": {}})
        envelope = json.dumps({"version": 1, "operation_id": str(uuid4()),
                               "request": {"action": "memory.usage", "parameters": {}}}, sort_keys=True).encode()
        codes = [subprocess.run(list(prepared.argv), input=envelope, capture_output=True, timeout=30).returncode for _ in range(2)]
        record["negative"]["replay"] = {"first_exit": codes[0], "second_exit": codes[1]}
    Path(args.out).write_text(json.dumps(record, indent=2) + "\n")
    ok = (all(r["status"] == "succeeded" and r["verified"] and r["peer_verified"] for runs in record["assets"].values() for r in runs)
          and record["negative"]["host_key_mismatch"]["status"] != "succeeded"
          and all(v.startswith("refused") for v in refused.values())
          and codes[0] == 0 and codes[1] != 0)
    print("PASS" if ok else "FAIL", json.dumps(record["negative"]))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
