"""End-to-end integration acceptance across the modules (requirements 69, 71).

Ordinary owner on the prepared target with the root sensor, broker and policy
daemon running and the monitor writing ~/.linxai/security.sqlite. One run walks:
  AI      natural language -> planning graph -> typed preview (no model needed)
  OPS     confirm -> supervised execution -> verified postconditions -> audit
  CONTEXT follow-up resolved from job history; admin action previewed, never run
  CONFLICT service preview carries an approve/warn/block decision
  SEC     harmless fixture -> kernel event -> monitor incident (with lineage field)
  WARN    the next preview carries the incident as an advisory security warning
  EXPLAIN explanation of the incident and the job; cross-module timeline
  RES     typed process lowering of an owned child, verified; path/user inspection
  DEVOPS  Node project recipe in the workspace
  LEARN   medallion lake cycle and baseline readiness
  POLICY  policy daemon reachable and kernel qualification recorded for this boot
Nothing privileged is executed; admin steps are only previewed.
    LINXAI_TEST_INTEGRATED=1 python3 -B scripts/accept_integrated.py --out integrated.json
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="integrated.json")
    args = parser.parse_args(argv)
    if os.environ.get("LINXAI_TEST_INTEGRATED") != "1":
        print("PENDING: opt in with LINXAI_TEST_INTEGRATED=1 on the prepared target"); return 3
    from operations.agent import Agent
    from operations.store import Store
    uid, steps = os.getuid(), {}
    if uid == 0:
        raise PermissionError("Run as the ordinary owner")
    state = Path.home() / ".linxai"

    def step(name, ok, **facts):
        steps[name] = {"ok": bool(ok), **facts}
        print(("PASS " if ok else "FAIL ") + name, json.dumps(facts)[:300], flush=True)

    with tempfile.TemporaryDirectory(prefix="linxai-int-", dir=Path.home()) as temp:
        os.chmod(temp, 0o700)
        workspace = Path(temp) / "work"; workspace.mkdir(mode=0o700)
        agent = Agent(state, str(workspace))
        call = lambda method, **fields: agent.handle(uid, {"version": 1, "method": method, **fields})

        def run_job(row):
            call("confirm", id=row["id"], digest=row["digest"])
            agent.jobs.process(row["id"])
            return call("job", id=row["id"])

        row = call("preview", text="show memory usage")
        trace = (row.get("plan") or {}).get("workflow", {}).get("trace", [])
        step("ai_preview", row["request"]["action"] == "memory.usage" and "adapt" in trace, trace=trace)
        done = run_job(row)
        result = done.get("result") or {}
        step("ops_execute_verify_audit", done["state"] == "succeeded" and result.get("verified") is True
             and result.get("audit_complete") is True, state=done["state"])

        status = call("preview", text="is ssh running")
        follow = call("preview", text="restart it")
        step("context_follow_up_and_admin_preview",
             follow["request"] == {"action": "service.restart", "parameters": {"service": "ssh.service"}}
             and follow.get("privilege") == "authenticated_admin", privilege=follow.get("privilege"))
        decision = (follow.get("conflicts") or {}).get("decision")
        step("conflict_decision", decision in {"approve", "warn", "block"}, decision=decision)
        call("cancel", id=follow["id"]); call("cancel", id=status["id"])

        started = time.time()
        probe = Path("/tmp") / f"linxai-int-{os.getpid()}"
        probe.write_text("#!/bin/sh\nsleep 3\n"); probe.chmod(0o700)
        try:
            subprocess.run([str(probe)], timeout=10)
        finally:
            probe.unlink()
        incident = None
        for _ in range(30):
            store = Store(state / "security.sqlite")
            try:
                incident = next((r for r in store.list("incident", 50) if r.get("created", 0) >= started
                                 and r.get("rule") == "temporary_executable_attempt"), None)
            finally:
                store.close()
            if incident:
                break
            time.sleep(1)
        step("security_kernel_incident", incident is not None,
             latency_s=round(incident["created"] - started, 2) if incident else None,
             lineage=(incident or {}).get("lineage", {}).get("identity"))

        warned = call("preview", text="restart ssh")
        warnings = warned.get("security_warnings") or []
        step("security_warning_on_next_preview",
             any(w.get("rule") == "temporary_executable_attempt" for w in warnings), warnings=len(warnings))
        call("cancel", id=warned["id"])

        explained = call("explain", id=incident["id"]) if incident else {"explanation": []}
        job_text = " ".join(call("explain", id=row["id"])["explanation"])
        step("explain_incident_and_job", incident is not None and "attempt" in " ".join(explained["explanation"])
             and "verified" in job_text)
        modules = {r["module"] for r in call("timeline", limit=100)["timeline"]}
        step("timeline_cross_module", {"operations", "audit", "security"} <= modules, modules=sorted(modules))

        child = subprocess.Popen(["/usr/bin/sleep", "120"])
        try:
            from operations.system import proc_stat
            lowered = call("typed_preview", request={"action": "process.priority.lower",
                                                     "parameters": {"pid": child.pid, "start_ticks": proc_stat(child.pid)[0], "nice": 5}})
            done = run_job(lowered)
            step("resource_lower_verified", done["state"] == "succeeded" and proc_stat(child.pid)[1] == 5, state=done["state"])
        finally:
            child.kill(); child.wait()
        inspected = run_job(call("preview", text="who owns /etc"))
        owner = json.loads((inspected.get("result") or {}).get("stdout") or "{}").get("chain", [{}])[0].get("owner")
        step("path_inspection", inspected["state"] == "succeeded" and owner == "root", owner=owner)

        recipe = run_job(call("preview", text="create a node project in web"))
        step("devops_node_recipe", recipe["state"] == "succeeded" and (workspace / "web/package.json").exists(), state=recipe["state"])

        from security.lake import Lake
        lake = Lake(Store(state / "lake.sqlite"), Store(state / "security.sqlite"))
        cycle = lake.run_cycle()
        model = lake.model()
        step("learning_lake_cycle", isinstance(cycle, dict) and isinstance(model, dict),
             cycle={k: cycle.get(k) for k in list(cycle)[:6]} if isinstance(cycle, dict) else None)

        try:
            from security.policy_daemon import PolicyClient
            policy = PolicyClient().call("status")
            step("policy_daemon_qualified", policy.get("qualified") is True, qualified=policy.get("qualified"))
        except Exception as exc:
            step("policy_daemon_qualified", False, error=type(exc).__name__ + ": " + str(exc)[:120])

    Path(args.out).write_text(json.dumps(steps, indent=2, default=str) + "\n")
    passed = all(s["ok"] for s in steps.values())
    print(("PASS" if passed else "FAIL"), f"{sum(s['ok'] for s in steps.values())}/{len(steps)} steps")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
