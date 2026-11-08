"""Requirements 61-62: log viewer and deterministic explain mode."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from operations.explain import explain_anomaly, explain_incident, explain_job, tail_jsonl


class ExplainTests(unittest.TestCase):
    def test_tail_skips_corrupt_lines_filters_and_bounds(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "operations.jsonl"
            lines = [json.dumps({"operation_id": "a" if n % 2 else "b", "n": n}) for n in range(10)] + ["{broken"]
            path.write_text("\n".join(lines) + "\n")
            self.assertEqual([r["n"] for r in tail_jsonl(path, 3)], [7, 8, 9])
            self.assertEqual({r["operation_id"] for r in tail_jsonl(path, 50, operation_id="a")}, {"a"})
            self.assertEqual(tail_jsonl(Path(temp) / "missing.jsonl"), [])
            self.assertLessEqual(len(tail_jsonl(path, 10_000)), 200)

    def test_succeeded_job_with_restoration_and_warning(self):
        row = {"text": "lower priority of my build", "privilege": "unprivileged", "state": "succeeded",
               "request": {"action": "process.priority.lower", "parameters": {"pid": 42, "start_ticks": 7, "nice": 10}},
               "security_warnings": [{"rule": "temporary_executable_attempt", "target": "/tmp/*"}],
               "result": {"verified": True, "restoration": {"action": "process.priority.restore"}}}
        audit = [{"phase": "validation", "status": "passed"}] * 3
        text = " ".join(explain_job(row, audit))
        for fragment in ("process 42", "ordinary account", "3 mandatory", "verified", "process.priority.restore", "temporary_executable_attempt"):
            self.assertIn(fragment, text)

    def test_failed_and_uncertain_jobs_report_only_recorded_facts(self):
        failed = {"state": "failed", "privilege": "authenticated_admin",
                  "request": {"action": "service.restart", "parameters": {"service": "nginx.service"}}, "result": {"reason": "denied"}}
        audit = [{"phase": "validation", "status": "failed", "details": {"requirement": "service_exists", "reason": "Required state absent"}}]
        text = " ".join(explain_job(failed, audit))
        self.assertIn("administrator authorization", text)
        self.assertIn("service_exists", text)
        self.assertNotIn("verified", text)
        unknown = " ".join(explain_job({"state": "unknown", "request": {"action": "service.stop", "parameters": {"service": "x.service"}}}))
        self.assertIn("does not retry", unknown)

    def test_incident_and_anomaly_are_framed_as_evidence_not_proof(self):
        incident = {"rule": "sensitive_file_attempt", "severity": "warning", "response": "none",
                    "evidence": {"uid": 1000, "process": "cat", "target": {"path": "/etc/shadow"}}}
        self.assertIn("outcome is unknown", " ".join(explain_incident(incident)))
        anomaly = {"key": "/usr/bin/nc", "uid": 1000, "score_bits": 8.6, "baseline_events": 3000}
        self.assertIn("advisory", " ".join(explain_anomaly(anomaly)))


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "getuid") and os.getuid() != 0, "native agent")
class NativeAgentExplainTests(unittest.TestCase):
    def test_agent_runs_read_then_lists_logs_and_explains(self):
        from operations.agent import Agent
        with tempfile.TemporaryDirectory(prefix=".linxai-explain-", dir=Path.home()) as temp:
            os.chmod(temp, 0o700)
            state, workspace = Path(temp) / "state", Path(temp) / "work"
            workspace.mkdir(mode=0o700)
            agent = Agent(state, str(workspace))
            uid = os.getuid()
            row = agent.handle(uid, {"version": 1, "method": "typed_preview", "request": {"action": "memory.usage", "parameters": {}}})
            agent.handle(uid, {"version": 1, "method": "confirm", "id": row["id"], "digest": row["digest"]})
            agent.jobs.process(row["id"])
            logs = agent.handle(uid, {"version": 1, "method": "logs", "limit": 20})
            self.assertTrue(any(r.get("phase") == "result" for r in logs["records"]))
            explained = agent.handle(uid, {"version": 1, "method": "explain", "id": row["id"]})
            self.assertEqual(explained["kind"], "job")
            self.assertIn("postconditions were verified", " ".join(explained["explanation"]))
            with self.assertRaises(ValueError):
                agent.handle(uid, {"version": 1, "method": "logs", "limit": 0})


if __name__ == "__main__":
    unittest.main()
