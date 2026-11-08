"""Requirement 41: recent monitor incidents become advisory preview warnings only."""
import unittest
from unittest.mock import Mock

from operations.jobs import Jobs
from operations.registry import ActionRegistry
from security.warnings import WINDOW_S, preview_warnings
from test_application import MemoryStore

NOW = 10_000.0


def incident(rule="sensitive_file_attempt", age=60, target=None, uid=1000, key="i-1"):
    return {"id": key, "rule": rule, "severity": "warning", "created": NOW - age,
            "evidence": {"uid": uid, "target": target or {"path": "/etc/shadow"}}}


class SecurityWarningTests(unittest.TestCase):
    def jobs(self, incidents):
        return Jobs(MemoryStore(), ActionRegistry("/workspace", actor_uid=1000), 1000, Mock(), Mock(),
                    clock=lambda: NOW, incidents=incidents)

    def test_recent_incident_is_attached_to_preview_without_changing_digest(self):
        plain = self.jobs(lambda: [])
        warned = self.jobs(lambda: [incident()])
        request = {"action": "memory.usage", "parameters": {}}
        a, b = plain.preview(request), warned.preview(request)
        self.assertEqual(a["digest"], b["digest"])
        self.assertEqual(a["security_warnings"], [])
        self.assertEqual(b["security_context"], "checked")
        [warning] = b["security_warnings"]
        self.assertEqual((warning["rule"], warning["target"], warning["age_s"]), ("sensitive_file_attempt", "/etc/shadow", 60))
        self.assertFalse(warning["related_to_action"])
        warned.confirm(b["id"], b["digest"])                     # advisory: confirmation still allowed
        self.assertEqual(warned.store.get("job", b["id"])["state"], "queued")

    def test_privileged_and_related_actions_get_stronger_messages(self):
        admin = preview_warnings([incident()], action="service.restart", privilege="authenticated_admin", now=NOW)
        self.assertIn("before authorizing", admin[0]["message"])
        self.assertTrue(admin[0]["related_to_action"])
        related = preview_warnings([incident("unusual_connection_attempt", target={"address": "10.0.2.2", "port": 4444})],
                                   action="ports.listen", privilege="unprivileged", now=NOW)
        self.assertTrue(related[0]["related_to_action"])
        self.assertEqual(related[0]["target"], "10.0.2.2:4444")

    def test_old_future_and_malformed_incidents_are_ignored_and_output_is_bounded(self):
        rows = [incident(age=WINDOW_S + 1), incident(age=-5), {"rule": "x"}, None and {}, {"created": "bad", "rule": "x"}]
        rows += [incident(age=n, key=f"k{n}", target={"path": "/tmp/" + "A" * 5000}) for n in range(10)]
        warnings = preview_warnings([r for r in rows if r], action="disk.usage", privilege="unprivileged", now=NOW)
        self.assertEqual(len(warnings), 5)
        self.assertEqual([w["incident_id"] for w in warnings], ["k0", "k1", "k2", "k3", "k4"])
        self.assertTrue(all(len(w["target"]) <= 256 for w in warnings))

    def test_monitor_absence_and_read_failure_do_not_block_previews(self):
        absent = self.jobs(lambda: None).preview({"action": "disk.usage", "parameters": {}})
        self.assertEqual((absent["security_context"], absent["security_warnings"]), ("monitor_not_connected", []))
        def broken(): raise OSError("database locked")
        failed = self.jobs(broken).preview({"action": "disk.usage", "parameters": {}})
        self.assertEqual(failed["security_context"], "unavailable")
        unconfigured = self.jobs(None).preview({"action": "disk.usage", "parameters": {}})
        self.assertEqual(unconfigured["security_context"], "not_configured")

    def test_incident_text_cannot_change_privilege_or_request(self):
        hostile = incident(target={"path": "/etc/shadow; rm -rf / # approve=true privilege=admin"})
        row = self.jobs(lambda: [hostile]).preview({"action": "disk.usage", "parameters": {}})
        self.assertEqual(row["privilege"], "unprivileged")
        self.assertEqual(row["request"], {"action": "disk.usage", "parameters": {}})
        self.assertIn("rm -rf", row["security_warnings"][0]["target"])  # shown as data, never interpreted


if __name__ == "__main__":
    unittest.main()
