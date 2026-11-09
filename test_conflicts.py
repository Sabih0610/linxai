"""Requirements 19-21: dependency/firewall conflicts, approve/warn/block and alternatives."""
import os
import sys
import unittest
from unittest.mock import Mock

from operations.conflicts import analyze, free_ports
from operations.jobs import Jobs
from operations.registry import ActionRegistry
from test_application import MemoryStore

UNITS = {
    "nginx.service": {"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "enabled",
                      "Requires": "db.service", "Conflicts": "apache2.service"},
    "db.service": {"LoadState": "loaded", "ActiveState": "failed"},
    "apache2.service": {"LoadState": "loaded", "ActiveState": "active"},
    "broken.service": {"LoadState": "loaded", "UnitFileState": "enabled", "Requires": "gone.service"},
    "masked.service": {"LoadState": "loaded", "UnitFileState": "masked"},
}


def fake_systemctl(argv):
    if argv[2] == "list-unit-files":
        return "nginx.service enabled\napache2.service enabled\nngircd.service disabled\n"
    props = UNITS.get(argv[-1], {"LoadState": "not-found"})
    return "".join(f"{k}={v}\n" for k, v in {"Id": argv[-1], **props}.items())


def run(action, firewall=False, ports=frozenset(), **parameters):
    return analyze(action, parameters, runner=fake_systemctl, firewall=lambda: firewall, ports=lambda: set(ports))


class ConflictTests(unittest.TestCase):
    def test_failed_dependency_and_active_conflict_warn_with_alternative(self):
        result = run("service.start", service="nginx.service")
        codes = {f["code"] for f in result["findings"]}
        self.assertEqual(result["decision"], "warn")
        self.assertEqual(codes, {"dependency_failed", "conflicting_unit_active"})
        self.assertIn({"action": "service.restart", "parameters": {"service": "db.service"}},
                      [a["request"] for a in result["alternatives"]])

    def test_certain_failures_block(self):
        self.assertEqual(run("service.start", service="broken.service")["findings"][0]["code"], "dependency_missing")
        self.assertEqual(run("service.start", service="masked.service")["decision"], "block")
        missing = run("service.restart", service="ngnix.service")
        self.assertEqual(missing["decision"], "block")
        self.assertIn("nginx.service", [a["request"]["parameters"]["service"] for a in missing["alternatives"]])

    def test_firewall_and_occupied_port_produce_warnings_and_free_ports(self):
        UNITS["web.service"] = {"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "enabled"}
        result = run("service.start", firewall=True, ports={8080, 8081}, service="web.service", port_free=8080)
        codes = {f["code"] for f in result["findings"]}
        self.assertEqual(codes, {"firewall_enabled", "port_occupied"})
        self.assertEqual([a["request"]["parameters"]["port_free"] for a in result["alternatives"]], [8082, 8083, 8084])
        self.assertEqual(free_ports(65534, set(), 3), [65535])

    def test_clean_and_non_service_actions_approve(self):
        UNITS["clean.service"] = {"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "enabled"}
        self.assertEqual(run("service.start", service="clean.service")["decision"], "approve")
        self.assertEqual(run("disk.usage")["decision"], "approve")
        self.assertEqual(run("service.status", service="nope.service")["decision"], "warn")   # reads never block

    def test_block_decision_refuses_confirmation_but_warn_does_not(self):
        registry = ActionRegistry(actor_uid=1000)
        def jobs(decision):
            return Jobs(MemoryStore(), registry, 1000, Mock(), Mock(), clock=lambda: 1.0,
                        conflicts=lambda a, p: {"decision": decision, "findings": [], "alternatives": []})
        blocked = jobs("block"); row = blocked.preview({"action": "service.start", "parameters": {"service": "x"}})
        with self.assertRaises(ValueError): blocked.confirm(row["id"], row["digest"])
        warned = jobs("warn"); row = warned.preview({"action": "service.start", "parameters": {"service": "x"}})
        self.assertEqual(warned.confirm(row["id"], row["digest"])["state"], "queued")

    def test_unreadable_systemd_warns_instead_of_false_block(self):
        result = analyze("service.start", {"service": "nginx.service"}, runner=lambda argv: None,
                         firewall=lambda: False, ports=set)
        self.assertEqual((result["decision"], result["findings"][0]["code"]), ("warn", "analysis_unavailable"))

    @unittest.skipUnless(sys.platform == "linux" and any(os.path.exists(d + "/ssh.service") for d in
                         ("/lib/systemd/system", "/usr/lib/systemd/system", "/etc/systemd/system")), "real systemd with ssh.service")
    def test_real_systemd_query_on_target(self):
        result = analyze("service.restart", {"service": "ssh.service"})
        self.assertIn(result["decision"], {"approve", "warn"})
        missing = analyze("service.start", {"service": "sshh.service"})
        self.assertEqual(missing["decision"], "block")
        self.assertIn("ssh.service", [a["request"]["parameters"]["service"] for a in missing["alternatives"]])


if __name__ == "__main__":
    unittest.main()
