"""Original requirements 46-49: typed process inventory and priority actions."""
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import Mock

from ai.local_planner import Planner
from operations.registry import ActionRegistry, InvalidParameters, Privilege
from operations.service import LocalPolicy

LINUX = sys.platform == "linux"


class ResourceContractTests(unittest.TestCase):
    registry = ActionRegistry(actor_uid=1000)

    def test_inventory_is_bounded_fixed_program_read(self):
        prepared = self.registry.prepare("process.list", {"limit": 5})
        self.assertEqual(prepared.argv[:3], ("/usr/bin/python3", "-I", "-c"))
        self.assertEqual(prepared.argv[-2:], ("list", "5"))
        self.assertIs(prepared.contract.privilege, Privilege.UNPRIVILEGED)
        for bad in ({"limit": 0}, {"limit": 51}, {"limit": True}, {"limit": "5"}, {"limit": 5, "shell": "x"}):
            with self.assertRaises(InvalidParameters): self.registry.prepare("process.list", bad)

    def test_lower_binds_stable_identity_and_owner(self):
        prepared = self.registry.prepare("process.priority.lower", {"pid": 4321, "start_ticks": 99, "nice": 10})
        checks = {c.identifier: dict(c.arguments) for c in prepared.mandatory_checks}
        self.assertEqual(checks["process_identity"], {"pid": 4321, "start_ticks": 99, "uid": 1000})
        self.assertEqual(checks["nice_direction"]["direction"], "increase")
        self.assertNotIn("authenticated_authorization", checks)
        self.assertTrue(prepared.contract.recovery_supported)
        self.assertEqual(prepared.argv[-5:], ("lower", "4321", "99", "10", "1000"))

    def test_restore_is_admin_bounded_at_nice_zero(self):
        prepared = self.registry.prepare("process.priority.restore", {"pid": 4321, "start_ticks": 99, "nice": 0})
        self.assertIs(prepared.contract.privilege, Privilege.AUTHENTICATED_ADMIN)
        self.assertIn("authenticated_authorization", [c.identifier for c in prepared.mandatory_checks])
        self.assertFalse(LocalPolicy(1000).allows(Mock(ordinary=lambda: True, uid=1000), "process.priority.restore"))

    def test_rejects_pid_only_names_and_out_of_range_values(self):
        lower = lambda **p: self.registry.prepare("process.priority.lower", p)
        for params in ({"pid": 4321, "nice": 10}, {"name": "firefox", "nice": 10},
                       {"pid": 1, "start_ticks": 9, "nice": 10}, {"pid": 4321, "start_ticks": 9, "nice": 0},
                       {"pid": 4321, "start_ticks": 9, "nice": 20}, {"pid": 4321, "start_ticks": 9, "nice": -5}):
            with self.assertRaises(InvalidParameters): lower(**params)
        with self.assertRaises(InvalidParameters):
            self.registry.prepare("process.priority.restore", {"pid": 4321, "start_ticks": 9, "nice": 19})
        with self.assertRaises(InvalidParameters):
            ActionRegistry().prepare("process.priority.lower", {"pid": 4321, "start_ticks": 9, "nice": 10})

    def test_natural_language_inventory_uses_fast_path_without_model(self):
        model = Mock()
        request, plan = Planner(self.registry, model).propose("show top processes")
        self.assertEqual(request, {"action": "process.list", "parameters": {}})
        request, _ = Planner(self.registry, model).propose("forecast cpu usage")
        self.assertEqual(request["action"], "resource.forecast")
        model.generate.assert_not_called()

    def test_forecast_contract_is_bounded_read(self):
        prepared = self.registry.prepare("resource.forecast", {"samples": 20, "horizon_s": 120})
        self.assertEqual(prepared.argv[-3:], ("forecast", "20", "120"))
        self.assertIs(prepared.contract.privilege, Privilege.UNPRIVILEGED)
        self.assertLessEqual(20 * 0.5 + 5, prepared.contract.timeout_s)
        for bad in ({"samples": 4}, {"samples": 41}, {"horizon_s": 5}, {"horizon_s": 601}, {"apply": True}):
            with self.assertRaises(InvalidParameters): self.registry.prepare("resource.forecast", bad)

    def test_path_and_user_inspection_contracts_are_bounded_reads(self):
        # Requirements 17/18: metadata-only reads, unprivileged, exact parameters.
        prepared = self.registry.prepare("path.inspect", {"path": "/etc/ssh"})
        self.assertIs(prepared.contract.privilege, Privilege.UNPRIVILEGED)
        self.assertEqual(prepared.argv[-2:], ("path", "/etc/ssh"))
        for bad in ({"path": "etc"}, {"path": "/etc/../root"}, {"path": "/etc\x00"}, {"path": "/etc", "follow": True}, {}):
            with self.assertRaises(InvalidParameters, msg=bad):
                self.registry.prepare("path.inspect", bad)
        self.assertEqual(self.registry.prepare("user.lookup", {}).argv[-1], "1000")
        self.assertEqual(self.registry.prepare("user.lookup", {"user": "www-data"}).argv[-1], "www-data")
        for bad in ({"user": "Root;id"}, {"user": "../x"}, {"user": True}, {"user": "a" * 40}):
            with self.assertRaises(InvalidParameters, msg=bad):
                self.registry.prepare("user.lookup", bad)
        planner = Planner(self.registry, Mock())
        self.assertEqual(planner.propose("who owns /var/log")[0], {"action": "path.inspect", "parameters": {"path": "/var/log"}})
        self.assertEqual(planner.propose("what groups is alice in?")[0], {"action": "user.lookup", "parameters": {"user": "alice"}})
        self.assertEqual(planner.propose("who am i")[0], {"action": "user.lookup", "parameters": {}})
        planner.model.generate.assert_not_called()

    def test_forecast_math_detects_rising_trend_and_clamps(self):
        from operations._resource_program import FORECAST_MATH
        math = {}
        exec(FORECAST_MATH, math)
        rising = [40, 45, 50, 55, 60, 65, 70, 75, 80, 85]          # +10 %/s at 0.5 s spacing
        predicted, slope, _level = math["forecast"](rising, 0.5, 10)
        self.assertAlmostEqual(slope, 10.0)
        self.assertEqual(predicted, 100.0)                            # clamped
        flat = math["forecast"]([20.0] * 10, 0.5, 60)
        self.assertEqual((flat[0], flat[1]), (20.0, 0.0))
        falling = math["forecast"]([60, 50, 40, 30, 20], 0.5, 60)
        self.assertEqual(falling[0], 0.0)


@unittest.skipUnless(LINUX and hasattr(os, "getuid") and os.getuid() != 0, "requires an ordinary Linux account")
class NativeResourceTests(unittest.TestCase):
    def setUp(self):
        from operations.service import OperationService
        from operations.system import proc_stat
        from operations.workflows import WorkflowSystem
        from test_application import MemoryAudit
        self.uid, self.proc_stat = os.getuid(), proc_stat
        self.child = subprocess.Popen(["/bin/sleep", "60"])
        self.addCleanup(lambda: (self.child.kill(), self.child.wait()))
        self.start = proc_stat(self.child.pid)[0]
        self.service = OperationService(ActionRegistry(actor_uid=self.uid), WorkflowSystem(), LocalPolicy(self.uid), MemoryAudit())

    def run_action(self, action, **params):
        return self.service.run({"action": action, "parameters": params})

    def test_path_and_user_inspection_on_target(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir=os.path.expanduser("~")) as temp:
            target = os.path.join(temp, "data"); open(target, "w").close(); os.chmod(target, 0o640)
            result = self.run_action("path.inspect", path=target)
            self.assertEqual((result.status, result.verified), ("succeeded", True), result)
            value = json.loads(result.stdout)
            self.assertEqual((value["exists"], value["chain"][0]["mode"], value["chain"][0]["uid"]), (True, "0o640", self.uid))
            self.assertEqual(value["actor_access"], {"read": True, "write": True, "execute": False})
            missing = json.loads(self.run_action("path.inspect", path=target + "-missing").stdout)
            self.assertFalse(missing["exists"])
        shadow = json.loads(self.run_action("path.inspect", path="/etc/shadow").stdout)
        self.assertFalse(shadow["actor_access"]["read"])
        me = json.loads(self.run_action("user.lookup").stdout)
        self.assertEqual((me["uid"], me["is_actor"]), (self.uid, True))
        root = self.run_action("user.lookup", user="root")
        self.assertEqual((json.loads(root.stdout)["uid"], root.verified), (0, True))
        self.assertFalse(json.loads(self.run_action("user.lookup", user="no-such-user-x").stdout)["exists"])

    def test_inventory_observes_child_with_identity(self):
        result = self.run_action("process.list", limit=50)
        self.assertEqual((result.status, result.verified), ("succeeded", True))
        value = json.loads(result.stdout)
        self.assertGreater(value["observed"], 0)
        self.assertLessEqual(len(value["processes"]), 50)

    def test_lower_verifies_and_captures_admin_restoration(self):
        result = self.run_action("process.priority.lower", pid=self.child.pid, start_ticks=self.start, nice=7)
        self.assertEqual((result.status, result.verified), ("succeeded", True), result.reason)
        self.assertEqual(self.proc_stat(self.child.pid)[1], 7)
        self.assertEqual(result.recovery, "available_for_review")
        self.assertEqual(result.restoration, {"action": "process.priority.restore",
                                              "parameters": {"pid": self.child.pid, "start_ticks": self.start, "nice": 0}})
        again = self.run_action("process.priority.lower", pid=self.child.pid, start_ticks=self.start, nice=5)
        self.assertEqual(again.status, "validation_failed")       # cannot raise priority as ordinary user
        restore = self.run_action("process.priority.restore", pid=self.child.pid, start_ticks=self.start, nice=0)
        self.assertFalse(restore.executed)                         # admin action: never dispatched locally
        self.assertEqual(self.proc_stat(self.child.pid)[1], 7)

    def test_forecast_runs_and_verifies_on_target(self):
        result = self.run_action("resource.forecast", samples=6, horizon_s=60)
        self.assertEqual((result.status, result.verified), ("succeeded", True), result.reason)
        value = json.loads(result.stdout)
        self.assertEqual(len(value["cpu"]["observed"]), 6)
        self.assertLessEqual(len(value["recommendations"]), 5)

    def test_stale_identity_is_refused_without_change(self):
        result = self.run_action("process.priority.lower", pid=self.child.pid, start_ticks=self.start + 1, nice=9)
        self.assertEqual((result.status, result.executed), ("validation_failed", False))
        self.assertEqual(self.proc_stat(self.child.pid)[1], 0)


if __name__ == "__main__":
    unittest.main()
