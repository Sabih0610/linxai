"""Lifecycle regressions using disposable files and trusted adapter doubles."""
from dataclasses import replace
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from operations import ActionRegistry
from operations.cli import run_request
from operations.registry import FileParameters, DirectoryParameters, requirement
from operations.service import (
    Approval, Execution, Identity, LocalPolicy, Observation, OperationResult,
    OperationService, fingerprint,
)
from operations.system import LinuxSystemAdapter
from operations.audit import JsonlAudit


class MemoryAudit:
    def __init__(self):
        self.records = []
        self.fail_phase = None

    def append(self, record):
        if record["phase"] == self.fail_phase:
            raise OSError("simulated audit failure")
        self.records.append(json.loads(json.dumps(record)))


class IsolatedSystem:
    """All writes confined to a test-owned TemporaryDirectory; no subprocesses."""
    def __init__(self, root):
        self.root = Path(root)
        self.identity = Identity(1000, 1000, "tester")
        self.state = "initial"
        self.check_override = None
        self.post_failure = None
        self.execution_error = ""
        self.returncode = 0
        self.calls = []
        self.exec_count = 0
        self.corrupt = False

    def resolve_identity(self):
        return self.identity

    def check(self, op_id, required, identity):
        self.calls.append((op_id, "check", required.identifier))
        if self.check_override:
            return self.check_override(op_id, required, identity)
        return Observation(op_id, required, True, "observed", self.state)

    def execute(self, op_id, prepared, identity):
        self.exec_count += 1
        self.calls.append((op_id, "execute", prepared.argv))
        stdout = ""
        if not self.execution_error and self.returncode == 0:
            if isinstance(prepared.parameters, FileParameters):
                target = self.root / prepared.parameters.relative_path
                with target.open("xb") as stream:
                    stream.write(b"corrupt" if self.corrupt else prepared.stdin)
            elif isinstance(prepared.parameters, DirectoryParameters):
                (self.root / prepared.parameters.relative_path).mkdir()
            elif prepared.contract.identifier == "disk.usage":
                stdout = "Filesystem 1B-blocks Used Available Capacity Mounted on\n/dev/test 100 40 60 40% /\n"
            elif prepared.contract.identifier == "memory.usage":
                stdout = "              total used free shared buff/cache available\nMem: 1000 100 700 0 200 800\nSwap: 0 0 0\n"
            elif prepared.contract.identifier == "ports.listen":
                stdout = "LISTEN 0 16 127.0.0.1:80 0.0.0.0:*\n"
            elif prepared.contract.identifier == "service.status":
                stdout = f"Id={prepared.parameters.service}\nLoadState=loaded\nActiveState=inactive\nSubState=dead\n"
        return Execution(op_id, prepared.argv, self.returncode, stdout=stdout, error=self.execution_error)

    def verify(self, op_id, required, prepared, execution, identity):
        self.calls.append((op_id, "verify", required.identifier))
        if required.identifier == self.post_failure:
            return Observation(op_id, required, False, "simulated failed postcondition")
        if isinstance(prepared.parameters, (FileParameters, DirectoryParameters)):
            target = self.root / prepared.parameters.relative_path
            args = dict(required.arguments)
            if required.identifier == "file_content_sha256":
                ok = hashlib.sha256(target.read_bytes()).hexdigest() == args["sha256"]
            elif required.identifier == "entry_type":
                ok = target.is_file() if args["kind"] == "file" else target.is_dir()
            elif required.identifier == "entry_confined":
                ok = target.resolve().is_relative_to(self.root.resolve())
            else:
                ok = execution.returncode == 0
            return Observation(op_id, required, ok, "isolated entry observed")
        return LinuxSystemAdapter().verify(op_id, required, prepared, execution, identity)


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = self.enterContext(tempfile.TemporaryDirectory())
        self.system = IsolatedSystem(self.temp)
        self.audit = MemoryAudit()
        self.now = [10.0]
        self.registry = ActionRegistry("/srv/linxai-work")
        self.service = OperationService(self.registry, self.system, LocalPolicy(1000), self.audit,
                                        clock=lambda: self.now[0])
        for name in ("subprocess.Popen", "subprocess.run", "socket.create_connection", "os.system"):
            self.enterContext(patch(name, side_effect=AssertionError("Live operation forbidden")))

    def request(self, action="memory.usage", parameters=None):
        return {"action": action, "parameters": {} if parameters is None else parameters}

    def test_read_workflows_complete_and_correlate_all_phases(self):
        for action, parameters in (("disk.usage", {}), ("memory.usage", {}),
                                   ("ports.listen", {"port": 80}), ("service.status", {"service": "nginx"})):
            with self.subTest(action=action):
                result = self.service.run(self.request(action, parameters))
                self.assertEqual(result.status, "succeeded")
                self.assertTrue(result.executed and result.verified and result.audit_complete)
                records = [r for r in self.audit.records if r["operation_id"] == result.operation_id]
                self.assertTrue({"received", "identity", "authorization", "constructed", "validation",
                                 "approval", "execution", "verification", "result"} <= {r["phase"] for r in records})
                for record in records:
                    if record["phase"] in {"validation", "execution", "verification", "approval"}:
                        self.assertEqual(record["fingerprint"], result.fingerprint)
                calls = [c for c in self.system.calls if c[0] == result.operation_id]
                self.assertTrue({"check", "execute", "verify"} <= {c[1] for c in calls})

    def test_disposable_file_creation_is_verified_and_recovery_unsupported(self):
        content = "hello\n$(not executed)"
        result = self.service.run(self.request("file.create", {"path": "sample.txt", "content": content}))
        self.assertEqual(result.status, "succeeded")
        self.assertEqual((Path(self.temp) / "sample.txt").read_text(), content)
        self.assertEqual(result.recovery, "unsupported")
        self.assertNotIn(content, json.dumps(self.audit.records))
        self.assertNotIn("token", json.dumps(self.audit.records))

    def test_disposable_directory_creation(self):
        result = self.service.run(self.request("directory.create", {"path": "reports"}))
        self.assertEqual(result.status, "succeeded")
        self.assertTrue((Path(self.temp) / "reports").is_dir())

    def test_denied_account_never_checks_or_executes(self):
        self.system.identity = Identity(2000, 2000, "other")
        result = self.service.run(self.request())
        self.assertEqual(result.status, "authorization_denied")
        self.assertEqual(self.system.calls, [])
        self.assertEqual(self.audit.records[-1]["operation_id"], result.operation_id)

    def test_root_setuid_unknown_identity_and_boolean_identity_denied(self):
        for identity in (Identity(0, 0, "root"), Identity(1000, 0, "tester"),
                         Identity(1000, 1001, "tester"), Identity(1, True, "bad"), None):
            with self.subTest(identity=identity):
                self.system.identity = identity
                result = self.service.run(self.request())
                self.assertEqual(result.status, "identity_denied")
                self.assertFalse(result.executed)

    def test_privileged_actions_always_require_broker_even_with_permissive_policy(self):
        self.service.policy = types.SimpleNamespace(allows=lambda *args: True)
        for action in ("service.start", "service.stop", "service.restart"):
            with self.subTest(action=action):
                result = self.service.run(self.request(action, {"service": "nginx"}))
                self.assertEqual(result.status, "authentication_authorization_required")
                self.assertFalse(result.executed)
        self.assertEqual(self.system.calls, [])

    def test_client_identity_and_permission_claims_are_not_accepted(self):
        for field in ("identity", "uid", "authenticated", "approved", "requires_sudo"):
            request = self.request()
            request[field] = True
            with self.subTest(field=field):
                result = self.service.run(request)
                self.assertEqual(result.status, "invalid_request")
                self.assertFalse(result.executed)

    def test_unsupported_and_malformed_requests_return_correlated_errors(self):
        cases = (None, [], {}, {"action": "shell", "parameters": {"command": "id"}},
                 self.request("service.status", {"service": "nginx;id"}),
                 self.request("ports.listen", {"port": True}),
                 self.request("file.create", {"path": "../outside"}),
                 {"action": "disk.usage", "parameters": []})
        for request in cases:
            with self.subTest(request=request):
                result = self.service.run(request)
                self.assertEqual(result.status, "invalid_request")
                self.assertEqual(self.audit.records[-1]["operation_id"], result.operation_id)
        self.assertEqual(self.system.exec_count, 0)

    def test_missing_malformed_or_uncorrelated_checks_block(self):
        overrides = (
            lambda op, req, ident: None,
            lambda op, req, ident: Observation(op, req, None, "incomplete"),
            lambda op, req, ident: Observation("other", req, True, "wrong ID"),
            lambda op, req, ident: Observation(op, requirement("invented"), True, "wrong check"),
            lambda op, req, ident: Observation(op, req, False, "unavailable"),
        )
        for override in overrides:
            with self.subTest(override=override):
                self.system.check_override = override
                result = self.service.run(self.request())
                self.assertEqual(result.status, "validation_failed")
                self.assertFalse(result.executed)

    def test_check_exception_and_budget_overrun_block(self):
        self.system.check_override = Mock(side_effect=OSError("check unavailable"))
        self.assertEqual(self.service.run(self.request()).status, "validation_failed")
        def slow(op, req, identity):
            self.now[0] += 6
            return Observation(op, req, True, "late")
        self.system.check_override = slow
        self.assertEqual(self.service.run(self.request()).status, "validation_failed")
        self.assertEqual(self.system.exec_count, 0)

    def test_altered_approved_action_parameters_target_argv_or_checks_rejected(self):
        for mutation in ("action", "parameters", "target", "argv", "checks", "stdin", "postconditions", "timeout"):
            approval = self.service.prepare(self.request("service.status", {"service": "nginx"}))
            self.assertIsInstance(approval, Approval)
            prepared = approval.operation.prepared
            if mutation == "action":
                prepared = replace(prepared, contract=replace(prepared.contract, identifier="service.stop"))
            elif mutation in {"parameters", "target"}:
                prepared = replace(prepared, parameters=replace(prepared.parameters, service="ssh.service"))
            elif mutation == "argv":
                prepared = replace(prepared, argv=("/bin/sh", "-c", "id"))
            elif mutation == "checks":
                prepared = replace(prepared, mandatory_checks=())
            elif mutation == "stdin":
                prepared = replace(prepared, stdin=b"altered")
            elif mutation == "postconditions":
                prepared = replace(prepared, postconditions=())
            else:
                prepared = replace(prepared, contract=replace(prepared.contract, timeout_s=999))
            altered = replace(approval, operation=replace(approval.operation, prepared=prepared))
            with self.subTest(mutation=mutation):
                result = self.service.execute(altered)
                self.assertEqual(result.status, "approval_invalid")
                self.assertEqual(result.operation_id, approval.operation.operation_id)
        self.assertEqual(self.system.exec_count, 0)

    def test_request_mutation_after_validation_does_not_change_execution(self):
        request = self.request("file.create", {"path": "original.txt", "content": "original"})
        approval = self.service.prepare(request)
        request["parameters"]["path"] = "changed.txt"
        request["parameters"]["content"] = "changed"
        result = self.service.execute(approval)
        self.assertEqual(result.status, "succeeded")
        self.assertEqual((Path(self.temp) / "original.txt").read_text(), "original")
        self.assertFalse((Path(self.temp) / "changed.txt").exists())

    def test_replay_expiry_and_forged_tokens_cannot_execute(self):
        approval = self.service.prepare(self.request())
        self.now[0] += 31
        self.assertEqual(self.service.execute(approval).status, "approval_expired")
        self.assertEqual(self.service.execute(approval).status, "approval_invalid")
        self.assertEqual(self.service.execute(replace(approval, token="forged")).status, "approval_invalid")
        self.assertEqual(self.service.execute(replace(approval, token=[])).status, "approval_invalid")
        self.assertEqual(self.system.exec_count, 0)

    def test_successful_approval_is_single_use(self):
        approval = self.service.prepare(self.request())
        self.assertEqual(self.service.execute(approval).status, "succeeded")
        self.assertEqual(self.service.execute(approval).status, "approval_invalid")
        self.assertEqual(self.system.exec_count, 1)

    def test_approval_expiring_during_revalidation_cannot_start_execution(self):
        self.service.ttl = 1.0
        approval = self.service.prepare(self.request())
        def delayed(op, req, identity):
            self.now[0] += 0.5
            return Observation(op, req, True, "observed", "initial")
        self.system.check_override = delayed
        result = self.service.execute(approval)
        self.assertEqual(result.status, "approval_expired")
        self.assertEqual(self.system.exec_count, 0)

    def test_identity_policy_registry_or_required_state_change_requires_revalidation(self):
        for mutation in ("identity", "policy", "registry", "state"):
            service = OperationService(self.registry, self.system, LocalPolicy(1000), self.audit,
                                       clock=lambda: self.now[0])
            approval = service.prepare(self.request("file.create", {"path": "safe.txt"}))
            if mutation == "identity":
                self.system.identity = Identity(2000, 2000, "changed")
            elif mutation == "policy":
                service.policy = LocalPolicy(2000)
            elif mutation == "registry":
                service.registry = ActionRegistry("/srv/changed")
            else:
                self.system.state = "changed"
            with self.subTest(mutation=mutation):
                result = service.execute(approval)
                self.assertIn(result.status, {"identity_denied", "authorization_denied", "approval_invalid", "state_changed"})
                self.assertFalse(result.executed)
            self.system.identity = Identity(1000, 1000, "tester")
            self.system.state = "initial"

    def test_execution_failure_does_not_verify_or_run_generated_recovery(self):
        for error, code in (("timeout", None), ("launch failed", None), ("", 1)):
            self.system.execution_error, self.system.returncode = error, code
            self.system.calls.clear()
            result = self.service.run(self.request())
            self.assertEqual(result.status, "execution_failed")
            self.assertFalse(result.verified)
            self.assertEqual(result.recovery, "unsupported")
            self.assertNotIn("verify", {c[1] for c in self.system.calls})

    def test_failed_postconditions_leave_explicit_reviewable_result(self):
        self.system.corrupt = True
        result = self.service.run(self.request("file.create", {"path": "partial.txt", "content": "expected"}))
        self.assertEqual(result.status, "verification_failed")
        self.assertTrue(result.executed)
        self.assertFalse(result.verified)
        self.assertEqual(result.recovery, "unsupported")
        self.assertEqual((Path(self.temp) / "partial.txt").read_text(), "corrupt")

    def test_incomplete_postcondition_never_succeeds(self):
        self.system.verify = Mock(return_value=None)
        result = self.service.run(self.request())
        self.assertEqual(result.status, "verification_failed")
        self.assertTrue(result.executed)
        self.assertFalse(result.verified)

    def test_adapter_exception_or_wrong_execution_id_reports_unknown_side_effects(self):
        for returned in (None, Execution("wrong-id", (), 0)):
            self.system.execute = Mock(return_value=returned)
            result = self.service.run(self.request())
            self.assertEqual(result.status, "execution_failed")
            self.assertIsNone(result.executed)
        self.system.execute = Mock(side_effect=OSError("adapter interrupted"))
        result = self.service.run(self.request())
        self.assertEqual(result.status, "execution_failed")
        self.assertIsNone(result.executed)
        self.system.execute = lambda op, prepared, identity: Execution(op, prepared.argv, 0, started=False)
        result = self.service.run(self.request())
        self.assertEqual(result.status, "execution_failed")
        self.assertFalse(result.executed or result.verified)

    def test_audit_failure_before_execution_blocks_and_after_execution_reports_side_effects(self):
        self.audit.fail_phase = "execution"
        result = self.service.run(self.request())
        self.assertEqual(result.status, "audit_failed")
        self.assertFalse(result.executed or result.audit_complete)
        self.assertEqual(self.system.exec_count, 0)
        self.audit.fail_phase = "verification"
        result = self.service.run(self.request())
        self.assertEqual(result.status, "audit_failed")
        self.assertTrue(result.executed)
        self.assertFalse(result.audit_complete)

    def test_distinct_operations_have_distinct_correlated_ids(self):
        first, second = self.service.run(self.request()), self.service.run(self.request())
        self.assertNotEqual(first.operation_id, second.operation_id)
        self.assertNotEqual(first.fingerprint, second.fingerprint)
        self.assertEqual({r["operation_id"] for r in self.audit.records}, {first.operation_id, second.operation_id})


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.adapter = LinuxSystemAdapter()
        self.identity = Identity(1000, 1000, "tester")
        self.enterContext(patch.object(self.adapter, "resolve_identity", return_value=self.identity))
        self.enterContext(patch("subprocess.Popen", side_effect=AssertionError("No real process")))
        self.registry = ActionRegistry("/srv/linxai-work")

    def test_runner_uses_exact_array_shell_false_controlled_environment_and_timeout(self):
        prepared = self.registry.prepare("memory.usage")
        def fake_run(argv, **kwargs):
            self.assertEqual(argv, list(prepared.argv))
            self.assertIs(kwargs["shell"], False)
            self.assertEqual(kwargs["input"], prepared.stdin)
            self.assertEqual(kwargs["timeout"], prepared.contract.timeout_s)
            self.assertEqual(kwargs["cwd"], "/")
            self.assertNotIn("PYTHONPATH", kwargs["env"])
            kwargs["stdout"].write(b"controlled output")
            return types.SimpleNamespace(returncode=0)
        with patch("subprocess.run", side_effect=fake_run) as launch:
            result = self.adapter.execute("op", prepared, self.identity)
        launch.assert_called_once()
        self.assertEqual(result.stdout, "controlled output")
        self.assertEqual(result.operation_id, "op")

    def test_runner_reports_timeout_launch_error_and_excess_output(self):
        prepared = self.registry.prepare("memory.usage")
        for error, started in ((subprocess.TimeoutExpired("free", 5), True), (FileNotFoundError("missing"), False)):
            with patch("subprocess.run", side_effect=error):
                result = self.adapter.execute("op", prepared, self.identity)
                self.assertTrue(result.error)
                self.assertEqual(result.started, started)
        def noisy(argv, **kwargs):
            kwargs["stdout"].write(b"x" * (self.adapter.OUTPUT_LIMIT + 1))
            return types.SimpleNamespace(returncode=0)
        with patch("subprocess.run", side_effect=noisy):
            result = self.adapter.execute("op", prepared, self.identity)
        self.assertEqual(result.error, "Output limit exceeded")

    def test_adapter_itself_refuses_admin_or_changed_identity(self):
        with patch("subprocess.run") as launch:
            prepared = self.registry.prepare("service.start", {"service": "nginx"})
            self.assertTrue(self.adapter.execute("op", prepared, self.identity).error)
            prepared = self.registry.prepare("disk.usage")
            self.assertTrue(self.adapter.execute("op", prepared, Identity(2000, 2000, "other")).error)
            launch.assert_not_called()

    def test_unknown_live_check_and_postcondition_fail_closed(self):
        required = requirement("invented")
        self.assertFalse(self.adapter.check("op", required, self.identity).ok)
        prepared = self.registry.prepare("memory.usage")
        execution = Execution("op", prepared.argv, 0)
        self.assertFalse(self.adapter.verify("op", required, prepared, execution, self.identity).ok)

    def test_zero_exit_alone_does_not_prove_observations(self):
        for action in ("disk.usage", "memory.usage", "ports.listen", "service.status"):
            params = {"service": "nginx"} if action.startswith("service") else {}
            prepared = self.registry.prepare(action, params)
            execution = Execution("op", prepared.argv, 0, stdout="malformed")
            required = prepared.postconditions[-1]
            with self.subTest(action=action):
                self.assertFalse(self.adapter.verify("op", required, prepared, execution, self.identity).ok)

    def test_empty_port_inventory_and_inactive_service_are_valid_observations(self):
        prepared = self.registry.prepare("ports.listen")
        self.assertTrue(self.adapter.verify("op", prepared.postconditions[-1], prepared,
                                           Execution("op", prepared.argv, 0), self.identity).ok)
        prepared = self.registry.prepare("service.status", {"service": "nginx"})
        text = "Id=nginx.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\n"
        self.assertTrue(self.adapter.verify("op", prepared.postconditions[-1], prepared,
                                           Execution("op", prepared.argv, 0, text), self.identity).ok)

    def test_port_filter_and_service_target_must_match_result(self):
        prepared = self.registry.prepare("ports.listen", {"port": 80})
        wrong = Execution("op", prepared.argv, 0, "LISTEN 0 16 127.0.0.1:81 0.0.0.0:*\n")
        self.assertFalse(self.adapter.verify("op", prepared.postconditions[-1], prepared, wrong, self.identity).ok)
        prepared = self.registry.prepare("service.status", {"service": "nginx"})
        wrong = Execution("op", prepared.argv, 0, "Id=ssh.service\nLoadState=loaded\nActiveState=active\nSubState=running\n")
        self.assertFalse(self.adapter.verify("op", prepared.postconditions[-1], prepared, wrong, self.identity).ok)


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).with_name("main.py")
        spec = importlib.util.spec_from_file_location("linxai_operations_cli_test", path)
        cls.legacy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.legacy)

    def test_main_routes_operation_before_constructing_legacy_pipeline(self):
        with patch.object(self.legacy, "LINxAIPipeline", side_effect=AssertionError("Legacy fallback forbidden")), patch("operations.cli.run_request", return_value=2) as run:
            result = self.legacy.main(["--operation", "service.start", "--operation-params", '{"service":"nginx"}'])
        self.assertEqual(result, 2)
        run.assert_called_once_with("service.start", '{"service":"nginx"}', None, None)

    def test_cli_calls_same_service_and_prints_correlated_json(self):
        with tempfile.TemporaryDirectory() as directory:
            system, audit = IsolatedSystem(directory), MemoryAudit()
            service = OperationService(ActionRegistry(), system, LocalPolicy(1000), audit)
            output = io.StringIO()
            with patch("sys.stdout", output):
                code = run_request("memory.usage", service_factory=lambda *args: service)
            result = json.loads(output.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(result["operation_id"], audit.records[-1]["operation_id"])

    def test_cli_errors_are_explicit_and_never_fall_back(self):
        for parameters in ("", "not JSON", '"text"', '{"command":"id"}', '{"port":80,"port":81}'):
            with tempfile.TemporaryDirectory() as directory:
                system = IsolatedSystem(directory)
                service = OperationService(ActionRegistry(), system, LocalPolicy(1000), MemoryAudit())
                output = io.StringIO()
                with patch("sys.stdout", output):
                    code = run_request("disk.usage", parameters, service_factory=lambda *args: service)
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(output.getvalue())["status"], "invalid_request")
                self.assertEqual(system.exec_count, 0)

    def test_empty_explicit_parameters_are_not_replaced_with_defaults(self):
        with patch("operations.cli.run_request", return_value=2) as run:
            self.legacy.main(["--operation", "disk.usage", "--operation-params", ""])
        self.assertEqual(run.call_args.args[1], "")

    def test_conflicting_cli_modes_are_rejected(self):
        with patch("sys.stderr", io.StringIO()):
            for args in (["--operation", "disk.usage", "--command", "df"],
                         ["--operation", "disk.usage", "--daemon"],
                         ["--operations-workspace", "/srv/work"]):
                with self.subTest(args=args), self.assertRaises(SystemExit):
                    self.legacy.parse_args(args)

    def test_root_legacy_startup_is_rejected_before_pipeline(self):
        with patch.object(self.legacy.sys, "platform", "linux"), patch.object(self.legacy.os, "getuid", return_value=0, create=True), patch.object(self.legacy.os, "geteuid", return_value=0, create=True), patch.object(self.legacy, "LINxAIPipeline") as pipeline, patch("sys.stderr", io.StringIO()):
            self.assertEqual(self.legacy.main([]), 2)
            pipeline.assert_not_called()


class AuditAdapterTests(unittest.TestCase):
    def audit_environment(self, directory, *, unsafe=False):
        # Simulate POSIX ownership/mode metadata while writing only Windows temp files.
        parent = Path(directory)
        real_stat, real_lstat, real_fstat = Path.stat, Path.lstat, os.fstat
        def metadata(info, private=False):
            return types.SimpleNamespace(st_mode=(0o40777 if unsafe else 0o40700 if private else 0o40755),
                                         st_uid=1000 if private else 0)
        self.enterContext(patch.object(Path, "stat", lambda path, **kw: metadata(real_stat(path, **kw), path == parent)))
        self.enterContext(patch.object(Path, "lstat", lambda path: metadata(real_lstat(path), path == parent)))
        self.enterContext(patch.object(os, "getuid", return_value=1000, create=True))
        self.enterContext(patch.object(os, "geteuid", return_value=1000, create=True))
        self.enterContext(patch.object(os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0), create=True))
        self.enterContext(patch.object(os, "O_CLOEXEC", getattr(os, "O_CLOEXEC", 0), create=True))
        def file_stat(fd):
            real_fstat(fd)
            return types.SimpleNamespace(st_mode=0o100600, st_uid=1000, st_nlink=1)
        self.enterContext(patch.object(os, "fstat", side_effect=file_stat))
        locks = types.SimpleNamespace(flock=Mock(), LOCK_EX=2)
        self.enterContext(patch.dict("sys.modules", {"fcntl": locks}))
        return locks

    def test_private_jsonl_round_trip_in_temporary_file(self):
        directory = tempfile.TemporaryDirectory()
        try:
            with self.subTest("mocked POSIX metadata"):
                locks = self.audit_environment(directory.name)
                path = Path(directory.name) / "operations.jsonl"
                ledger = JsonlAudit(path)
                ledger.append({"operation_id": "same-id", "phase": "validation"})
                ledger.append({"operation_id": "same-id", "phase": "result"})
                records = [json.loads(line) for line in path.read_text().splitlines()]
                self.assertEqual([r["operation_id"] for r in records], ["same-id", "same-id"])
                self.assertEqual(locks.flock.call_count, 2)
        finally:
            # Exit mocks before TemporaryDirectory performs native cleanup.
            self.doCleanups()
            directory.cleanup()

    def test_unsafe_audit_directory_is_rejected_without_opening_log(self):
        directory = tempfile.TemporaryDirectory()
        try:
            self.audit_environment(directory.name, unsafe=True)
            with patch("operations.audit.os.open") as opened, self.assertRaises(PermissionError):
                JsonlAudit(Path(directory.name) / "audit.jsonl").append({"operation_id": "denied"})
            opened.assert_not_called()
        finally:
            self.doCleanups()
            directory.cleanup()

if __name__ == "__main__":
    unittest.main()
