"""Offline regressions. No real commands, network calls, services or signals."""
import importlib
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch

from ai.plan_schema import SUPPORTED_INTENTS, validate_plan
from ai.fast_path import classify_fast
from ai.prompts import SYSTEM_PROMPT
from cie.validator import CHECK_REGISTRY, CommandIntelligenceEngine, _run_single_check
from executor.controller import ExecutionController
from executor.result import ExecutionResult


def plan(**updates):
    value = {"intent": "service_restart", "target": "nginx",
             "command": "systemctl restart nginx", "pre_conditions": [],
             "requires_sudo": True, "risk_level": "medium", "rollback": ""}
    value.update(updates)
    return value


def check_result(status="ok"):
    return {"check": "sample", "status": status, "reason": "test evidence",
            "found": None, "detail": {}}


class OfflineTest(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch("subprocess.Popen", side_effect=AssertionError("Real subprocess forbidden in offline tests")))
        self.enterContext(patch("subprocess.run", side_effect=AssertionError("Real subprocess forbidden in offline tests")))
        self.enterContext(patch("socket.create_connection", side_effect=AssertionError("Network forbidden in offline tests")))


class PlanSchemaTests(OfflineTest):
    def test_defaults_and_original_are_separate(self):
        original = {"intent": "unknown", "target": "", "command": ""}
        result = validate_plan(original)
        self.assertEqual(result["pre_conditions"], [])
        self.assertNotIn("pre_conditions", original)

    def test_prompt_and_supported_intents_match(self):
        text = SYSTEM_PROMPT.split("INTENT LIST (use EXACTLY these strings):", 1)[1].split("RETURN THIS JSON", 1)[0]
        self.assertEqual(set(text.replace(",", " ").split()), SUPPORTED_INTENTS)

    def test_invalid_top_level_rejected(self):
        for value in (None, [], "plan", 3):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_plan(value)

    def test_missing_required_fields_rejected(self):
        for key in ("intent", "target", "command"):
            candidate = plan()
            del candidate[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_plan(candidate)

    def test_malformed_fields_rejected(self):
        bad = [("intent", 1), ("intent", "invented_action"), ("target", []),
               ("command", []), ("command", "echo\x00bad"),
               ("requires_sudo", "false"), ("requires_sudo", 1),
               ("risk_level", "critical"), ("rollback", []),
               ("pre_conditions", "port_free"), ("pre_conditions", ["port_free"]),
               ("pre_conditions", [{}]), ("pre_conditions", [{"check": []}]),
               ("pre_conditions", [{"check": ""}]), ("content", []),
               ("command", "x" * 32769)]
        for key, value in bad:
            with self.subTest(key=key, value=str(value)[:40]), self.assertRaises(ValueError):
                validate_plan(plan(**{key: value}))

    def test_invalid_ports_rejected(self):
        for value in (True, 0, -1, 65536, "65536", "80;id", [], None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_plan(plan(port=value))

    def test_valid_port_normalized(self):
        self.assertEqual(validate_plan(plan(port=80))["port"], "80")
        self.assertEqual(validate_plan(plan(port="65535"))["port"], "65535")

    def test_conditions_are_copied(self):
        original = plan(pre_conditions=[{"check": "port_free", "port": 80}])
        result = validate_plan(original)
        result["pre_conditions"][0]["port"] = 81
        self.assertEqual(original["pre_conditions"][0]["port"], 80)

    def test_too_many_conditions_rejected(self):
        with self.assertRaises(ValueError):
            validate_plan(plan(pre_conditions=[{"check": "port_free"}] * 65))

    def test_documented_prompt_examples_remain_valid(self):
        import json
        examples = [line for line in SYSTEM_PROMPT.splitlines() if line.startswith('{"intent":') and '<intent>' not in line]
        self.assertGreater(len(examples), 20)
        for line in examples:
            with self.subTest(example=line[:70]):
                validate_plan(json.loads(line))


class ValidationTests(OfflineTest):
    def test_missing_checks_registered(self):
        self.assertIn("port_range", CHECK_REGISTRY)
        self.assertIn("process_count", CHECK_REGISTRY)

    def test_unknown_check_blocks(self):
        result = CommandIntelligenceEngine().validate(plan(pre_conditions=[{"check": "misspelled"}]))
        self.assertEqual(result["decision"], "block")
        self.assertEqual(result["results"][0]["status"], "error")

    def test_bad_conditions_block(self):
        for value in ("port_free", None, [None], [{}], [{"check": []}]):
            with self.subTest(value=value):
                result = CommandIntelligenceEngine().validate(plan(pre_conditions=value))
                self.assertEqual(result["decision"], "block")

    def test_bad_plan_blocks(self):
        for value in (None, [], {}, {"command": []}):
            with self.subTest(value=value):
                self.assertEqual(CommandIntelligenceEngine().validate(value)["decision"], "block")

    def test_check_exception_blocks(self):
        with patch.dict(CHECK_REGISTRY, {"test": Mock(side_effect=OSError("unavailable"))}):
            result = CommandIntelligenceEngine().validate(plan(pre_conditions=[{"check": "test"}]))
        self.assertEqual(result["decision"], "block")

    def test_bad_check_results_block(self):
        for output in (None, [], {}, {"status": "maybe", "reason": "x"}, {"status": "ok", "reason": []}):
            with self.subTest(output=output), patch.dict(CHECK_REGISTRY, {"test": Mock(return_value=output)}):
                self.assertEqual(CommandIntelligenceEngine().validate(plan(pre_conditions=[{"check": "test"}]))["decision"], "block")

    def test_error_status_blocks(self):
        with patch.dict(CHECK_REGISTRY, {"test": Mock(return_value=check_result("error"))}):
            self.assertEqual(CommandIntelligenceEngine().validate(plan(pre_conditions=[{"check": "test"}]))["decision"], "block")

    def test_expired_budget_runs_no_declared_checks(self):
        function = Mock(return_value=check_result())
        with patch.dict(CHECK_REGISTRY, {"test": function}):
            result = CommandIntelligenceEngine(timeout_ms=0).validate(plan(pre_conditions=[{"check": "test"}]))
        function.assert_not_called()
        self.assertEqual(result["checks_run"], 0)
        self.assertEqual(result["decision"], "block")

    def test_final_check_overrun_blocks(self):
        clock = [10.0]
        def slow():
            clock[0] += 1.0
            return check_result()
        with patch("cie.validator.time.perf_counter", side_effect=lambda: clock[0]), patch.dict(CHECK_REGISTRY, {"test": slow}):
            result = CommandIntelligenceEngine().validate(plan(pre_conditions=[{"check": "test"}]))
        self.assertEqual(result["checks_run"], 1)
        self.assertEqual(result["decision"], "block")

    def test_overrun_skips_remaining_check_and_blocks(self):
        clock = [10.0]
        second = Mock(return_value=check_result("conflict"))
        def slow():
            clock[0] += 1.0
            return check_result()
        with patch("cie.validator.time.perf_counter", side_effect=lambda: clock[0]), patch.dict(CHECK_REGISTRY, {"slow": slow, "second": second}):
            result = CommandIntelligenceEngine().validate(plan(pre_conditions=[{"check": "slow"}, {"check": "second"}]))
        second.assert_not_called()
        self.assertEqual(result["decision"], "block")

    def test_successful_checks_approve(self):
        with patch.dict(CHECK_REGISTRY, {"test": Mock(return_value=check_result())}):
            self.assertEqual(CommandIntelligenceEngine().validate(plan(pre_conditions=[{"check": "test"}]))["decision"], "approve")

    def test_conflict_blocks(self):
        with patch.dict(CHECK_REGISTRY, {"test": Mock(return_value=check_result("conflict"))}):
            self.assertEqual(CommandIntelligenceEngine().validate(plan(pre_conditions=[{"check": "test"}]))["decision"], "block")

    def test_advisory_warning_preserved(self):
        with patch.dict(CHECK_REGISTRY, {"test": Mock(return_value=check_result("warning"))}):
            self.assertEqual(CommandIntelligenceEngine().validate(plan(pre_conditions=[{"check": "test"}]))["decision"], "warn")

    def test_read_only_request_with_no_checks_still_approves(self):
        self.assertEqual(CommandIntelligenceEngine().validate(plan(intent="disk_usage", command="df -h", requires_sudo=False))["decision"], "approve")

    def test_protected_path_still_blocked(self):
        result = CommandIntelligenceEngine().validate(plan(intent="file_delete", command="rm -rf /etc"))
        self.assertEqual(result["decision"], "block")

    def test_empty_required_results_do_not_approve(self):
        self.assertEqual(CommandIntelligenceEngine()._decide([], plan())[0], "block")


class ConditionalRequestTests(OfflineTest):
    def test_conditional_restart_preserves_action_and_condition(self):
        for phrase in ("restart nginx only if port 80 is free", "restart nginx only if port 80 is not currently in use"):
            with self.subTest(phrase=phrase):
                result = classify_fast(phrase)
                self.assertEqual(result["intent"], "service_restart")
                self.assertEqual(result["command"], "systemctl restart nginx")
                self.assertEqual(result["port"], "")
                self.assertIn({"check": "port_free", "port": 80}, result["pre_conditions"])

    def test_conditional_stop_preserves_occupied_check(self):
        result = classify_fast("stop nginx if port 80 is occupied")
        self.assertEqual(result["intent"], "service_stop")
        self.assertIn({"check": "port_occupied", "port": 80}, result["pre_conditions"])

    def test_unsupported_compositions_not_reduced_to_port_query(self):
        for phrase in ("restart nginx unless port 80 is occupied", "restart nginx only if port 80 is free and disk is healthy", "check port 80 then stop nginx", "do something with port 80"):
            with self.subTest(phrase=phrase):
                self.assertIsNone(classify_fast(phrase))

    def test_direct_port_queries_preserved(self):
        for phrase in ("port 80", "check port 80", "what is running on port 80", "80"):
            with self.subTest(phrase=phrase):
                self.assertEqual(classify_fast(phrase)["intent"], "port_check")

    def test_explicit_listener_request_preserved(self):
        result = classify_fast("start nginx on port 5555")
        self.assertEqual(result["intent"], "service_start")
        self.assertEqual(result["port"], "5555")

    def test_conditional_service_alias_matches_check(self):
        result = classify_fast("restart apache.service only if port 80 is free")
        self.assertEqual(result["target"], "apache2")
        self.assertIn({"check": "service_exists", "service": "apache2"}, result["pre_conditions"])

    def test_condition_conflict_never_reaches_executor(self):
        operation = classify_fast("restart nginx only if port 80 is free")
        executor = Mock()
        with patch.dict(CHECK_REGISTRY, {"service_exists": Mock(return_value=check_result()), "port_free": Mock(return_value=check_result("conflict"))}):
            validation = CommandIntelligenceEngine().validate(operation)
        if validation["decision"] == "approve":
            executor.execute(operation)
        executor.execute.assert_not_called()
        self.assertEqual(validation["decision"], "block")


class EngineTests(OfflineTest):
    def setUp(self):
        super().setUp()
        requests = types.ModuleType("requests")
        requests.post = Mock(side_effect=AssertionError("Model calls forbidden in this unit test"))
        requests.RequestException = RuntimeError
        self.requests = requests
        self.enterContext(patch.dict(sys.modules, {"requests": requests}))
        sys.modules.pop("ai.engine", None)
        self.engine_class = importlib.import_module("ai.engine").AIEngine
        self.engine = self.engine_class.__new__(self.engine_class)
        self.engine.cache = None

    def test_engine_routes_supported_condition_without_model(self):
        result = self.engine.classify("restart nginx only if port 80 is free")
        self.assertEqual(result["intent"], "service_restart")
        self.requests.post.assert_not_called()

    def test_unsupported_condition_ignores_stale_cache(self):
        self.engine.cache = Mock()
        self.engine.cache.get.return_value = plan(intent="port_check", target="80", command="ss -tlnp")
        result = self.engine.classify("restart nginx unless port 80 is occupied")
        self.assertEqual(result["intent"], "unknown")
        self.assertEqual(result["command"], "")
        self.engine.cache.get.assert_not_called()

    def test_valid_cached_plan_normalized(self):
        self.engine.cache = Mock()
        self.engine.cache.get.return_value = {"intent": "service_status", "target": "nginx", "command": "systemctl status nginx"}
        result = self.engine.classify("please inspect the web server health")
        self.assertIs(result["requires_sudo"], False)
        self.assertEqual(result["pre_conditions"], [])

    def test_bad_cached_plan_does_not_escape_validation(self):
        self.engine.cache = Mock()
        self.engine.cache.get.return_value = plan(command=[])
        self.engine.model = "unit-test"
        self.engine.host = "http://unused"
        self.engine.timeout = 1
        good = plan(intent="service_status", command="systemctl status nginx", requires_sudo=False)
        import json
        response = Mock()
        response.json.return_value = {"message": {"content": json.dumps(good)}}
        self.requests.post.side_effect = None
        self.requests.post.return_value = response
        result = self.engine.classify("inspect the web service please")
        self.assertIsInstance(result["command"], str)
        self.requests.post.assert_called_once()


class ExecutionTests(OfflineTest):
    def test_generated_rollback_never_starts_process(self):
        controller = ExecutionController(use_face_auth=False)
        result = controller._execute_rollback(plan(rollback="rm -rf /etc"))
        self.assertFalse(result["executed"])
        self.assertEqual(result["status"], "requires_review")

    def test_failure_reports_rollback_not_executed(self):
        controller = ExecutionController(use_face_auth=False)
        failed = ExecutionResult("error", 1, "", "operation failed", "systemctl restart nginx", "service_restart", 0)
        with patch.object(controller, "_run_subprocess", return_value=failed):
            result = controller.execute(plan(requires_sudo=False, rollback="systemctl stop nginx"))
        self.assertIn("Automatic rollback was not run", result.stderr)

    def test_subprocess_uses_thread_safe_session_option(self):
        controller = ExecutionController(use_face_auth=False)
        with patch('executor.controller.os.setsid', new=lambda: None, create=True), patch('executor.controller.subprocess.Popen', side_effect=OSError('simulated launch failure')) as launch:
            controller._run_subprocess('true', 'system_info', plan(), 'none', 1)
        launch.assert_called_once()
        self.assertTrue(launch.call_args.kwargs['start_new_session'])
        self.assertNotIn('preexec_fn', launch.call_args.kwargs)


class PipelineGateTests(OfflineTest):
    def test_retry_cannot_execute_with_missing_or_invalid_decision(self):
        controller_path = Path(sys.modules['executor.controller'].__file__)
        spec = importlib.util.spec_from_file_location('linxai_legacy_test', controller_path.parent.parent/'main.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for validation in ({}, {'decision': 'unexpected', 'reason': 'invalid'}, {'result': 'missing'}):
            with self.subTest(validation=validation):
                pipeline = module.LINxAIPipeline.__new__(module.LINxAIPipeline)
                pipeline.cie = Mock()
                pipeline.cie.validate.return_value = validation
                pipeline.hub = Mock()
                pipeline.memory = Mock()
                pipeline.executor = Mock()
                with patch('builtins.print'):
                    pipeline._run_suggested_command(plan(), 'systemctl restart nginx')
                pipeline.executor.execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
