"""Requirement 5: planning runs as an explicit, bounded state graph."""
import sys
import types
import unittest
from unittest.mock import Mock, patch

from ai import workflow
from ai.local_planner import Planner
from operations.registry import ActionRegistry


class FakeStateGraph:
    """Minimal stand-in exercising the same StateGraph calls LINxAI makes."""
    def __init__(self, schema): self.nodes, self.routes, self.entry = {}, {}, None
    def add_node(self, name, fn): self.nodes[name] = fn
    def set_entry_point(self, name): self.entry = name
    def add_conditional_edges(self, name, route, mapping): self.routes[name] = (route, mapping)
    def compile(self):
        graph = self
        class App:
            def invoke(self, state, config):
                node, steps = graph.entry, 0
                while node != "END" and steps < config["recursion_limit"]:
                    update = graph.nodes[node](state)
                    state = {**state, **update, "trace": state["trace"] + update.get("trace", [])}
                    route, mapping = graph.routes[node]
                    node, steps = mapping[route(state)], steps + 1
                return state
        return App()


class WorkflowGraphTests(unittest.TestCase):
    def setUp(self):
        self.model = Mock()
        self.planner = Planner(ActionRegistry("/workspace", actor_uid=1000), self.model)

    def test_fast_path_trace_and_typed_result(self):
        request, plan = self.planner.propose("show memory usage")
        self.assertEqual(request["action"], "memory.usage")
        self.assertEqual(plan["workflow"]["trace"], ["normalize", "deterministic", "classify_fast", "validate", "adapt"])
        self.model.generate.assert_not_called()

    def test_deterministic_route_stops_early(self):
        _, plan = self.planner.propose("show top processes")
        self.assertEqual(plan["workflow"]["trace"], ["normalize", "deterministic"])

    def test_model_route_is_still_validated_and_adapted(self):
        from ai.fast_path import classify_fast
        self.model.generate.return_value = classify_fast("show memory usage")   # a schema-valid plan
        with patch("ai.workflow.classify_fast", return_value=None):
            request, plan = self.planner.propose("how much ram is free right now please")
        self.assertEqual(request["action"], "memory.usage")
        self.assertEqual(plan["workflow"]["trace"], ["normalize", "deterministic", "classify_fast", "model", "validate", "adapt"])
        self.model.generate.return_value = {"intent": "unsupported_root_shell", "command": "rm -rf /", "risk": "low",
                                            "requires_sudo": False}
        with patch("ai.workflow.classify_fast", return_value=None), self.assertRaises(Exception):
            self.planner.propose("do something dangerous")

    def test_step_bound_stops_runaway_graphs(self):
        looping = {**workflow.EDGES, "validate": lambda s: "validate"}
        with patch.object(workflow, "EDGES", looping), patch.object(workflow, "engine", return_value="builtin"), \
                patch("ai.workflow.classify_fast", return_value={"intent": "x"}), \
                patch("ai.workflow.validate_plan", side_effect=lambda p: p), self.assertRaises(RuntimeError):
            self.planner.propose("show memory usage")

    def test_langgraph_adapter_wiring_matches_builtin(self):
        fake = types.ModuleType("langgraph"); graph = types.ModuleType("langgraph.graph")
        graph.StateGraph, graph.END = FakeStateGraph, "END"
        with patch.dict(sys.modules, {"langgraph": fake, "langgraph.graph": graph}):
            self.assertEqual(workflow.engine(), "langgraph")
            request, plan = self.planner.propose("show memory usage")
        self.assertEqual(plan["workflow"]["engine"], "langgraph")
        self.assertEqual(request["action"], "memory.usage")
        self.assertEqual(plan["workflow"]["trace"], ["normalize", "deterministic", "classify_fast", "validate", "adapt"])


    def test_account_and_privilege_changes_refused_before_model(self):
        # Intent evaluation (req 3) found the 1.5B model mapping "add user ... to sudoers"
        # onto service.start sudo.service; such requests must never reach the model.
        from operations.registry import UnsupportedAction
        for text in ("add user mallory to sudoers", "give me root access", "change the passwd of bob"):
            with self.assertRaises(UnsupportedAction):
                self.planner.propose(text)
        self.model.generate.assert_not_called()

    def test_destructive_refused_and_status_questions_are_deterministic(self):
        from operations.registry import UnsupportedAction
        for text in ("format the disk", "rm -rf / please", "mkfs.ext4 /dev/sda1"):
            with self.assertRaises(UnsupportedAction):
                self.planner.propose(text)
        request, plan = self.planner.propose("is docker up?")
        self.assertEqual(request, {"action": "service.status", "parameters": {"service": "docker.service", "port_free": None, "port_occupied": None}}
                         if "port_free" in request["parameters"] else {"action": "service.status", "parameters": {"service": "docker.service"}})
        self.assertEqual(plan["workflow"]["trace"], ["normalize", "deterministic"])
        self.model.generate.assert_not_called()

    def test_model_resource_intents_map_to_read_only_actions(self):
        from operations.plans import adapt_plan
        registry = ActionRegistry("/workspace", actor_uid=1000)
        for intent, action in (("cpu_usage", "process.list"), ("process_list", "process.list"),
                               ("resource_forecast", "resource.forecast")):
            prepared = adapt_plan({"intent": intent, "target": "", "command": "top -b -n1"}, registry)
            self.assertEqual(prepared.contract.identifier, action)


if __name__ == "__main__":
    unittest.main()
