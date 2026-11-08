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


if __name__ == "__main__":
    unittest.main()
