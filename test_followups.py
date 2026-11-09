"""Requirement 8: context-aware follow-up commands resolve to ordinary typed previews."""
import unittest
from unittest.mock import Mock

from ai.local_planner import Planner, follow_up
from operations.jobs import Jobs
from operations.registry import ActionRegistry, Privilege
from test_application import MemoryStore


def turn(action, **parameters):
    return {"text": "earlier", "plan": {}, "request": {"action": action, "parameters": parameters}}


class FollowUpTests(unittest.TestCase):
    def setUp(self):
        self.model = Mock()
        self.planner = Planner(ActionRegistry("/workspace", actor_uid=1000), self.model)

    def test_pronoun_service_verbs_reuse_the_last_service(self):
        context = [turn("memory.usage"), turn("service.status", service="nginx.service")]
        request, plan = self.planner.propose("restart it", context)
        self.assertEqual(request, {"action": "service.restart", "parameters": {"service": "nginx.service"}})
        self.assertEqual(plan["intent"], "follow_up")
        self.assertEqual(self.planner.propose("is it running?", context)[0]["action"], "service.status")
        self.model.generate.assert_not_called()

    def test_same_for_replaces_only_the_target_field(self):
        self.assertEqual(follow_up("do the same for apache2", [turn("service.status", service="nginx.service")]),
                         {"action": "service.status", "parameters": {"service": "apache2.service"}})
        self.assertEqual(follow_up("now for 8080", [turn("ports.listen", port=80, protocol="tcp")]),
                         {"action": "ports.listen", "parameters": {"port": 8080, "protocol": "tcp"}})

    def test_repeat_and_latest_turn_wins(self):
        context = [turn("disk.usage"), turn("memory.usage")]
        self.assertEqual(follow_up("do it again", context), {"action": "memory.usage", "parameters": {}})

    def test_no_context_or_unrelated_text_falls_through(self):
        self.assertIsNone(follow_up("restart it", []))
        self.assertIsNone(follow_up("restart it", [turn("memory.usage")]))      # no service to refer to
        self.assertIsNone(follow_up("show disk usage", [turn("memory.usage")]))
        self.assertIsNone(follow_up("restart it", [{"text": "x", "plan": {}}]))  # legacy rows without request

    def test_follow_up_never_carries_authority_and_is_revalidated(self):
        context = [turn("service.status", service="nginx.service")]
        request, _ = self.planner.propose("restart it", context)
        jobs = Jobs(MemoryStore(), ActionRegistry("/workspace", actor_uid=1000), 1000, Mock(), Mock(), clock=lambda: 1.0)
        row = jobs.preview(request)
        self.assertEqual(row["privilege"], Privilege.AUTHENTICATED_ADMIN.value)     # still broker + OS auth
        with self.assertRaises(Exception):
            self.planner.propose("do the same for ../../etc", [turn("service.status", service="nginx.service")])
        with self.assertRaises(Exception):
            self.planner.propose("now for 99999", [turn("ports.listen", port=80, protocol="tcp")])

    def test_multi_turn_dialogue_corpus(self):
        # Requirements 7/8: context accumulates turn by turn exactly as the agent stores it;
        # every turn is deterministic (the model is never reached) and every result is typed.
        self.model.generate.side_effect = AssertionError("model must not be needed")
        svc = lambda action, name: {"action": action, "parameters": {"service": name + ".service"}}
        dialogues = [
            [("is nginx running", svc("service.status", "nginx")), ("restart it", svc("service.restart", "nginx")),
             ("is it running?", svc("service.status", "nginx")), ("do the same for redis", svc("service.status", "redis")),
             ("stop it", svc("service.stop", "redis")), ("start it again", svc("service.start", "redis"))],
            [("is docker up?", svc("service.status", "docker")), ("show memory usage", {"action": "memory.usage", "parameters": {}}),
             ("restart it", svc("service.restart", "docker")), ("do it again", svc("service.restart", "docker"))],
            [("restart nginx", None), ("now for apache2", None), ("check it", None)],
            [("show top processes", {"action": "process.list", "parameters": {}}), ("restart it", "refused")],
        ]
        dialogues[2] = [("restart nginx", "service.restart"), ("now for apache2", svc("service.restart", "apache2")),
                        ("check it", svc("service.status", "apache2"))]
        for dialogue in dialogues:
            context = []
            for text, expected in dialogue:
                if expected == "refused":
                    with self.assertRaises(Exception, msg=text):
                        self.planner.propose(text, context)
                    continue
                request, plan = self.planner.propose(text, context)
                if isinstance(expected, str):
                    self.assertEqual(request["action"], expected, text)
                else:
                    got = {"action": request["action"], "parameters": {k: request["parameters"][k] for k in expected["parameters"]}}
                    self.assertEqual(got, expected, text)
                context.append({"text": text, "plan": plan, "request": request})


if __name__ == "__main__":
    unittest.main()
