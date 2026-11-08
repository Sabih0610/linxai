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
                         {"action": "service.status", "parameters": {"service": "apache2"}})
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


if __name__ == "__main__":
    unittest.main()
