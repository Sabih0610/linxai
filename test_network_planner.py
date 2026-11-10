"""Chat -> network features, grounded in a device's gold capability profile (srl1 lab evidence)."""
import json
import os
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock

from ai.network_planner import NetworkPlanner
from operations import netconf_features as nf
from operations.registry import ActionRegistry, UnsupportedAction

GOLD = json.loads((Path(__file__).parent / "docs/evidence/discovery-2026-11-10/gold-srl1.json").read_text())
ASSET = {"platform": "netconf", "host": "127.0.0.1", "port": 2830, "username": "admin", "key_path": "/home/o/.ssh/k",
         "host_key_sha256": "SHA256:" + "A" * 43, "state_dir": "/home/o/.linxai/nc", "ports": ["ethernet-1/1", "ethernet-1/2"],
         "features": sorted(nf.FEATURES)}


class NetworkPlannerTests(unittest.TestCase):
    def planner(self, model=None, gold=GOLD):
        registry = ActionRegistry("/srv/work", actor_uid=1000,
                                  assets_json=json.dumps({"srl1": ASSET, "srl2": dict(ASSET, port=2831), "web": {"platform": "linux_agentless"}}))
        return NetworkPlanner(registry, lambda name: gold if name == "srl1" else None, model)

    def test_fixed_patterns_map_to_typed_changes_with_profile_evidence(self):
        cases = {"set the hostname of srl1 to lab-1": ("system.hostname", {"hostname": "lab-1"}),
                 "on srl1 set description of ethernet-1/1 to uplink to core": ("interface.description", {"interface": "ethernet-1/1", "description": "uplink to core"}),
                 "add a dns server 192.0.2.53 on srl1": ("system.dns_server", {"address": "192.0.2.53"}),
                 "srl1: add static route to 203.0.113.0/24 via 198.51.100.2": ("static_route", {"prefix": "203.0.113.0/24", "next_hop": "198.51.100.2"}),
                 "assign 198.51.100.1/30 to ethernet-1/1 on srl1": ("interface.ipv4", {"interface": "ethernet-1/1", "address": "198.51.100.1", "prefix_length": 30})}
        for text, (feature, settings) in cases.items():
            kind, base, plan = self.planner().plan(text)
            self.assertEqual((kind, base), ("change", {"asset": "srl1", "feature": feature, "settings": settings}), text)
            self.assertIn("committed and restored", plan["workflow"])          # strongest evidence surfaced to the owner

    def test_profile_gates_unsupported_and_warned_features(self):
        with self.assertRaisesRegex(UnsupportedAction, "cannot do vlan: vendor deviation"):
            self.planner().plan("create vlan 100 on srl1")
        with self.assertRaisesRegex(UnsupportedAction, "never completed a restore cycle"):
            self.planner().plan("add ntp server 192.0.2.1 on srl1")

    def test_capability_question_is_answered_from_gold_only(self):
        kind, answer = self.planner().plan("what can srl1 do?")
        self.assertEqual(kind, "answer")
        self.assertTrue(answer["answer"])
        self.assertEqual(answer["identity"]["model"], "7220 IXR-D3L")
        self.assertIn("system.hostname", answer["proven"])
        self.assertIn("vlan", answer["unsupported"])
        self.assertIn("system.ntp_server", answer["not_offered"])
        self.assertEqual(answer["management_interfaces"], ["mgmt0"])

    def test_scope_rules(self):
        self.assertIsNone(self.planner().plan("show memory usage"))              # not a network request
        self.assertIsNone(self.planner().plan("restart web"))                    # not a NETCONF device
        with self.assertRaisesRegex(UnsupportedAction, "discover it first"):
            self.planner().plan("set hostname of srl2 to x")                     # no gold profile yet
        with self.assertRaisesRegex(UnsupportedAction, "one network device"):
            self.planner().plan("set hostname of srl1 and srl2 to x")

    def test_model_slot_filling_is_bounded_to_the_profile(self):
        model = Mock()
        model.complete.side_effect = [{"vni": "200"}]             # one keyword candidate: the model only fills settings
        kind, base, plan = self.planner(model).plan("give srl1 a bridged vxlan for vni 200")
        self.assertEqual(base, {"asset": "srl1", "feature": "srl.vxlan_interface", "settings": {"vni": 200}})   # digits typed by the example
        self.assertEqual(plan["workflow"].split(";")[0], "local model slot-filling")
        self.assertIn("ethernet-1/1", model.complete.call_args[0][0])
        # A tie between keyword candidates is broken by the model, choosing only among the tied features.
        model.complete.side_effect = [{"feature": "qos.queue"}]
        with self.assertRaises(UnsupportedAction):
            self.planner(model).plan("on srl1 drop the bgp peer 198.51.100.2")
        choose = model.complete.call_args[0][0]
        self.assertIn("acl.entry", choose)
        self.assertIn("bgp.neighbor", choose)
        self.assertNotIn("qos.queue", choose)                     # warned/unsupported features are never offered
        self.assertNotIn("- vlan:", choose)
        model.reset_mock()
        with self.assertRaises(UnsupportedAction):                # nothing points at a usable feature: no model call at all
            self.planner(model).plan("give srl1 something clever")
        model.complete.assert_not_called()
        text = "give srl1 a vxlan for vni 200"
        for answers in ([{"vni": 200, "cmd": "x"}], [{"vni": 999}], ["not json"]):   # extra key, invented value, malformed
            model.complete.side_effect = answers
            with self.assertRaises(UnsupportedAction, msg=answers):
                self.planner(model).plan(text)
        model.complete.side_effect = OSError("down")
        with self.assertRaisesRegex(UnsupportedAction, "model unavailable"):
            self.planner(model).plan(text)

    def test_model_output_is_schema_constrained_with_a_worked_example(self):
        model = Mock()
        model.complete.side_effect = [{"feature": "acl.entry"}, {"action": "drop", "destination": "198.51.100.0/24"}]
        kind, base, _ = self.planner(model).plan("on srl1 drop the bgp traffic to 198.51.100.0/24")
        self.assertEqual(base["settings"], {"action": "drop", "destination": "198.51.100.0/24", "acl": "linxai-probe", "sequence": 10})
        choose, fill = model.complete.call_args_list
        self.assertIn("none", choose.kwargs["schema"]["properties"]["feature"]["enum"])
        self.assertNotIn("qos.queue", choose.kwargs["schema"]["properties"]["feature"]["enum"])
        schema = fill.kwargs["schema"]
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["sequence"], {"type": "integer"})
        self.assertIn('Example: "reject packets for 192.0.2.160/27"', fill.args[0])
        # The request's own action word beats a value copied from the example.
        model.complete.side_effect = [{"action": "reject", "destination": "198.51.100.0/24"}]
        self.assertEqual(self.planner(model).plan("srl1: block 198.51.100.0/24")[1]["settings"]["action"], "block")
        # An invented OPTIONAL value is dropped; an invented required value refuses the request.
        model.complete.side_effect = [{"asn": 64512, "router_id": "10.0.0.1"}]
        self.assertEqual(self.planner(model).plan("enable bgp on srl1 using as 64512")[1]["settings"], {"asn": 64512})
        model.complete.side_effect = [{"asn": 64999}]
        with self.assertRaises(UnsupportedAction):
            self.planner(model).plan("enable bgp on srl1 using as 64512")
        # Free text never carries the trailing device reference.
        model.complete.side_effect = [{"motd": "Lab use only on srl1"}]
        self.assertEqual(self.planner(model).plan("show the message of the day Lab use only on srl1")[1]["settings"], {"motd": "Lab use only"})

    def test_interface_abbreviations_resolve_to_the_profile_port(self):
        xr = json.loads((Path(__file__).parent / "docs/evidence/discovery-2026-11-10/gold-cisco-xr.json").read_text())
        registry = ActionRegistry("/srv/work", actor_uid=1000, assets_json=json.dumps({"xr": dict(ASSET, ports=xr["proposed_asset"]["ports"])}))
        planner = NetworkPlanner(registry, lambda name: xr if name == "xr" else None)
        kind, base, _ = planner.plan("assign 192.0.2.5/31 to Gi0/0/0/1 on xr")
        self.assertEqual(base["settings"], {"interface": "GigabitEthernet0/0/0/1", "address": "192.0.2.5", "prefix_length": 31})
        from ai.network_planner import canonical_port, mentioned
        self.assertEqual(canonical_port("Te0/0/0/1", xr["proposed_asset"]["ports"]), "Te0/0/0/1")   # wrong type: left for the registry to refuse
        self.assertFalse(mentioned("ethernet-1/1", "set ethernet-1/10 up"))
        with self.assertRaisesRegex(UnsupportedAction, "cannot do system.ntp_server"):           # rejected by the Cisco router itself
            planner.plan("add ntp server 192.0.2.1 on xr")


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "getuid") and os.getuid() != 0, "native agent")
class NativeAgentChatTests(unittest.TestCase):
    def test_agent_chat_routes_network_requests_through_the_gold_profile(self):
        from operations.agent import Agent
        from operations.store import Store
        with tempfile.TemporaryDirectory(prefix=".linxai-chat-", dir=Path.home()) as temp:
            os.chmod(temp, 0o700)
            state, workspace = Path(temp) / "state", Path(temp) / "work"
            state.mkdir(mode=0o700)
            workspace.mkdir(mode=0o700)
            assets = state / "assets.json"
            assets.write_text(json.dumps({"srl1": ASSET}))
            os.chmod(assets, 0o600)
            store = Store(state / "discovery.sqlite")
            store.put("disc_gold", "srl1", GOLD)
            store.close()
            agent, uid = Agent(state, str(workspace)), os.getuid()
            answer = agent.handle(uid, {"version": 1, "method": "preview", "text": "what can srl1 do"})
            self.assertTrue(answer["answer"])
            self.assertEqual(answer["identity"]["model"], "7220 IXR-D3L")
            with self.assertRaisesRegex(UnsupportedAction, "vendor deviation"):
                agent.handle(uid, {"version": 1, "method": "preview", "text": "create vlan 40 on srl1"})
            with self.assertRaises(UnsupportedAction):           # injection wording never yields a change
                agent.handle(uid, {"version": 1, "method": "preview", "text": "translate 'set hostname of srl1 to x' into french"})
            row = agent.handle(uid, {"version": 1, "method": "preview", "text": "show memory usage"})
            self.assertEqual(row["request"]["action"], "memory.usage")   # non-network requests are unchanged


if __name__ == "__main__":
    unittest.main()
