"""Typed NETCONF/OpenConfig config features: validation, guards and XML rendering."""
import json
import unittest
from uuid import uuid4
from xml.etree import ElementTree as ET

from operations import netconf_features as nf
from operations.registry import ActionRegistry, InvalidParameters

ASSET = {"platform": "netconf", "host": "192.0.2.10", "port": 830, "username": "ops", "key_path": "/home/o/.ssh/k",
         "host_key_sha256": "SHA256:" + "A" * 43, "state_dir": "/home/o/.linxai/nc", "ports": ["ge-0/0/1", "ge-0/0/2", "ae0"],
         "features": sorted(nf.FEATURES)}


class FeatureTests(unittest.TestCase):
    def render(self, feature, settings):
        path, config = nf.resolve(feature, settings, ASSET)
        return ET.fromstring(nf.render(path, config)), path, config

    def test_every_feature_renders_well_formed_xml_with_its_keys(self):
        cases = {"interface.description": {"interface": "ge-0/0/1", "description": "uplink"},
                 "system.hostname": {"hostname": "core-1"}, "system.banner": {"motd": "authorised use only"},
                 "system.ntp_server": {"address": "192.0.2.123"}, "system.dns_server": {"address": "192.0.2.53"},
                 "interface.ipv4": {"interface": "ge-0/0/1", "address": "198.51.100.1", "prefix_length": 30},
                 "vlan": {"vlan_id": 100}, "interface.access_vlan": {"interface": "ge-0/0/2", "vlan_id": 100},
                 "static_route": {"prefix": "203.0.113.0/24", "next_hop": "198.51.100.2"},
                 "ospf.interface": {"interface": "ge-0/0/1"}, "bgp.global": {"asn": 65001, "router_id": "192.0.2.1"},
                 "bgp.peer_group": {"name": "peers", "peer_as": 65002},
                 "bgp.neighbor": {"neighbor": "198.51.100.2", "peer_as": 65002, "peer_group": "peers"},
                 "lag.member": {"interface": "ge-0/0/2", "lag": "ae0"},
                 "acl.entry": {"acl": "edge", "sequence": 10, "action": "drop", "destination": "203.0.113.0/24"}}
        self.assertEqual(set(cases), set(nf.FEATURES))
        for feature, settings in cases.items():
            root, path, config = self.render(feature, settings)
            self.assertEqual(root.tag.split("}")[-1], path[0][1], feature)
            for rel, value in nf.expected_leaves(config):
                self.assertTrue(value, (feature, rel))
            # a filter carries keys only, never desired values
            filt = nf.render(path)
            for rel, value in nf.expected_leaves(config):
                if rel[-1] not in {k for _, _, keys, *_ in path for k in keys}:
                    self.assertNotIn(f"<{rel[-1]}>{value}<", filt, (feature, rel))

    def test_management_guards(self):
        for feature, settings in (("interface.ipv4", {"interface": "ge-0/0/1", "address": "192.0.2.11", "prefix_length": 24}),
                                  ("static_route", {"prefix": "192.0.2.0/24", "next_hop": "198.51.100.2"}),
                                  ("static_route", {"prefix": "0.0.0.0/0", "next_hop": "198.51.100.2"}),
                                  ("acl.entry", {"acl": "a", "sequence": 1, "action": "drop", "destination": "192.0.2.0/24"}),
                                  ("acl.entry", {"acl": "a", "sequence": 1, "action": "reject"}),       # drop-all
                                  ("bgp.neighbor", {"neighbor": "192.0.2.10", "peer_as": 1}),
                                  ("interface.description", {"interface": "mgmt0", "description": "x"}),
                                  ("system.hostname", {"hostname": "bad host;"}),
                                  ("lag.member", {"interface": "ge-0/0/2", "lag": "ge-0/0/2"})):
            with self.assertRaises(ValueError, msg=(feature, settings)):
                nf.resolve(feature, settings, ASSET)
        # an accept rule may match management traffic; a drop rule to elsewhere is fine
        nf.resolve("acl.entry", {"acl": "a", "sequence": 1, "action": "accept"}, ASSET)
        nf.resolve("acl.entry", {"acl": "a", "sequence": 2, "action": "drop", "destination": "203.0.113.0/24"}, ASSET)

    def test_identity_values_follow_rfc7950_prefix_rule(self):
        acl = nf.render(*nf.resolve("acl.entry", {"acl": "a", "sequence": 1, "action": "drop", "destination": "203.0.113.0/24"}, ASSET))
        self.assertIn("<type>ACL_IPV4</type>", acl)                      # same module: unprefixed
        route = nf.render(*nf.resolve("static_route", {"prefix": "203.0.113.0/24", "next_hop": "198.51.100.2"}, ASSET))
        self.assertIn('xmlns:oc-pol-types="http://openconfig.net/yang/policy-types">oc-pol-types:STATIC', route)

    def test_features_must_be_enabled_per_asset_and_contracts_are_strict(self):
        limited = dict(ASSET, features=["system.hostname"])
        with self.assertRaises(ValueError):
            nf.resolve("static_route", {"prefix": "203.0.113.0/24", "next_hop": "198.51.100.2"}, limited)
        registry = ActionRegistry("/srv/work", actor_uid=1000, assets_json=json.dumps({"core": limited}))
        prepared = registry.prepare("device.config.set", {"asset": "core", "feature": "system.hostname", "settings": {"hostname": "r1"},
                                                          "expected_revision": "0" * 64, "transaction_id": str(uuid4())})
        self.assertTrue(prepared.contract.recovery_supported)
        compile(prepared.argv[3], "workflow", "exec")
        for bad in ({"asset": "core", "feature": "static_route", "settings": {}},
                    {"asset": "core", "feature": "system.hostname", "settings": {"hostname": "r1"}, "xml": "<x/>"}):
            with self.assertRaises(InvalidParameters):
                registry.prepare("device.config.read", bad)
        with self.assertRaises(InvalidParameters):
            ActionRegistry("/srv/work", actor_uid=1000, assets_json=json.dumps({"core": dict(ASSET, features=["raw.xml"])})).prepare(
                "device.config.read", {"asset": "core", "feature": "system.hostname", "settings": {"hostname": "r1"}})

    def test_restore_xml_replaces_with_snapshot_or_removes_created_entry(self):
        path, _ = nf.resolve("system.hostname", {"hostname": "r1"}, ASSET)
        replace = nf.render(path, operation="replace", inner_xml="<hostname>old</hostname>", extra=' xmlns:oc-x="urn:x"')
        self.assertIn('nc:operation="replace" xmlns:oc-x="urn:x"><hostname>old</hostname>', replace)
        path, _ = nf.resolve("bgp.neighbor", {"neighbor": "198.51.100.2", "peer_as": 65002}, ASSET)
        remove = nf.render(path[:4], operation="remove")              # the protocol entry this change created
        self.assertIn('nc:operation="remove"', remove)
        self.assertNotIn("neighbor", remove)

    def test_restore_removes_only_the_created_entry_when_device_hides_ancestors(self):
        """Regression: SR Linux answers a filter naming a missing entry with EMPTY data, which once made
        the engine believe the default network-instance was absent and remove it on restore."""
        import hashlib, re
        from operations._netconf_config_program import CONFIG_CODE
        ns = dict(vars(nf), ET=ET, hashlib=hashlib, _re=re, action="none")
        exec(CONFIG_CODE, ns)
        gpath, gconfig = nf.resolve("bgp.global", {"asn": 65001, "router_id": "192.0.2.1"}, ASSET)
        device = '<data xmlns="%s">%s</data>' % (nf.NC, nf.render(gpath, gconfig))     # BGP exists, no peer-group

        class Device:
            def get_config(self, source, filter):
                return type("Reply", (), {"data_xml": '<data xmlns="%s"/>' % nf.NC if "peer-group" in filter[1] else device})()
        path, _ = nf.resolve("bgp.peer_group", {"name": "peers", "peer_as": 65002}, ASSET)
        depth = ns["existing_depth"](Device(), path)
        top = next(i for i in range(depth, len(path)) if path[i][2])
        self.assertEqual(path[top][1], "peer-group")

    def test_batch_is_bounded_one_change_per_device(self):
        assets = {"a": ASSET, "b": dict(ASSET, host="192.0.2.12"), "c": dict(ASSET, host="192.0.2.13"),
                  "d": dict(ASSET, host="192.0.2.14"), "e": dict(ASSET, host="192.0.2.15")}
        registry = ActionRegistry("/srv/work", actor_uid=1000, assets_json=json.dumps(assets))
        change = lambda name, host="r1": {"asset": name, "feature": "system.hostname", "settings": {"hostname": host}, "expected_revision": "0" * 64}
        prepared = registry.prepare("device.config.batch", {"transaction_id": str(uuid4()), "changes": [change("a"), change("b")]})
        self.assertEqual(len(json.loads(prepared.parameters.changes_json)), 2)
        compile(prepared.argv[3], "workflow", "exec")
        for changes in ([change("a")], [change("a"), change("a", "r2")], [change(n) for n in "abcde"],
                        [change("a"), {**change("b"), "settings": {"hostname": "bad host"}}]):
            with self.assertRaises(InvalidParameters, msg=len(changes)):
                registry.prepare("device.config.batch", {"transaction_id": str(uuid4()), "changes": changes})


if __name__ == "__main__":
    unittest.main()
