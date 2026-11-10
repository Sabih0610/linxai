"""Device discovery: capability evidence, knowledge base medallion and live gold profile."""
import base64
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import zlib

from discovery import capability as cap
from discovery.device import Discovery
from discovery.kb import Builder
from operations import netconf_features as nf
from test_application import MemoryStore

OC = {"openconfig-%s" % m: "" for m in ("system", "interfaces", "if-ip", "if-ethernet", "vlan", "network-instance",
                                        "if-aggregate", "acl", "qos")}
DEVIATIONS = '''module acme-dev {
  deviation "/oc-qos:qos/oc-qos:classifiers/oc-qos:classifier/oc-qos:terms/oc-qos:term/oc-qos:conditions/oc-qos:ipv4/oc-qos:config/oc-qos:dscp-set" {
    deviate not-supported;
  }
  deviation /oc-sys:system/oc-sys:config/oc-sys:motd-banner { deviate replace { type string { length "0..10"; } } }
  deviation "/oc-ni:network-instances/oc-ni:network-instance/oc-ni:vlans" { description "a } inside a string"; deviate not-supported; }
}'''


def packed(name, text):
    raw = text.encode()
    import hashlib
    return {"name": name, "ok": True, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "z": base64.b64encode(zlib.compress(raw)).decode()}


class CapabilityTests(unittest.TestCase):
    def test_every_feature_has_a_sample_and_evaluates(self):
        self.assertEqual(set(cap.SAMPLES), set(nf.FEATURES))
        statuses = {r["feature"]: r["status"] for r in cap.evaluate_all(set(OC), [])}
        self.assertTrue(all(s == "supported" for f, s in statuses.items() if not f.startswith("srl.")))
        self.assertTrue(all(s == "unknown" for f, s in statuses.items() if f.startswith("srl.")))   # native: needs a live device

    def test_deviations_parse_with_nested_braces_and_decide_support(self):
        devs = cap.parse_deviations(DEVIATIONS, "acme-dev")
        self.assertEqual([d["path"] for d in devs], ["/qos/classifiers/classifier/terms/term/conditions/ipv4/config/dscp-set",
                                                     "/system/config/motd-banner", "/network-instances/network-instance/vlans"])
        result = {r["feature"]: r for r in cap.evaluate_all(set(OC), devs)}
        self.assertEqual(result["qos.classifier_term"]["status"], "unsupported")
        self.assertIn("dscp-set", result["qos.classifier_term"]["evidence"][0])
        self.assertEqual(result["system.banner"]["status"], "supported_with_limits")
        self.assertEqual(result["vlan"]["status"], "unsupported")
        self.assertEqual(result["system.hostname"]["status"], "supported")      # same container, different leaf

    def test_missing_model_and_native_namespace(self):
        result = cap.evaluate("acl.entry", set(OC) - {"openconfig-acl"}, [])
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(cap.evaluate("srl.vxlan_interface", set(OC), [], namespaces=set())["status"], "unsupported")
        self.assertEqual(cap.evaluate("srl.vxlan_interface", set(OC), [], namespaces={nf.NS["srlvx"]})["status"], "supported")

    def test_capabilities_and_vendor_identification(self):
        mods = cap.parse_capabilities([
            "http://openconfig.net/yang/vlan?module=openconfig-vlan&revision=2015-10-09&deviation=cisco-xr-openconfig-vlan-deviations",
            "http://cisco.com/ns/yang/Cisco-IOS-XR-ifmgr-cfg?module=Cisco-IOS-XR-ifmgr-cfg&revision=2015-11-09",
            "urn:ietf:params:netconf:capability:candidate:1.0", "junk?module=bad name"])
        self.assertEqual(set(mods), {"openconfig-vlan", "Cisco-IOS-XR-ifmgr-cfg"})
        self.assertEqual(mods["openconfig-vlan"]["deviations"], ["cisco-xr-openconfig-vlan-deviations"])
        self.assertEqual(cap.identify(mods), ("cisco", "iosxr"))


class KnowledgeBaseTests(unittest.TestCase):
    def test_cisco_platform_flows_bronze_silver_gold_and_quarantines_bad_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            d = root / "yang" / "vendor" / "cisco" / "xr" / "792"
            d.mkdir(parents=True)
            caps = "".join(f"<capability>http://openconfig.net/yang/x?module={m}&amp;revision=1&amp;deviations=acme-dev</capability>" for m in OC)
            (d / "capabilities-ncs5k.xml").write_text(f'<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities>{caps}</capabilities></hello>')
            (d / "capabilities-broken.xml").write_text("<hello><not closed>")
            (d / "acme-dev.yang").write_text(DEVIATIONS)
            builder = Builder(root / "kb.sqlite")
            builder.cisco(root)
            builder.close()
            db = sqlite3.connect(root / "kb.sqlite")
            self.assertEqual(db.execute("SELECT vendor, os, platform, modules, deviations FROM silver_platform").fetchall(),
                             [("cisco", "iosxr", "ncs5k", len(OC), 3)])
            self.assertEqual(db.execute("SELECT count(*) FROM bronze_file").fetchone()[0], 3)
            self.assertEqual(db.execute("SELECT reason FROM quarantine").fetchall(), [("unparsable capability list",)])
            self.assertEqual(db.execute("SELECT status FROM gold_support WHERE feature='qos.classifier_term'").fetchone()[0], "unsupported")
            db.close()


class LiveDiscoveryTests(unittest.TestCase):
    def output(self):
        hello = "\n".join([f"http://openconfig.net/yang/{m}?module={m}&revision=1&deviations=acme-dev" for m in OC]
                          + ["urn:ietf:params:netconf:capability:candidate:1.0", "urn:ietf:params:netconf:capability:confirmed-commit:1.1",
                             "urn:ietf:params:netconf:capability:validate:1.1", "urn:nokia.com:srlinux:x?module=srl_nokia-x&revision=1"])
        intf = ('<data><interfaces xmlns="http://openconfig.net/yang/interfaces">'
                '<interface><name>mgmt0</name><state><type>iana-if-type:ethernetCsmacd</type><oper-status>UP</oper-status></state></interface>'
                '<interface><name>ethernet-1/1</name><state><type>iana-if-type:ethernetCsmacd</type><oper-status>DOWN</oper-status></state></interface>'
                '<interface><name>srte_c_333_ep_3.0.3.6</name></interface>'          # IOS XR SR-TE tunnel: no type, no state
                '</interfaces></data>')
        system = '<data><system xmlns="http://openconfig.net/yang/system"><state><hostname>leaf1</hostname><software-version>26.7.2</software-version></state></system></data>'
        return {"discovery": [packed("hello", hello), packed("interfaces", intf), packed("system", system), packed("lldp", "<data><broken"),
                              {"name": "components", "ok": False, "error": "unknown element"},
                              {"name": "running_config", "ok": True, "sha256": "a" * 64, "bytes": 10},
                              packed("schema:acme-dev", DEVIATIONS)]}

    def test_gold_profile_from_raw_replies_with_quarantine_history_and_drift(self):
        store = MemoryStore()
        with tempfile.TemporaryDirectory() as tmp:
            tx = Path(tmp) / "transactions"
            tx.mkdir()
            (tx / "a.json").write_text(json.dumps({"feature": "system.hostname", "state": "restored"}))
            for i in range(3):
                (tx / f"q{i}.json").write_text(json.dumps({"feature": "qos.queue", "state": "captured"}))
            disc = Discovery(store, clock=lambda: 1000.0)
            asset = {"host": "192.0.2.10", "state_dir": tmp}
            gold = disc.ingest("leaf1", asset, {"open": [{"port": 23, "banner": ""}]}, self.output(),
                               probes=[{"feature": "static_route", "validated": True}, {"feature": "acl.entry", "validated": False, "device_error": "no"}])
            features = {r["feature"]: r for r in gold["features"]}
            self.assertEqual((gold["vendor"], gold["os"], gold["version"], gold["hostname"]), ("nokia", "srlinux", "26.7.2", "leaf1"))
            self.assertTrue(gold["safe_changes"])
            self.assertEqual(gold["management_interfaces"], ["mgmt0"])
            self.assertEqual(gold["proposed_asset"]["ports"], ["ethernet-1/1"])           # management port and untyped tunnels never offered
            self.assertEqual(features["system.hostname"]["status"], "proven")
            self.assertIn("never completed", features["qos.queue"]["warning"])
            self.assertNotIn("qos.queue", gold["proposed_asset"]["features"])
            self.assertEqual(features["static_route"]["probe"], "validated by device")
            self.assertEqual(features["acl.entry"]["status"], "unsupported")              # device rejected the probe
            self.assertEqual(features["vlan"]["status"], "unsupported")                   # vendor deviation
            self.assertTrue(any("telnet" in n for n in gold["security_notes"]))
            quarantined = {q["item"] for q in store.get("disc_quarantine", "leaf1")["items"]}
            self.assertEqual(quarantined, {"components", "lldp"})
            self.assertIsNotNone(store.get("disc_bronze", "leaf1:hello"))
            later = self.output()
            later["discovery"][5] = {"name": "running_config", "ok": True, "sha256": "b" * 64, "bytes": 10}
            gold2 = Discovery(store, clock=lambda: 2000.0).ingest("leaf1", asset, {"open": []}, later)
            self.assertIn("running configuration changed since the previous discovery", gold2["security_notes"])
            # Fleet evidence: a second device on the same OS and version inherits proven/warning facts.
            peer = Discovery(store, clock=lambda: 3000.0).ingest("leaf2", {"host": "192.0.2.11"}, {"open": []}, self.output())
            peer_features = {r["feature"]: r for r in peer["features"]}
            self.assertIn("proven on leaf1", peer_features["system.hostname"]["fleet"])
            self.assertIn("on leaf1", peer_features["qos.queue"]["warning"])
            self.assertNotIn("qos.queue", peer["proposed_asset"]["features"])


if __name__ == "__main__":
    unittest.main()
