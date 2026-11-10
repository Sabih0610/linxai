#!/bin/bash
# Enable QoS and EVPN-VXLAN features on the lab assets and write the hard-tier cases.
python3 - <<'PY'
import json, os
h = os.path.expanduser("~/.linxai-netlab")
new = {"srl.qos_queue", "srl.qos_forwarding_class", "srl.qos_dscp_rule", "srl.qos_interface_policy", "srl.vxlan_interface", "srl.mac_vrf_evpn", "interface.ipv4"}
for f in ("assets.json", "assets-batch.json"):
    p = h + "/" + f
    if not os.path.exists(p): continue
    a = json.load(open(p))
    for v in a.values(): v["features"] = sorted(set(v.get("features", [])) | new)
    open(p, "w").write(json.dumps(a, indent=2)); os.chmod(p, 0o600)
IP = {"feature": "interface.ipv4", "settings": {"interface": "ethernet-1/1", "address": "198.51.100.1", "prefix_length": 30}}
Q = {"feature": "srl.qos_queue", "settings": {"queue": "unicast-5"}}
F = {"feature": "srl.qos_forwarding_class", "settings": {"name": "fc5", "unicast_queue": "unicast-5"}}
R = {"feature": "srl.qos_dscp_rule", "settings": {"policy": "linxai-dscp", "dscp": 46, "forwarding_class": "fc5"}}
V = {"feature": "srl.vxlan_interface", "settings": {"vni": 100}}
cases = [Q, dict(F, requires=[Q]), dict(R, requires=[Q, F]),
         {"feature": "srl.qos_interface_policy", "settings": {"interface": "ethernet-1/1", "policy": "linxai-dscp"}, "requires": [IP, Q, F, R]},
         V, {"feature": "srl.mac_vrf_evpn", "settings": {"name": "linxai-macvrf", "vni": 100, "route_target": "target:65001:100"}, "requires": [V]}]
open(h + "/cases-hard.json", "w").write(json.dumps(cases)); print("cases", len(cases))
PY
