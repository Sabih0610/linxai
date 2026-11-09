#!/bin/bash
python3 - <<'PY'
import json, os
h = os.path.expanduser("~/.linxai-netlab")
cases = [{"feature": "interface.description", "settings": {"interface": "ethernet-1/1", "description": "linxai lab uplink"}},
         {"feature": "system.hostname", "settings": {"hostname": "linxai-lab"}},
         {"feature": "system.banner", "settings": {"motd": "Managed by LINxAI lab"}},
         {"feature": "system.dns_server", "settings": {"address": "192.0.2.53"}},
         {"feature": "interface.ipv4", "settings": {"interface": "ethernet-1/1", "address": "198.51.100.1", "prefix_length": 30}},
         {"feature": "static_route", "settings": {"prefix": "203.0.113.0/24", "next_hop": "198.51.100.2"}},
         {"feature": "bgp.global", "settings": {"asn": 65001, "router_id": "192.0.2.1"}},
         {"feature": "bgp.peer_group", "settings": {"name": "linxai-peers", "peer_as": 65002},
          "requires": [{"feature": "bgp.global", "settings": {"asn": 65001, "router_id": "192.0.2.1"}}]},
         {"feature": "bgp.neighbor", "settings": {"neighbor": "198.51.100.2", "peer_as": 65002, "peer_group": "linxai-peers"},
          "requires": [{"feature": "bgp.global", "settings": {"asn": 65001, "router_id": "192.0.2.1"}},
                       {"feature": "bgp.peer_group", "settings": {"name": "linxai-peers", "peer_as": 65002}}]},
         {"feature": "lag.member", "settings": {"interface": "ethernet-1/2", "lag": "lag1"}},
         {"feature": "acl.entry", "settings": {"acl": "linxai-test", "sequence": 10, "action": "drop", "destination": "203.0.113.0/24"}}]
open(h + "/cases-commit.json", "w").write(json.dumps(cases)); print("cases", len(cases))
PY
