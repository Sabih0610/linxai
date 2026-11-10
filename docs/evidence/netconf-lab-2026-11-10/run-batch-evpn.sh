#!/bin/bash
cd $HOME/linxai-dev && LINXAI_TEST_NETCONF_LAB=1 python3 -B scripts/accept_netconf_batch.py --assets $HOME/.linxai-netlab/assets-batch.json \
  --first srl1 --second srl2 \
  --ok-change '[{"feature": "srl.vxlan_interface", "settings": {"vni": 100}}, {"feature": "srl.mac_vrf_evpn", "settings": {"name": "linxai-macvrf", "vni": 100, "route_target": "target:65001:100"}}]' \
  --bad-change '{"feature": "system.ntp_server", "settings": {"address": "192.0.2.123"}}' --out $HOME/batch-evpn.json 2>&1 | grep -E "^(PASS|FAIL)|rror" | cut -c1-400
