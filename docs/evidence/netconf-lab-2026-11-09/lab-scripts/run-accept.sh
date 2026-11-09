#!/bin/bash
cd $HOME/linxai-dev
LINXAI_TEST_NETCONF_LAB=1 python3 -B scripts/accept_netconf.py --assets $HOME/.linxai-netlab/assets.json --asset srl1 --out $HOME/netconf-acceptance.json
