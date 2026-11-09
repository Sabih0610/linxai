#!/bin/bash
# Enable NETCONF (port 830, no shell) and key-only admin login on the lab SR Linux node.
set -e
KEYDIR=/root/linxai-netlab; mkdir -p -m 700 $KEYDIR
[ -f $KEYDIR/id_ed25519 ] || ssh-keygen -q -t ed25519 -N "" -f $KEYDIR/id_ed25519 -C linxai-netlab
PUB=$(cut -d' ' -f1,2 $KEYDIR/id_ed25519.pub)
cat > /tmp/srl-netconf.cfg <<CFG
enter candidate
set / system ssh-server mgmt-netconf admin-state enable network-instance mgmt port 830 disable-shell true
set / system netconf-server mgmt admin-state enable ssh-server mgmt-netconf
set / system aaa authentication admin-user ssh-key [ "$PUB" ]
set / system lldp admin-state enable
set / system management openconfig admin-state enable
commit now
CFG
docker cp /tmp/srl-netconf.cfg srl1:/tmp/srl-netconf.cfg
timeout 60 docker exec -i srl1 sudo sr_cli -ed < /tmp/srl-netconf.cfg 2>&1 | tail -5 || true
timeout 30 docker exec srl1 sudo bash -c 'sr_cli -d "info system netconf-server *"; sr_cli -d "info system ssh-server mgmt-netconf"' 2>&1 | tail -15
