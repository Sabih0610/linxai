#!/bin/bash
# Start a local Nokia SR Linux lab node (free image) with NETCONF on 127.0.0.1:2830.
docker rm -f srl1 >/dev/null 2>&1
docker run -t -d --privileged --name srl1 -p 127.0.0.1:2830:830 -p 127.0.0.1:2022:22 \
  ghcr.io/nokia/srlinux sudo bash /opt/srlinux/bin/sr_linux >/dev/null
for i in $(seq 1 60); do
  docker exec srl1 sr_cli -d "info from state system information version" 2>/dev/null | grep -q version && break
  sleep 5
done
docker exec srl1 sr_cli -d "info from state system information version"
echo "--- netconf"; docker exec srl1 sr_cli -d "info system netconf-server" 2>&1 | head -20
echo "--- ssh"; docker exec srl1 sr_cli -d "info system ssh-server" 2>&1 | head -10
