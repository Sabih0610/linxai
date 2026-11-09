#!/bin/bash
# Root part (WSL lab only): lab interface on the SR Linux node; hand the lab key to the owner.
set -e
printf 'enter candidate\nset / interface ethernet-1/1 admin-state disable\ncommit now\n' > /tmp/srl-if.cfg
docker cp /tmp/srl-if.cfg srl1:/tmp/srl-if.cfg
timeout 60 docker exec -i srl1 sudo sr_cli -ed < /tmp/srl-if.cfg | tail -1
install -d -o sabih -g sabih -m 700 /home/sabih/.linxai-netlab /home/sabih/.linxai-netlab/state
install -o sabih -g sabih -m 600 /root/linxai-netlab/id_ed25519 /home/sabih/.linxai-netlab/id_ed25519
