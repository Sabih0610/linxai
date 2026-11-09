#!/bin/bash
# Root (WSL lab only): a second data interface and a static LAG for lag.member tests.
printf 'enter candidate\nset / interface ethernet-1/2 admin-state disable\nset / interface lag1 admin-state enable\nset / interface lag1 lag lag-type static\ncommit now\n' > /tmp/srl-lag.cfg
docker cp /tmp/srl-lag.cfg srl1:/tmp/srl-lag.cfg
timeout 60 docker exec -i srl1 sudo sr_cli -ed < /tmp/srl-lag.cfg | tail -1
