#!/bin/bash
docker start srl1 >/dev/null
for i in $(seq 1 40); do
  timeout 20 docker exec srl1 sudo sr_cli -d "info from state system information version" 2>/dev/null | grep -q version && break
  sleep 5
done
echo "ready after ~$((i*5))s"
