#!/bin/bash
cd $HOME/linxai-dev && LINXAI_TEST_IOT_LAB=1 python3 -B scripts/accept_iot.py --assets $HOME/.linxai-iot/assets.json --modbus plc --mqtt home --out $HOME/iot-acceptance.json 2>&1 | grep -E "^(PASS|FAIL)|rror" | cut -c1-230
