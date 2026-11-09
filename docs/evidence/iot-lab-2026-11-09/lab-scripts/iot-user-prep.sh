#!/bin/bash
# Owner: start the simulator and write the IoT assets file.
set -e
H=$HOME/.linxai-iot
pkill -f iot_lab_sim.py || true
cd $HOME/linxai-dev
setsid nohup python3 -B scripts/iot_lab_sim.py --mqtt-password-file $H/device.pass > $H/sim.log 2>&1 < /dev/null &
sleep 3
python3 - <<PY
import json, os
H = os.path.expanduser("~/.linxai-iot")
assets = {
 "plc": {"platform": "modbus", "host": "127.0.0.1", "port": 5020, "unit": 1, "state_dir": H + "/state",
         "points": {"setpoint": {"kind": "holding", "address": 10, "writable": True, "min": 15, "max": 30},
                    "pump": {"kind": "coil", "address": 0, "writable": True},
                    "temperature": {"kind": "input", "address": 0}}},
 "home": {"platform": "mqtt", "host": "127.0.0.1", "port": 1883, "username": "linxai", "password_file": H + "/mqtt.pass",
          "ca_file": None, "state_dir": H + "/state",
          "points": {"lamp": {"state_topic": "lab/lamp/state", "command_topic": "lab/lamp/set", "values": ["ON", "OFF"]},
                     "fan": {"state_topic": "lab/fan/state", "command_topic": "lab/fan/set", "min": 0, "max": 3},
                     "humidity": {"state_topic": "lab/humidity", "command_topic": None}}}}
path = H + "/assets.json"; open(path, "w").write(json.dumps(assets, indent=2)); os.chmod(path, 0o600)
print("assets written")
PY
pgrep -f iot_lab_sim.py >/dev/null && echo "simulator running"; tail -3 $H/sim.log
