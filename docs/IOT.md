# IoT devices: MQTT and Modbus/TCP (extension)

LINxAI reads and writes IoT devices only through three typed actions —
`iot.inspect`, `iot.point.set`, `iot.point.restore` — on owner-configured assets.
The AI can ask to inspect an asset; a write is previewed with the agent's
`iot_preview` (asset, point, value), which binds it to the inspected state. The AI
can never name a topic, register address or raw payload.

## Status (9 November 2026)

| Target | Status |
| --- | --- |
| Modbus/TCP PLC (pymodbus 3.6.9 simulator) and MQTT devices (Mosquitto 2.0.18 with password auth and per-user ACLs), WSL2 lab | **Accepted**: `scripts/accept_iot.py` 19/19 (`evidence/iot-lab-2026-11-09/`) |
| Real PLCs, real MQTT devices/gateways, MQTT over TLS on a network | Not yet tested |
| Other protocols (OPC UA, BACnet, Zigbee via Zigbee2MQTT) | Not implemented |

## Safety model

- **Allowlisted points only.** Each asset lists named points; anything else is refused
  before dispatch. MQTT topics must be literal (no `+`/`#` wildcards).
- **Bounds.** Writable holding registers need `min`/`max`; MQTT writes need
  enumerated `values` or integer `min`/`max`; coils take true/false; input
  registers, discrete inputs and points without a command topic are read-only.
- **Preview binding.** A write carries the revision of the writable points seen at
  preview (sensor readings are excluded, since they drift) and a single-use
  transaction id; a changed device or a replay is refused.
- **Verified by the device.** Modbus writes are read back from the device. MQTT
  writes succeed only when the device itself reports the new value on its state
  topic — a broker accepting a publish proves nothing (a silent device fails).
- **Authenticated sessions.** MQTT success requires an explicit CONNACK 0; a wrong
  password fails (the acceptance test caught the bug where `connect()` alone looked
  successful). MQTT over a network requires TLS (`ca_file`); plain MQTT is only
  allowed to a loopback broker.
- **Restore.** Every write snapshots the prior value; the result offers a typed
  `iot.point.restore`, valid 300 s, refused if the device changed since.
- **Modbus has no authentication** — keep PLCs on an isolated network. On the
  gateway host, LINxAI's kernel sensor and learned baseline flag unexpected
  processes or destinations (e.g. a new program talking to port 502).

## Asset examples (private file, owner-configured)

```json
{"plc": {"platform": "modbus", "host": "10.0.50.20", "port": 502, "unit": 1, "state_dir": "/home/owner/.linxai/iot",
         "points": {"setpoint": {"kind": "holding", "address": 10, "writable": true, "min": 15, "max": 30},
                    "pump": {"kind": "coil", "address": 0, "writable": true},
                    "temperature": {"kind": "input", "address": 0}}},
 "home": {"platform": "mqtt", "host": "broker.lab", "port": 8883, "username": "linxai",
          "password_file": "/home/owner/.linxai/mqtt.pass", "ca_file": "/home/owner/.linxai/lab-ca.pem",
          "state_dir": "/home/owner/.linxai/iot",
          "points": {"lamp": {"state_topic": "lab/lamp/state", "command_topic": "lab/lamp/set", "values": ["ON", "OFF"]},
                     "humidity": {"state_topic": "lab/humidity", "command_topic": null}}}}
```

## Lab

`scripts/iot_lab_sim.py` (development only) simulates a Modbus PLC and MQTT
lamp/fan/humidity devices; the broker setup and asset file used for acceptance are
in `evidence/iot-lab-2026-11-09/lab-scripts/`.
