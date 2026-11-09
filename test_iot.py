"""IoT extension: strict MQTT/Modbus assets, bounded values, typed actions only."""
import json
import unittest
from uuid import uuid4

from operations.registry import ActionRegistry, InvalidParameters

MODBUS = {"platform": "modbus", "host": "192.0.2.20", "port": 502, "unit": 1, "state_dir": "/home/owner/.linxai/iot",
          "points": {"setpoint": {"kind": "holding", "address": 10, "writable": True, "min": 15, "max": 30},
                     "pump": {"kind": "coil", "address": 0, "writable": True},
                     "temperature": {"kind": "input", "address": 0}}}
MQTT = {"platform": "mqtt", "host": "127.0.0.1", "port": 1883, "username": "linxai", "password_file": "/home/owner/.linxai/mqtt.pass",
        "ca_file": None, "state_dir": "/home/owner/.linxai/iot",
        "points": {"lamp": {"state_topic": "lab/lamp/state", "command_topic": "lab/lamp/set", "values": ["ON", "OFF"]},
                   "fan": {"state_topic": "lab/fan/state", "command_topic": "lab/fan/set", "min": 0, "max": 3},
                   "humidity": {"state_topic": "lab/humidity", "command_topic": None}}}


def registry(**assets):
    return ActionRegistry("/srv/work", actor_uid=1000, assets_json=json.dumps(assets))


def write(asset, point, value):
    return {"asset": asset, "point": point, "value": value, "expected_revision": "0" * 64, "transaction_id": str(uuid4())}


class IotContractTests(unittest.TestCase):
    def setUp(self):
        self.registry = registry(plc=MODBUS, home=MQTT)

    def test_inspect_and_bounded_writes_prepare(self):
        prepared = self.registry.prepare("iot.inspect", {"asset": "plc"})
        self.assertEqual(prepared.argv[:3], ("/usr/bin/python3", "-I", "-c"))
        compile(prepared.argv[3], "workflow", "exec")
        self.assertEqual(self.registry.prepare("iot.point.set", write("plc", "setpoint", 22)).parameters.value, 22)
        self.assertIs(self.registry.prepare("iot.point.set", write("plc", "pump", True)).parameters.value, True)
        self.assertEqual(self.registry.prepare("iot.point.set", write("home", "lamp", "ON")).parameters.value, "ON")
        self.assertTrue(self.registry.prepare("iot.point.set", write("home", "fan", 3)).contract.recovery_supported)

    def test_out_of_bounds_read_only_and_unknown_points_refused(self):
        for asset, point, value in (("plc", "setpoint", 31), ("plc", "setpoint", 14), ("plc", "setpoint", True),
                                    ("plc", "pump", 1), ("plc", "temperature", 20), ("plc", "valve", 1),
                                    ("home", "lamp", "BLINK"), ("home", "fan", 4), ("home", "humidity", "50"),
                                    ("home", "lamp", "ON; rm -rf /")):
            with self.assertRaises(InvalidParameters, msg=(point, value)):
                self.registry.prepare("iot.point.set", write(asset, point, value))
        with self.assertRaises(InvalidParameters):
            self.registry.prepare("iot.point.set", {**write("plc", "setpoint", 20), "address": 99})

    def test_asset_configuration_is_strict(self):
        bad = [dict(MQTT, host="192.0.2.5"),                                   # network MQTT without TLS
               dict(MQTT, points={"x": {"state_topic": "lab/#", "command_topic": None}}),   # wildcard topic
               dict(MQTT, points={"x": {"state_topic": "a", "command_topic": "b"}}),        # writable without bounds
               dict(MODBUS, unit=300), dict(MODBUS, points={"t": {"kind": "input", "address": 1, "writable": True}}),
               dict(MODBUS, points={"s": {"kind": "holding", "address": 1, "writable": True}}),  # no min/max
               dict(MODBUS, extra=1), dict(MODBUS, platform="bacnet")]
        for asset in bad:
            with self.assertRaises(InvalidParameters, msg=asset):
                registry(x=asset).prepare("iot.inspect", {"asset": "x"})
        tls = dict(MQTT, host="192.0.2.5", ca_file="/etc/ssl/certs/lab-ca.pem")
        registry(x=tls).prepare("iot.inspect", {"asset": "x"})

    def test_planner_inspects_configured_iot_assets_only(self):
        from unittest.mock import Mock
        from ai.local_planner import Planner
        planner = Planner(self.registry, Mock())
        self.assertEqual(planner.propose("read plc sensors")[0], {"action": "iot.inspect", "parameters": {"asset": "plc"}})
        self.assertEqual(planner.propose("show home status")[0], {"action": "iot.inspect", "parameters": {"asset": "home"}})
        planner.model.generate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
