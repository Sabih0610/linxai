"""Typed IoT contracts: MQTT and Modbus/TCP points (IoT extension).

An owner-configured asset lists named points. Only listed points can be read and only
writable points can be written, within configured bounds or enumerated values. Writes
are bound to the revision the owner previewed and to a single-use transaction, read
back from the device, and offer a bounded restore. The AI can never name a topic,
register address or payload directly.

Modbus/TCP has no authentication, so assets must sit on an isolated network; MQTT
requires TLS unless the broker is on loopback.
"""
from dataclasses import dataclass
import ipaddress
import re
from uuid import UUID

IOT_ACTIONS = frozenset({"iot.inspect", "iot.point.set", "iot.point.restore"})
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_TOPIC = re.compile(r"[A-Za-z0-9_./-]{1,128}")


@dataclass(frozen=True)
class IotInspect:
    asset: str


@dataclass(frozen=True)
class IotSet:
    asset: str
    point: str
    value: object
    expected_revision: str
    transaction_id: str


@dataclass(frozen=True)
class IotRestore:
    asset: str
    transaction_id: str
    expected_revision: str


TYPES = (IotInspect, IotSet, IotRestore)


def _path(value):
    return isinstance(value, str) and value.startswith("/") and len(value) <= 4095 and "\x00" not in value


def _loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def validate_asset(asset, InvalidParameters):
    platform = asset.get("platform")
    if platform == "modbus":
        if set(asset) != {"platform", "host", "port", "unit", "state_dir", "points"}:
            raise InvalidParameters("Modbus asset requires exactly: platform, host, port, unit, state_dir, points")
        if type(asset["unit"]) is not int or not 0 <= asset["unit"] <= 247:
            raise InvalidParameters("Modbus unit id must be 0..247")
    elif platform == "mqtt":
        if set(asset) != {"platform", "host", "port", "username", "password_file", "ca_file", "state_dir", "points"}:
            raise InvalidParameters("MQTT asset requires exactly: platform, host, port, username, password_file, ca_file, state_dir, points")
        if asset["ca_file"] is None and not _loopback(asset["host"]):
            raise InvalidParameters("MQTT over a network requires TLS (ca_file)")
        if asset["ca_file"] is not None and not _path(asset["ca_file"]):
            raise InvalidParameters("Absolute CA file path required")
        if not isinstance(asset["username"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", asset["username"]) or not _path(asset["password_file"]):
            raise InvalidParameters("MQTT username and absolute password file required")
    else:
        raise InvalidParameters("Unsupported IoT platform")
    if not isinstance(asset["host"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}", asset["host"]):
        raise InvalidParameters("Invalid IoT host")
    if type(asset["port"]) is not int or not 1 <= asset["port"] <= 65535 or not _path(asset["state_dir"]):
        raise InvalidParameters("Invalid IoT port or state directory")
    points = asset["points"]
    if not isinstance(points, dict) or not 1 <= len(points) <= 64:
        raise InvalidParameters("1..64 configured points required")
    for name, point in points.items():
        if not _NAME.fullmatch(name) or not isinstance(point, dict):
            raise InvalidParameters("Invalid point name")
        if platform == "modbus":
            if point.get("kind") not in {"holding", "coil", "input", "discrete"} or type(point.get("address")) is not int \
                    or not 0 <= point["address"] <= 65535:
                raise InvalidParameters(f"Point {name}: kind and address 0..65535 required")
            if point["kind"] == "holding" and point.get("writable"):
                if not (type(point.get("min")) is int and type(point.get("max")) is int and 0 <= point["min"] <= point["max"] <= 65535):
                    raise InvalidParameters(f"Point {name}: writable holding register needs 0 <= min <= max <= 65535")
            if point.get("writable") and point["kind"] in {"input", "discrete"}:
                raise InvalidParameters(f"Point {name}: input registers and discrete inputs are read-only")
        else:
            if not isinstance(point.get("state_topic"), str) or not _TOPIC.fullmatch(point["state_topic"]):
                raise InvalidParameters(f"Point {name}: literal state topic required (no wildcards)")
            command = point.get("command_topic")
            if command is not None and (not isinstance(command, str) or not _TOPIC.fullmatch(command)):
                raise InvalidParameters(f"Point {name}: literal command topic required (no wildcards)")
            if command is not None and not (isinstance(point.get("values"), list) and 1 <= len(point["values"]) <= 16
                                            and all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", v) for v in point["values"])
                                            or type(point.get("min")) is int and type(point.get("max")) is int and point["min"] <= point["max"]):
                raise InvalidParameters(f"Point {name}: writable MQTT point needs enumerated values or integer min/max")


def writable(asset, point):
    spec = asset["points"][point]
    return bool(spec.get("writable")) if asset["platform"] == "modbus" else spec.get("command_topic") is not None


def check_value(asset, point, value, InvalidParameters):
    spec = asset["points"][point]
    if asset["platform"] == "modbus" and spec["kind"] == "coil":
        if type(value) is not bool: raise InvalidParameters("Coil value must be true or false")
    elif "values" in spec:
        if value not in spec["values"]: raise InvalidParameters("Value is not one of the configured values")
    elif type(value) is not int or not spec["min"] <= value <= spec["max"]:
        raise InvalidParameters(f"Value must be an integer from {spec['min']} through {spec['max']}")
    return value


def typed(identifier, name, asset, parameters, InvalidParameters):
    validate_asset(asset, InvalidParameters)
    if identifier == "iot.inspect":
        if set(parameters) != {"asset"}: raise InvalidParameters("Exact IoT inspect fields required")
        return IotInspect(name)
    expected = {"asset", "transaction_id", "expected_revision"} | ({"point", "value"} if identifier == "iot.point.set" else set())
    if set(parameters) != expected: raise InvalidParameters("Exact IoT write/restore fields required")
    token, revision = parameters["transaction_id"], parameters["expected_revision"]
    if not isinstance(token, str) or str(UUID(token)) != token: raise InvalidParameters("Canonical transaction UUID required")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision): raise InvalidParameters("Expected revision SHA256 required")
    if identifier == "iot.point.restore":
        return IotRestore(name, token, revision)
    point = parameters["point"]
    if point not in asset["points"] or not writable(asset, point): raise InvalidParameters("Configured writable point required")
    return IotSet(name, point, check_value(asset, point, parameters["value"], InvalidParameters), revision, token)
