"""Strict bridge from legacy AI plan slots to registry requests.

Command/risk/sudo/rollback metadata never controls a prepared action. Unsupported
semantic fields or declared conditions are rejected rather than silently erased.
"""
from pathlib import PurePosixPath
import re

from .registry import ActionRegistry, InvalidParameters, PreparedAction, UnsupportedAction, normalize_service, validate_port


_INTENTS = {
    "disk_usage": "disk.usage", "memory_usage": "memory.usage",
    "port_check": "ports.listen", "port_list": "ports.listen",
    "service_status": "service.status", "service_start": "service.start",
    "service_stop": "service.stop", "service_restart": "service.restart",
    "file_create": "file.create",
    # Read-only resource views (requirements 46, 50); the model often says cpu_usage.
    "process_list": "process.list", "cpu_usage": "process.list", "resource_forecast": "resource.forecast",
}
_SLOTS = {"target", "port", "protocol", "path", "location", "content", "kind",
          "file_create_kind", "name", "filename", "query", "stack", "repo_url"}
_METADATA = {"intent", "command", "risk_level", "requires_sudo", "rollback",
             "explanation", "suggestion", "source", "goal", "pre_conditions"}


def _port(value: object) -> int:
    # Legacy plans encode ports as strings. Do not coerce booleans or floats.
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}", value):
        value = int(value)
    return validate_port(value)


def _conditions(plan: dict, action: str, parameters: dict) -> None:
    conditions = plan.get("pre_conditions", [])
    if not isinstance(conditions, list) or len(conditions) > 64:
        raise InvalidParameters("pre_conditions must be a list of at most 64 objects")
    for condition in conditions:
        if not isinstance(condition, dict):
            raise InvalidParameters("each declared condition must be an object")
        check = condition.get("check")
        if check == "service_exists" and action.startswith("service."):
            if set(condition) != {"check", "service"} or normalize_service(condition["service"]) != parameters["service"]:
                raise InvalidParameters("service condition must match the action target")
        elif check in ("port_free", "port_occupied") and action in {"service.start", "service.stop", "service.restart"}:
            if set(condition) != {"check", "port"}:
                raise InvalidParameters("port condition requires only a port")
            value = _port(condition["port"])
            if check in parameters and parameters[check] != value:
                raise InvalidParameters("multiple different conditions of the same kind are unsupported")
            parameters[check] = value
        else:
            raise InvalidParameters("unsupported declared condition; it cannot be dropped")


def _create_parameters(plan: dict, registry: ActionRegistry) -> tuple[str, dict]:
    kinds = [plan[key] for key in ("kind", "file_create_kind") if plan.get(key, "") != ""]
    aliases = {"file": "file", "regular_file": "file", "directory": "directory", "folder": "directory", "dir": "directory"}
    if not kinds or any(not isinstance(k, str) or k not in aliases for k in kinds):
        raise InvalidParameters("file_create requires an explicit file or directory kind")
    if len({aliases[k] for k in kinds}) != 1:
        raise InvalidParameters("conflicting create kinds")
    kind = aliases[kinds[0]]
    paths = [plan[key] for key in ("path", "target", "name", "filename") if plan.get(key, "") != ""]
    if not paths:
        raise InvalidParameters("create requires an explicit path or target")
    location = plan.get("location", "")
    parent = registry.relative_path(location) if location != "" and location != registry.permitted_workspace else ""
    normalized = []
    for path in paths:
        # Validate before PurePosixPath can erase '.' or duplicate separators.
        relative = registry.relative_path(path)
        if location != "" and not PurePosixPath(path).is_absolute():
            relative = registry.relative_path(str(PurePosixPath(parent) / relative))
        if location != "" and str(PurePosixPath(relative).parent) != (parent or "."):
            raise InvalidParameters("location and create target disagree")
        normalized.append(relative)
    if len(set(normalized)) != 1:
        raise InvalidParameters("conflicting create paths")
    parameters = {"path": normalized[0]}
    content = plan.get("content", "")
    if kind == "file":
        parameters["content"] = content
    elif content != "":
        raise InvalidParameters("directory creation cannot include file content")
    return f"{kind}.create", parameters


def adapt_plan(plan: dict, registry: ActionRegistry) -> PreparedAction:
    """Prepare a supported plan without running it or granting any permission."""
    if not isinstance(plan, dict):
        raise InvalidParameters("plan must be an object")
    intent = plan.get("intent")
    if not isinstance(intent, str) or intent not in _INTENTS:
        raise UnsupportedAction(f"unsupported plan intent: {intent!r}")
    if set(plan) - _SLOTS - _METADATA:
        raise InvalidParameters("unexpected plan fields")
    action = _INTENTS[intent]
    used = set()
    parameters = {}
    if action.startswith("service."):
        parameters["service"] = normalize_service(plan.get("target"))
        used.add("target")
        # A legacy listener-config request must not become a plain service action.
        if plan.get("port", "") != "":
            _port(plan["port"])
            raise InvalidParameters("service listener configuration is outside this registry")
    elif action == "ports.listen":
        used.update(("port", "target", "protocol"))
        values = [plan[key] for key in ("port", "target") if plan.get(key, "") != ""]
        if intent == "port_check":
            if not values:
                raise InvalidParameters("port_check requires an explicit port")
            ports = [_port(v) for v in values]
            if len(set(ports)) != 1:
                raise InvalidParameters("conflicting port fields")
            parameters["port"] = ports[0]
        elif values:
            raise InvalidParameters("use port_check for a specific port")
        if "protocol" in plan:
            parameters["protocol"] = plan["protocol"]
    elif intent == "file_create":
        used.update(("path", "target", "name", "filename", "location", "kind", "file_create_kind", "content"))
        action, parameters = _create_parameters(plan, registry)
    for key in _SLOTS - used:
        if key in plan and plan[key] != "":
            raise InvalidParameters(f"unsupported nonempty slot: {key}")
    _conditions(plan, action, parameters)
    return registry.prepare(action, parameters)
