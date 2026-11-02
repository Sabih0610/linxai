"""Shape validation for generated and cached plans; this is not authorization."""
import re

SUPPORTED_INTENTS = frozenset("""
service_start service_stop service_restart service_status service_enable service_disable service_reload
process_list process_kill process_info process_priority process_background
port_check port_list firewall_add firewall_remove firewall_list network_status network_interfaces network_info dns_lookup
file_create file_delete file_move file_copy file_permissions file_read file_find disk_usage directory_list
user_add user_remove user_list user_password user_groups
package_install package_remove package_update package_list package_search env_setup
cpu_usage memory_usage system_uptime system_info kernel_info log_view log_tail log_search chat not_applicable unknown
""".split())


def validate_plan(plan: dict) -> dict:
    """Return a normalized copy; reject incorrect types before downstream use.

    A schema-valid shell command is not necessarily safe. Independent action,
    parameter and privilege policies are still required before execution.
    """
    if not isinstance(plan, dict):
        raise ValueError("Plan must be a JSON object.")
    result = dict(plan)
    for field in ("intent", "target", "command"):
        if field not in result:
            raise ValueError(f"Plan missing required field: '{field}'")
        if not isinstance(result[field], str):
            raise ValueError(f"Plan field '{field}' must be a string.")
    if result["intent"] not in SUPPORTED_INTENTS:
        raise ValueError("Plan contains an unsupported intent.")
    defaults = {"pre_conditions": [], "requires_sudo": False,
                "risk_level": "low", "rollback": "",
                "explanation": "No explanation provided.", "suggestion": "",
                "port": "", "goal": "", "path": "", "stack": "", "repo_url": ""}
    for key, value in defaults.items():
        result.setdefault(key, value)
    if type(result["requires_sudo"]) is not bool:
        raise ValueError("requires_sudo must be a JSON boolean.")
    if result["risk_level"] not in ("low", "medium", "high"):
        raise ValueError("risk_level must be low, medium or high.")
    for key in ("target", "command", "rollback", "explanation", "suggestion",
                "goal", "path", "stack", "repo_url", "location", "content",
                "kind", "source", "query", "name", "filename"):
        if key not in result:
            continue
        value = result[key]
        if not isinstance(value, str) or "\x00" in value or len(value) > 32768:
            raise ValueError(f"Plan field '{key}' must be a bounded string without NUL bytes.")
    port = result["port"]
    if type(port) is int:
        port = str(port)
    if not isinstance(port, str) or (port and (not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535)):
        raise ValueError("port must be empty or an integer between 1 and 65535.")
    result["port"] = port
    conditions = result["pre_conditions"]
    if not isinstance(conditions, list) or len(conditions) > 64:
        raise ValueError("pre_conditions must be a list of at most 64 objects.")
    for condition in conditions:
        if not isinstance(condition, dict) or not isinstance(condition.get("check"), str) or not condition["check"].strip():
            raise ValueError("Each precondition must contain a non-empty check name.")
    result["pre_conditions"] = [dict(condition) for condition in conditions]
    return result
