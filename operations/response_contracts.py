"""Response contracts extend the existing registry; no execution occurs here."""
from dataclasses import asdict, dataclass
import ipaddress
import json
from uuid import UUID

from ._policy_program import POLICY_PROGRAM


@dataclass(frozen=True)
class NetworkResponse:
    policy_id: str
    event_id: str
    address: str
    port: int
    duration: int


@dataclass(frozen=True)
class RevokeResponse:
    policy_id: str


def uuid(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("Canonical policy/evidence UUID required")
    return value


def prepare(registry, identifier, parameters, contract):
    from .registry import InvalidParameters, PreparedAction, requirement, validate_port
    allowed = {"policy_id", "event_id", "address", "port", "duration"} if identifier == "response.network.block" else {"policy_id"}
    if set(parameters) != allowed or registry.actor_uid is None:
        raise InvalidParameters("Exact response fields and backend OS identity are required")
    try:
        policy_id = uuid(parameters["policy_id"])
        if identifier == "response.network.block":
            address = str(ipaddress.IPv4Address(parameters["address"]))
            if address != parameters["address"]: raise ValueError("Canonical IPv4 address required")
            duration = parameters["duration"]
            if type(duration) is not int or not 30 <= duration <= 3600:
                raise ValueError("Policy duration must be 30–3600 seconds")
            typed = NetworkResponse(policy_id, uuid(parameters["event_id"]), address, validate_port(parameters["port"]), duration)
        else:
            typed = RevokeResponse(policy_id)
    except (ValueError, TypeError) as exc:
        raise InvalidParameters(str(exc)) from exc
    stdin = json.dumps({"actor_uid": registry.actor_uid, "parameters": asdict(typed)}, sort_keys=True, separators=(",", ":")).encode()
    checks = (requirement("linux_runtime"), requirement("trusted_executable", path="/usr/bin/python3"),
              requirement("authenticated_authorization", action=identifier, policy_id=policy_id),
              requirement("response_owner_scope", action=identifier, parameters=stdin.decode()),
              requirement("qualified_kernel_enforcer"))
    if identifier == "response.policy.revoke":
        checks = tuple(check for check in checks if check.identifier != "qualified_kernel_enforcer")
    post = (requirement("exit_code", value=0), requirement("response_policy_verified", action=identifier, policy_id=policy_id))
    return PreparedAction(contract, typed, ("/usr/bin/python3", "-I", "-c", POLICY_PROGRAM, identifier), checks, post, stdin)
