"""Typed process/resource contracts (original requirements 46-49).

Processes are addressed by (pid, start_ticks, owner uid), never by PID or name
alone. Lowering priority is an unprivileged owner action that captures the prior
nice value; restoring it needs authenticated admin authorization through the
broker and may never go below nice 0.
"""
from dataclasses import dataclass

from ._resource_program import RESOURCE_PROGRAM


@dataclass(frozen=True)
class ProcessQuery:
    limit: int = 15


@dataclass(frozen=True)
class Forecast:
    samples: int = 10
    horizon_s: int = 60


@dataclass(frozen=True)
class ProcessPriority:
    pid: int
    start_ticks: int
    nice: int


RESOURCES = frozenset({"process.list", "process.priority.lower", "process.priority.restore", "resource.forecast"})
TYPES = (ProcessQuery, ProcessPriority, Forecast)
PYTHON = "/usr/bin/python3"


def _integer(value, low, high, name):
    from .registry import InvalidParameters
    if type(value) is not int or not low <= value <= high:
        raise InvalidParameters(f"{name} must be an integer from {low} through {high}")
    return value


def prepare(registry, identifier, parameters, contract):
    from .registry import InvalidParameters, PreparedAction, requirement
    checks = [requirement("linux_runtime"), requirement("trusted_executable", path=PYTHON)]
    post = [requirement("exit_code", value=0)]
    if contract.parameter_type is ProcessQuery:
        if set(parameters) - {"limit"}:
            raise InvalidParameters("unexpected parameter fields")
        limit = _integer(parameters.get("limit", 15), 1, 50, "limit")
        checks.append(requirement("readable_path", path="/proc/stat"))
        post.append(requirement("process_inventory_observed", limit=limit))
        argv = (PYTHON, "-I", "-c", RESOURCE_PROGRAM, "list", str(limit))
        return PreparedAction(contract, ProcessQuery(limit), argv, tuple(checks), tuple(post))
    if contract.parameter_type is Forecast:
        if set(parameters) - {"samples", "horizon_s"}:
            raise InvalidParameters("unexpected parameter fields")
        samples = _integer(parameters.get("samples", 10), 5, 40, "samples")     # 0.5 s each, within timeout
        horizon = _integer(parameters.get("horizon_s", 60), 10, 600, "horizon_s")
        checks += [requirement("readable_path", path="/proc/stat"), requirement("readable_path", path="/proc/meminfo")]
        post.append(requirement("resource_forecast_observed", samples=samples))
        argv = (PYTHON, "-I", "-c", RESOURCE_PROGRAM, "forecast", str(samples), str(horizon))
        return PreparedAction(contract, Forecast(samples, horizon), argv, tuple(checks), tuple(post))
    if set(parameters) != {"pid", "start_ticks", "nice"}:
        raise InvalidParameters("pid, start_ticks and nice are required")
    if registry.actor_uid is None:
        raise InvalidParameters("process actions require a configured backend actor")
    lower = identifier == "process.priority.lower"
    pid = _integer(parameters["pid"], 2, 4194304, "pid")
    start = _integer(parameters["start_ticks"], 1, 2**62, "start_ticks")
    nice = _integer(parameters["nice"], 1, 19, "nice") if lower else _integer(parameters["nice"], 0, 18, "nice")
    checks += [requirement("process_identity", pid=pid, start_ticks=start, uid=registry.actor_uid),
               requirement("nice_direction", pid=pid, start_ticks=start, nice=nice,
                           direction="increase" if lower else "decrease")]
    if not lower:
        checks.append(requirement("authenticated_authorization", action=identifier, pid=pid))
    post.append(requirement("process_priority_verified", pid=pid, start_ticks=start, nice=nice))
    argv = (PYTHON, "-I", "-c", RESOURCE_PROGRAM, "lower" if lower else "restore",
            str(pid), str(start), str(nice), str(registry.actor_uid))
    return PreparedAction(contract, ProcessPriority(pid, start, nice), argv, tuple(checks), tuple(post))
