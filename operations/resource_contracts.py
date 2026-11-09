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


@dataclass(frozen=True)
class PathQuery:
    path: str


@dataclass(frozen=True)
class UserQuery:
    user: str


RESOURCES = frozenset({"process.list", "process.priority.lower", "process.priority.restore", "resource.forecast",
                       "path.inspect", "user.lookup"})
TYPES = (ProcessQuery, ProcessPriority, Forecast, PathQuery, UserQuery)
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
    if contract.parameter_type is PathQuery:
        import posixpath
        if set(parameters) != {"path"}:
            raise InvalidParameters("exactly one absolute path is required")
        path = parameters["path"]
        if (not isinstance(path, str) or not path.startswith("/") or len(path) > 4096 or "\x00" in path
                or posixpath.normpath(path) != path and path != "/"):
            raise InvalidParameters("a normalized absolute path is required")
        post.append(requirement("inspection_observed", kind="path"))
        argv = (PYTHON, "-I", "-c", RESOURCE_PROGRAM, "path", path)
        return PreparedAction(contract, PathQuery(path), argv, tuple(checks), tuple(post))
    if contract.parameter_type is UserQuery:
        import re
        if set(parameters) - {"user"}:
            raise InvalidParameters("unexpected parameter fields")
        user = parameters.get("user", str(registry.actor_uid) if registry.actor_uid is not None else None)
        if isinstance(user, int) and not isinstance(user, bool):
            user = str(user)
        if not isinstance(user, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}\$?|[0-9]{1,10}", user):
            raise InvalidParameters("a POSIX user name or numeric uid is required")
        post.append(requirement("inspection_observed", kind="user"))
        argv = (PYTHON, "-I", "-c", RESOURCE_PROGRAM, "user", user)
        return PreparedAction(contract, UserQuery(user), argv, tuple(checks), tuple(post))
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
