"""Closed action vocabulary with validated, immutable preparation contracts.

No subprocesses, system checks, authentication or filesystem reads occur here.
PreparedAction is a specification, never an approval or an execution capability.
"""
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from pathlib import PurePosixPath
import re
from types import MappingProxyType
from typing import Mapping

from ._create_program import CREATE_PROGRAM
from .face_contracts import FaceParameters
from .response_contracts import NetworkResponse, RevokeResponse
from .workflow_contracts import Project, Device, Interface, Restore, Remote, TYPES as WORKFLOW_TYPES


class ActionError(ValueError):
    """An action request cannot be represented by this registry."""


class UnsupportedAction(ActionError):
    pass


class InvalidParameters(ActionError):
    pass


class Privilege(str, Enum):
    UNPRIVILEGED = "unprivileged"
    AUTHENTICATED_ADMIN = "authenticated_admin"


@dataclass(frozen=True)
class NoParameters:
    pass


@dataclass(frozen=True)
class PortParameters:
    port: int | None = None
    protocol: str = "tcp"


@dataclass(frozen=True)
class ServiceParameters:
    service: str
    port_free: int | None = None
    port_occupied: int | None = None


@dataclass(frozen=True)
class FileParameters:
    relative_path: str
    content: str = ""


@dataclass(frozen=True)
class DirectoryParameters:
    relative_path: str


Parameters = NoParameters | PortParameters | ServiceParameters | FileParameters | DirectoryParameters | NetworkResponse | RevokeResponse | Project | Device | Interface | Restore | Remote | FaceParameters


@dataclass(frozen=True)
class Requirement:
    """A required observation/predicate; not an observed check result."""
    identifier: str
    arguments: tuple[tuple[str, str | int], ...] = ()


def requirement(identifier: str, **arguments: str | int) -> Requirement:
    return Requirement(identifier, tuple(arguments.items()))


@dataclass(frozen=True)
class ActionContract:
    identifier: str
    parameter_type: type
    privilege: Privilege
    timeout_s: int
    recovery_supported: bool = False


@dataclass(frozen=True)
class PreparedAction:
    contract: ActionContract
    parameters: Parameters
    argv: tuple[str, ...]
    mandatory_checks: tuple[Requirement, ...]
    postconditions: tuple[Requirement, ...]
    stdin: bytes = b""
    # Deliberately cannot be enabled by an input parameter or a model field.
    execution_supported: bool = field(default=False, init=False)


_UNPRIVILEGED = Privilege.UNPRIVILEGED
_ADMIN = Privilege.AUTHENTICATED_ADMIN
ACTIONS: Mapping[str, ActionContract] = MappingProxyType({
    c.identifier: c for c in (
        ActionContract("auth.face.enroll", FaceParameters, _ADMIN, 20),
        ActionContract("auth.face.revoke", FaceParameters, _ADMIN, 10),
        ActionContract("environment.python", Project, _UNPRIVILEGED, 30),
        ActionContract("project.scaffold", Project, _UNPRIVILEGED, 30),
        ActionContract("device.initialize", Device, _UNPRIVILEGED, 10),
        ActionContract("device.inspect", Device, _UNPRIVILEGED, 10),
        ActionContract("device.interface.set", Interface, _UNPRIVILEGED, 10, recovery_supported=True),
        ActionContract("device.interface.restore", Restore, _UNPRIVILEGED, 10),
        ActionContract("remote.operation", Remote, _UNPRIVILEGED, 30),
        ActionContract("response.network.block", NetworkResponse, _ADMIN, 15),
        ActionContract("response.policy.revoke", RevokeResponse, _ADMIN, 15),
        ActionContract("disk.usage", NoParameters, _UNPRIVILEGED, 10),
        ActionContract("memory.usage", NoParameters, _UNPRIVILEGED, 5),
        ActionContract("ports.listen", PortParameters, _UNPRIVILEGED, 5),
        ActionContract("service.status", ServiceParameters, _UNPRIVILEGED, 10),
        ActionContract("service.start", ServiceParameters, _ADMIN, 30),
        ActionContract("service.stop", ServiceParameters, _ADMIN, 30),
        ActionContract("service.restart", ServiceParameters, _ADMIN, 30),
        ActionContract("file.create", FileParameters, _UNPRIVILEGED, 5),
        ActionContract("directory.create", DirectoryParameters, _UNPRIVILEGED, 5),
    )
})


def validate_port(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise InvalidParameters("port must be an integer from 1 through 65535")
    return value


def normalize_service(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 255:
        raise InvalidParameters("service must be a bounded service name")
    name = value.removesuffix(".service")
    # A conservative subset of systemd names; no globs, escapes or options.
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*(?:@[A-Za-z0-9][A-Za-z0-9_.-]*)?", name)
            or ".." in name or name.endswith((".service", ".socket", ".target", ".timer",
                                              ".path", ".mount", ".automount", ".swap",
                                              ".slice", ".scope"))):
        raise InvalidParameters("expected a single concrete .service unit")
    # Same compatibility aliases as the legacy deterministic command builder.
    name = {"apache": "apache2", "httpd": "apache2"}.get(name, name)
    if len(name + ".service") > 255:
        raise InvalidParameters("service unit is too long")
    return name + ".service"


def _path_text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8", errors="replace")) > 4095:
        raise InvalidParameters("path must be a nonempty bounded POSIX path")
    parts = value[1:].split("/") if value.startswith("/") else value.split("/")
    if any(part in {"", ".", ".."} or len(part) > 255
           or not re.fullmatch(r"[A-Za-z0-9_.][A-Za-z0-9_. -]*", part)
           for part in parts):
        raise InvalidParameters("path contains a traversal, empty or unsupported component")
    return value


@dataclass(frozen=True)
class ActionRegistry:
    """Construct with backend configuration, never configuration from an AI plan.

    POSIX paths are validated lexically even on Windows. Live filesystem identity,
    symlink/ownership checks and authorization belong to the future service.
    """
    permitted_workspace: str | None = None
    actor_uid: int | None = None
    assets_json: str = "{}"

    def __post_init__(self):
        if not isinstance(self.assets_json,str) or len(self.assets_json.encode())>65536 or not isinstance(json.loads(self.assets_json),dict):
            raise InvalidParameters("Bounded backend assets object required")
        if self.actor_uid is not None and (type(self.actor_uid) is not int or self.actor_uid <= 0):
            raise InvalidParameters("Backend actor must be an ordinary OS UID")
        if self.permitted_workspace is not None:
            root = _path_text(self.permitted_workspace)
            if not root.startswith("/"):
                raise InvalidParameters("permitted workspace must be an absolute POSIX directory")

    def relative_path(self, value: object) -> str:
        if self.permitted_workspace is None:
            raise InvalidParameters("file actions require an explicitly configured permitted workspace")
        path = PurePosixPath(_path_text(value))
        root = PurePosixPath(self.permitted_workspace)
        if path.is_absolute():
            try:
                path = path.relative_to(root)
            except ValueError as exc:
                raise InvalidParameters("path is outside the permitted workspace") from exc
        if path == PurePosixPath("."):
            raise InvalidParameters("the workspace itself cannot be a create target")
        # Relative inputs also need the length bound after anchoring to the root.
        _path_text(str(root / path))
        return str(path)

    def prepare(self, identifier: str, parameters: Mapping[str, object] | None = None) -> PreparedAction:
        if not isinstance(identifier, str) or identifier not in ACTIONS:
            raise UnsupportedAction(f"unsupported action: {identifier!r}")
        if parameters is None:
            parameters = {}
        if not isinstance(parameters, Mapping):
            raise InvalidParameters("parameters must be an object")
        parameters = dict(parameters)
        contract = ACTIONS[identifier]
        parameter_type = contract.parameter_type
        if parameter_type is FaceParameters:
            from .face_contracts import prepare
            return prepare(self, identifier, parameters, contract)
        if parameter_type in WORKFLOW_TYPES:
            from .workflow_contracts import prepare
            return prepare(self, identifier, parameters, contract)
        if parameter_type in {NetworkResponse, RevokeResponse}:
            from .response_contracts import prepare
            return prepare(self, identifier, parameters, contract)
        allowed = {
            NoParameters: set(), PortParameters: {"port", "protocol"},
            ServiceParameters: {"service", "port_free", "port_occupied"},
            FileParameters: {"path", "content"}, DirectoryParameters: {"path"},
        }[parameter_type]
        if set(parameters) - allowed:
            raise InvalidParameters("unexpected parameter fields")

        checks = [requirement("linux_runtime")]
        post = [requirement("exit_code", value=0)]
        stdin = b""
        if parameter_type is NoParameters:
            typed: Parameters = NoParameters()
            if identifier == "disk.usage":
                argv = ("/usr/bin/df", "-P", "-B1", "--exclude-type=fuse.sshfs")
                post.append(requirement("disk_usage_observed"))
            else:
                argv = ("/usr/bin/free", "--bytes")
                checks.append(requirement("readable_path", path="/proc/meminfo"))
                post.append(requirement("memory_usage_observed"))
        elif parameter_type is PortParameters:
            port = parameters.get("port")
            if port is not None:
                port = validate_port(port)
            protocol = parameters.get("protocol", "tcp")
            if not isinstance(protocol, str) or protocol not in {"tcp", "udp"}:
                raise InvalidParameters("protocol must be tcp or udp")
            typed = PortParameters(port, protocol)
            argv = ("/usr/bin/ss", "-H", "-l", "-n", "-t" if protocol == "tcp" else "-u")
            if port is not None:
                argv += (f"sport = :{port}",)
            checks.append(requirement("socket_inventory_available", protocol=protocol))
            selection = {"port": port} if port is not None else {}
            post.append(requirement("listeners_observed", protocol=protocol, **selection))
        elif parameter_type is ServiceParameters:
            service = normalize_service(parameters.get("service"))
            free = parameters.get("port_free")
            occupied = parameters.get("port_occupied")
            if free is not None:
                free = validate_port(free)
            if occupied is not None:
                occupied = validate_port(occupied)
            if free is not None and free == occupied:
                raise InvalidParameters("contradictory port conditions")
            if identifier == "service.status" and (free is not None or occupied is not None):
                raise InvalidParameters("status does not accept mutation conditions")
            typed = ServiceParameters(service, free, occupied)
            checks.extend((requirement("systemd_available"), requirement("service_exists", service=service)))
            if identifier == "service.status":
                argv = ("/usr/bin/systemctl", "--no-pager", "show",
                        "--property=Id,LoadState,ActiveState,SubState", "--", service)
                post.append(requirement("service_state_observed", service=service))
            else:
                action = identifier.split(".")[1]
                argv = ("/usr/bin/systemctl", "--no-ask-password", action, "--", service)
                checks.append(requirement("authenticated_authorization", action=identifier, service=service))
                if action in {"start", "restart"}:
                    checks.append(requirement("service_not_masked", service=service))
                if free is not None:
                    checks.append(requirement("tcp_port_free", port=free))
                if occupied is not None:
                    checks.append(requirement("tcp_port_occupied", port=occupied))
                post.append(requirement("service_active_state", service=service,
                                        state="inactive" if action == "stop" else "active"))
        else:
            relative = self.relative_path(parameters.get("path"))
            full = str(PurePosixPath(self.permitted_workspace) / relative)
            kind = "file" if parameter_type is FileParameters else "directory"
            if kind == "file":
                content = parameters.get("content", "")
                if not isinstance(content, str):
                    raise InvalidParameters("content must be UTF-8 text")
                try:
                    stdin = content.encode("utf-8")
                except UnicodeEncodeError as exc:
                    raise InvalidParameters("content must be valid UTF-8 text") from exc
                if len(stdin) > 65536:
                    raise InvalidParameters("content exceeds 65536 UTF-8 bytes")
                typed = FileParameters(relative, content)
                post.append(requirement("file_content_sha256", path=full, sha256=hashlib.sha256(stdin).hexdigest()))
            else:
                typed = DirectoryParameters(relative)
            argv = ("/usr/bin/python3", "-I", "-c", CREATE_PROGRAM,
                    self.permitted_workspace, relative, kind)
            checks.extend((
                requirement("unprivileged_identity"),
                requirement("workspace_safe", workspace=self.permitted_workspace),
                requirement("no_symlink_components", path=full),
                requirement("parent_directory_writable", path=str(PurePosixPath(full).parent)),
                requirement("target_absent", path=full),
            ))
            post.extend((requirement("entry_type", path=full, kind=kind),
                         requirement("entry_confined", workspace=self.permitted_workspace, path=full)))
        checks.insert(1, requirement("trusted_executable", path=argv[0]))
        return PreparedAction(contract, typed, argv, tuple(checks), tuple(post), stdin)
