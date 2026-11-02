"""Root-owned service mechanism. No wire authority, argv or raw shell is accepted."""
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import socket
import stat
import threading
import time

from . import ipc
from .audit import JsonlAudit
from .registry import ActionRegistry, Privilege, normalize_service
from .service import Execution, Identity, Observation, Operation, OperationResult, OperationService, _Stop, fingerprint
from .store import Store
from .supervised import SupervisedLinuxAdapter

SERVICE_ADMIN = frozenset({"service.start", "service.stop", "service.restart"})
RESPONSE_ADMIN = frozenset({"response.network.block", "response.policy.revoke"})
FACE_ADMIN = frozenset({"auth.face.enroll", "auth.face.revoke"})
ADMIN = SERVICE_ADMIN | RESPONSE_ADMIN | FACE_ADMIN


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int
    start: int

    @classmethod
    def read(cls, sock):
        pid, uid, gid = ipc.credentials(sock)
        data = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()
        peer = cls(pid, uid, gid, int(data[19]))
        peer.validate()
        return peer

    def validate(self):
        import pwd
        if self.pid <= 0 or self.uid <= 0:
            raise PermissionError("Ordinary peer required")
        status = Path(f"/proc/{self.pid}/status").read_text()
        rows = {line.split(":", 1)[0]: line.split(":", 1)[1].split() for line in status.splitlines() if ":" in line}
        start = int(Path(f"/proc/{self.pid}/stat").read_text().rpartition(")")[2].split()[19])
        if start != self.start or any(int(v) != self.uid for v in rows["Uid"]) or any(int(v) != self.gid for v in rows["Gid"]):
            raise PermissionError("Peer exited, changed credentials or was reused")
        return Identity(self.uid, self.uid, pwd.getpwuid(self.uid).pw_name)


class RootAudit(JsonlAudit):
    def _writer_uid(self):
        if os.getuid() != 0 or os.geteuid() != 0:
            raise PermissionError("Root ledger requires root")
        return 0

    def append(self, record):
        with self._lock:
            return self._append_locked(record)

    def _append_locked(self, record):
        # Bound each ledger generation. Only root can write the parent directory.
        if self.path.exists() and self.path.stat().st_size >= 8 * 1024 * 1024:
            self._writer_uid()
            SupervisedLinuxAdapter()._directories(self.path.parent, 0, private_leaf=True)
            for index in (3, 2, 1):
                src = self.path.with_name(self.path.name + (f".{index-1}" if index > 1 else ""))
                dst = self.path.with_name(self.path.name + f".{index}")
                if src.exists():
                    info = src.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
                        raise PermissionError("Unsafe audit rotation entry")
                    src.replace(dst)
        super().append(record)


class Polkit:
    def __init__(self, runner):
        self.runner = runner

    def authorize(self, peer, operation):
        peer.validate()
        if operation.prepared.contract.identifier not in FACE_ADMIN:
            try:
                from security.face import FaceClient
                if FaceClient().authorize(peer,operation) is True:
                    peer.validate();self.last_method="qualified_face";return True
            except Exception:
                pass  # Face failure never suppresses trusted OS password fallback.
        self.runner._trusted_executable("/usr/bin/pkcheck")
        prepared = operation.prepared
        digest = fingerprint(operation)
        target = getattr(prepared.parameters, "service", getattr(prepared.parameters, "policy_id", ""))
        if hasattr(prepared.parameters, "address"):
            target += f" {prepared.parameters.address}:{prepared.parameters.port} for {prepared.parameters.duration}s"
        if prepared.contract.identifier in FACE_ADMIN:target=f"account UID {peer.uid}"
        action_id = "org.linxai.response.manage" if prepared.contract.identifier in RESPONSE_ADMIN else "org.linxai.face.manage" if prepared.contract.identifier in FACE_ADMIN else "org.linxai.service.manage"
        argv = ("/usr/bin/pkcheck", "--action-id", action_id, "--process",
                f"{peer.pid},{peer.start},{peer.uid}", "--allow-user-interaction",
                "--detail", "action", prepared.contract.identifier,
                "--detail", "target", target,
                "--detail", "operation", operation.operation_id,
                "--detail", "digest", digest,
                "--detail", "polkit.message", f"Authorize LINxAI {prepared.contract.identifier} on {target}")
        result = self.runner._run(operation.operation_id, argv, b"", 120)
        if result.error or result.returncode != 0:
            status = "authentication_cancelled" if result.returncode == 3 else "authentication_authorization_required"
            raise _Stop(status, "OS authorization denied, unavailable, cancelled or timed out")
        peer.validate()
        self.last_method="polkit"
        return True


class BrokerSystem(SupervisedLinuxAdapter):
    OUTPUT_LIMIT = 8192
    def __init__(self, peer):
        self.peer = peer
        self.authorized = None

    def resolve_identity(self):
        return self.peer.validate()

    def check(self, op_id, required, identity):
        name, args = required.identifier, dict(required.arguments)
        if name == "face_owner_scope":
            try:
                from security.face import FaceClient
                value=FaceClient().call("preview",actor_uid=identity.uid)
                return Observation(op_id,required,value["uid"]==identity.uid==args["uid"],"Independent account profile checked",json.dumps(value.get("profile"),sort_keys=True))
            except Exception as exc:return Observation(op_id,required,False,type(exc).__name__)
        if name in {"response_owner_scope", "qualified_kernel_enforcer"}:
            try:
                from security.policy_daemon import PolicyClient
                if name == "qualified_kernel_enforcer":
                    reply = PolicyClient().call("status")
                    ok = reply["qualified"] is True and reply["owner_uid"] == identity.uid
                else:
                    payload = json.loads(args["parameters"])
                    reply = PolicyClient().call("preview", actor_uid=identity.uid, parameters=payload["parameters"], revoke=args["action"] == "response.policy.revoke")
                    ok = reply["owner_uid"] == identity.uid
                return Observation(op_id, required, ok, "Independent root response policy checked", json.dumps(reply, sort_keys=True))
            except Exception as exc:
                return Observation(op_id, required, False, type(exc).__name__)
        if name == "authenticated_authorization":
            ok = self.authorized is not None and time.monotonic() < self.authorized[1]
            return Observation(op_id, required, ok, "Bound OS authorization" if ok else "OS authorization absent", self.authorized[0] if ok else "")
        if name in {"tcp_port_free", "tcp_port_occupied"}:
            self._trusted_executable("/usr/bin/ss")
            result = self._run(op_id, ("/usr/bin/ss", "-H", "-l", "-n", "-t", f"sport = :{args['port']}"), b"", 3)
            ok = not result.error and result.returncode == 0 and bool(result.stdout.strip()) == (name == "tcp_port_occupied")
            return Observation(op_id, required, ok, "TCP constraint observed", result.stdout)
        if name in {"service_exists", "service_not_masked"}:
            try:
                props = self._service_properties(op_id, args["service"])
                ok = props.get("Id") == args["service"] and props.get("LoadState") == "loaded"
                if name == "service_not_masked":
                    ok = ok and props.get("UnitFileState") not in {None, "masked", "masked-runtime"}
                return Observation(op_id, required, ok, "Service state observed", json.dumps(props, sort_keys=True))
            except Exception as exc:
                return Observation(op_id, required, False, str(exc))
        return super().check(op_id, required, identity)

    def execute(self, op_id, prepared, identity):
        if os.getuid() != 0 or os.geteuid() != 0 or self.resolve_identity() != identity or self.authorized is None or time.monotonic() >= self.authorized[1]:
            return Execution(op_id, prepared.argv, None, started=False, error="Broker authorization/context expired")
        if (prepared.contract.identifier not in ADMIN or prepared != getattr(self, "authorized_prepared", None)
                or op_id != getattr(self, "authorized_operation_id", None)):
            return Execution(op_id, prepared.argv, None, started=False, error="Broker action unsupported")
        return self._run(op_id, prepared.argv, prepared.stdin, prepared.contract.timeout_s)

    def verify(self, op_id, required, prepared, execution, identity):
        if required.identifier == "face_profile_verified":
            try:
                from security.face import FaceClient
                value=FaceClient().call("status");args=dict(required.arguments)
                return Observation(op_id,required,value["uid"]==identity.uid==args["uid"] and value["enrolled"]==bool(args["enrolled"]),"Protected account enrollment state verified")
            except Exception as exc:return Observation(op_id,required,False,type(exc).__name__)
        if required.identifier == "response_policy_verified":
            try:
                from security.policy_daemon import PolicyClient
                reply = PolicyClient().call("verify", policy_id=dict(required.arguments)["policy_id"])
                return Observation(op_id, required, reply["verified"] is True, "Independent kernel containment/revocation verification", json.dumps(reply, sort_keys=True))
            except Exception as exc:
                return Observation(op_id, required, False, type(exc).__name__)
        if required.identifier == "service_active_state":
            args = dict(required.arguments)
            try:
                props = self._service_properties(op_id, args["service"])
                ok = props.get("Id") == args["service"] and props.get("LoadState") == "loaded" and props.get("ActiveState") == args["state"]
                return Observation(op_id, required, ok, "Fresh service state verified", json.dumps(props, sort_keys=True))
            except Exception as exc:
                return Observation(op_id, required, False, str(exc))
        return super().verify(op_id, required, prepared, execution, identity)


class BrokerService(OperationService):
    def __init__(self, request_id, request, peer, owner_uid, services, system, authorizer, audit):
        super().__init__(ActionRegistry(actor_uid=peer.uid), system, None, audit)
        self.id, self.request, self.peer = request_id, request, peer
        self.owner_uid, self.services, self.authorizer = owner_uid, frozenset(services), authorizer
        self.grant = None

    def _new_operation_id(self):
        return self.id

    def _authorize(self, identity, prepared):
        if identity.uid != self.owner_uid or identity != self.peer.validate() or prepared.contract.identifier not in ADMIN or (prepared.contract.identifier in SERVICE_ADMIN and prepared.parameters.service not in self.services):
            raise _Stop("authorization_denied", "Caller, action or service not in root-owned allowlist")
        operation = Operation(self.id, identity, json.dumps(self.request, sort_keys=True, separators=(",", ":"), allow_nan=False), prepared)
        digest = fingerprint(operation)
        if self.grant:
            if digest != self.grant[0] or time.monotonic() >= self.grant[1]:
                raise _Stop("authorization_denied", "Authorized operation changed or expired")
        else:
            automatic = False
            if prepared.contract.identifier == "response.network.block":
                try:
                    from security.policy_daemon import PolicyClient
                    proof = PolicyClient().call("automatic", actor_uid=identity.uid, parameters=asdict(prepared.parameters), operation_id=self.id, digest=digest)
                    automatic = (proof.get("authorized") is True and proof.get("owner_uid") == identity.uid
                                 and proof.get("operation_id") == self.id and proof.get("digest") == digest)
                except Exception:
                    automatic = False
            if not automatic and self.authorizer.authorize(self.peer, operation) is not True:
                raise _Stop("authentication_authorization_required", "Trusted OS authorization or independently configured automatic policy required")
            source=getattr(self.authorizer,"last_method","trusted_authorizer")
            self.authorization_source="root_owner_policy" if automatic else source if type(source) is str else "trusted_authorizer"
            self.grant = (digest, time.monotonic() + 30)
        self.system.authorized = self.grant
        self.system.authorized_prepared = prepared
        self.system.authorized_operation_id = self.id


class Broker:
    def __init__(self, owner_uid, services, store, audit, *, system_factory=BrokerSystem, authorizer_factory=Polkit):
        if type(owner_uid) is not int or owner_uid <= 0 or not isinstance(services, (tuple, list)) or not 1 <= len(services) <= 32:
            raise ValueError("Non-root owner and 1–32 explicit services required")
        self.owner_uid = owner_uid
        self.services = frozenset(normalize_service(s) for s in services)
        if {"linxai-broker.service", "polkit.service", "dbus.service"} & self.services:
            raise ValueError("Broker/authentication infrastructure cannot be managed")
        self.store, self.audit = store, audit
        self.system_factory, self.authorizer_factory = system_factory, authorizer_factory

    def handle(self, peer, envelope):
        from uuid import uuid4
        operation_id, result = str(uuid4()), None
        try:
            if set(envelope) != {"version", "request_id", "request"} or envelope["version"] != 1 or type(envelope["version"]) is not int:
                raise ValueError("Unsupported broker envelope")
            operation_id = ipc.request_id(envelope["request_id"])
            identity = peer.validate()
            if identity.uid != self.owner_uid:
                raise PermissionError("Peer account is not the configured owner")
            request = envelope["request"]
            if not isinstance(request, dict) or set(request) != {"action", "parameters"}:
                raise ValueError("Only typed action/parameters accepted")
            prepared = ActionRegistry(actor_uid=identity.uid).prepare(request["action"], request["parameters"])
            if prepared.contract.identifier not in ADMIN:
                raise ValueError("Only bounded service mutations are broker actions")
            # Persistent admission precedes authentication or dispatch; never retry an ID.
            self.store.put("broker_request", operation_id, {"uid": identity.uid, "state": "admitted"}, replace=False, limit=10000)
            system = self.system_factory(peer)
            service = BrokerService(operation_id, request, peer, self.owner_uid, self.services, system,
                                    self.authorizer_factory(system), self.audit)
            result = service.run(request)
            self.store.put("broker_request", operation_id, asdict(result), limit=10000)
            return asdict(result)
        except Exception as exc:
            # No exception exposes authentication output, credentials or executable data.
            result = (OperationResult(operation_id, "broker_record_failed", "Dispatch result could not be persisted; review correlated root audit", executed=result.executed, verified=result.verified, audit_complete=False)
                      if result is not None else OperationResult(operation_id, "broker_denied", f"Broker admission/replay refused: {type(exc).__name__}", audit_complete=False))
            try:
                self.audit.append({"operation_id": operation_id, "phase": "result", "status": result.status, "fingerprint": "", "details": {"error_type": type(exc).__name__}})
                if result.status != "broker_record_failed":
                    result = OperationResult(operation_id, result.status, result.reason)
            except Exception:
                pass
            return asdict(result)


class BrokerClient:
    def __init__(self, path="/run/linxai/broker.sock"):
        self.path = path

    def run(self, request, *, operation_id=None):
        from uuid import uuid4
        operation_id = operation_id or str(uuid4())
        try:
            info = Path(self.path).lstat()
            SupervisedLinuxAdapter()._directories(Path(self.path).parent, 0)
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
                raise PermissionError("Untrusted broker socket")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(160)
                sock.connect(self.path)
                if ipc.credentials(sock)[1] != 0:
                    raise PermissionError("Broker peer is not root")
                ipc.send(sock, {"version": 1, "request_id": operation_id, "request": request})
                value = ipc.receive(sock, timeout=160)
            if value.get("operation_id") != operation_id:
                raise ValueError("Uncorrelated broker response")
            return OperationResult(**value)
        except Exception:
            return OperationResult(operation_id, "authentication_authorization_required", "Trusted broker unavailable or response unconfirmed; do not automatically retry", executed=None, audit_complete=False)


def main():
    # Only broker_entry.py in an immutable root-owned bundle may call this as root.
    if os.getuid() != 0 or os.geteuid() != 0:
        raise PermissionError("Broker requires protected root deployment")
    from broker_entry import verify_bundle
    verify_bundle(Path(__file__).absolute().parent.parent)
    config_path = Path("/etc/linxai/broker.json")
    system = SupervisedLinuxAdapter()
    system._directories(config_path.parent, 0)
    info = config_path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError("Unsafe broker configuration")
    config = json.loads(config_path.read_text())
    if set(config) != {"owner_uid", "services"}:
        raise ValueError("Unknown broker configuration fields")
    broker = Broker(config["owner_uid"], config["services"], Store("/var/lib/linxai-broker/state.sqlite", uid=0),
                    RootAudit("/var/lib/linxai-broker/audit.jsonl"))
    path = Path("/run/linxai/broker.sock")
    system._directories(path.parent, 0)
    slots = threading.BoundedSemaphore(4)
    def handle(conn):
        with conn:
            try:
                conn.settimeout(5)
                peer = Peer.read(conn)
                if peer.uid != broker.owner_uid:
                    raise PermissionError("Wrong owner")
                envelope = ipc.receive(conn)
                conn.settimeout(160)
                ipc.send(conn, broker.handle(peer, envelope))
            except Exception:
                pass  # Malformed/disconnected peers never reach dispatch.
            finally:
                slots.release()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        # A stale socket requires an operator check; never unlink an unknown entry.
        server.bind(str(path))
        path.chmod(0o666)
        server.listen(8)
        try:
            while True:
                conn, _ = server.accept()
                if not slots.acquire(blocking=False):
                    conn.close()
                    continue
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
        finally:
            path.unlink(missing_ok=True)
