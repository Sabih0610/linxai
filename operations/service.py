"""Shared local operation lifecycle. Registry declarations are never approvals."""
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import secrets
import threading
import time
from datetime import datetime, timezone
from uuid import uuid4

from .registry import ActionError, ActionRegistry, PreparedAction, Privilege, Requirement


@dataclass(frozen=True)
class Identity:
    uid: int
    euid: int
    name: str

    def ordinary(self):
        return (type(self.uid) is int and type(self.euid) is int and self.uid > 0
                and self.euid == self.uid and isinstance(self.name, str) and bool(self.name))


@dataclass(frozen=True)
class Observation:
    operation_id: str
    requirement: Requirement
    ok: bool
    reason: str
    evidence: str = ""


@dataclass(frozen=True)
class Execution:
    operation_id: str
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    started: bool | None = True
    error: str = ""


@dataclass(frozen=True)
class Operation:
    operation_id: str
    identity: Identity
    request_json: str
    prepared: PreparedAction


def fingerprint(operation: Operation) -> str:
    p = operation.prepared
    payload = {
        "version": 1, "operation_id": operation.operation_id,
        "identity": asdict(operation.identity), "request": operation.request_json,
        "action": p.contract.identifier, "privilege": p.contract.privilege.value,
        "timeout_s": p.contract.timeout_s, "recovery": p.contract.recovery_supported,
        "parameters": asdict(p.parameters), "argv": p.argv,
        "stdin_sha256": hashlib.sha256(p.stdin).hexdigest(),
        "stdin_bytes": len(p.stdin), "checks": [asdict(c) for c in p.mandatory_checks],
        "execution_supported": p.execution_supported,
        "postconditions": [asdict(c) for c in p.postconditions],
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class Approval:
    operation: Operation
    token: str


@dataclass(frozen=True)
class OperationResult:
    operation_id: str
    status: str
    reason: str
    fingerprint: str = ""
    executed: bool | None = False
    verified: bool = False
    stdout: str = ""
    stderr: str = ""
    recovery: str = "unsupported"
    audit_complete: bool = True


@dataclass(frozen=True)
class LocalPolicy:
    """Backend-owned local account/action allowlist, independent of client claims."""
    owner_uid: int
    allowed_actions: frozenset[str] = frozenset({
        "disk.usage", "memory.usage", "ports.listen", "service.status",
        "file.create", "directory.create",
    })

    def allows(self, identity: Identity, action: str) -> bool:
        return identity.ordinary() and identity.uid == self.owner_uid and action in self.allowed_actions


@dataclass(frozen=True)
class _Pending:
    operation: Operation
    digest: str
    observations: tuple[Observation, ...]
    expires: float


class _Stop(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status, self.reason = status, reason


class OperationService:
    """In-process API for local CLI/desktop callers, not an authenticated IPC server.

    system, policy and audit are trusted server dependencies, never request fields.
    run() is the normal entry; prepare()/execute() permit reviewed delayed dispatch.
    """
    def __init__(self, registry: ActionRegistry, system, policy: LocalPolicy, audit,
                 *, clock=time.monotonic, approval_ttl_s=30.0, validation_timeout_s=5.0):
        if not 0 < approval_ttl_s <= 60 or not 0 < validation_timeout_s <= 30:
            raise ValueError("invalid server deadline configuration")
        self.registry, self.system, self.policy, self.audit = registry, system, policy, audit
        self.clock, self.ttl, self.validation_timeout = clock, approval_ttl_s, validation_timeout_s
        self._pending = {}
        self._lock = threading.Lock()

    def _emit(self, op_id, phase, status, digest="", **details):
        try:
            self.audit.append({"operation_id": op_id, "phase": phase, "status": status,
                               "fingerprint": digest, "timestamp": datetime.now(timezone.utc).isoformat(),
                               "details": details})
        except Exception as exc:
            raise _Stop("audit_failed", f"Required {phase} audit write failed: {exc}") from exc

    def _finish(self, op_id, status, reason, digest="", execution=None, verified=False):
        result = OperationResult(op_id, status, reason, digest,
                                 execution.started if execution else False, verified,
                                 execution.stdout if execution else "", execution.stderr if execution else "",
                                 audit_complete=status != "audit_failed")
        try:
            self._emit(op_id, "result", status, digest, reason=reason, executed=result.executed,
                       verified=verified, recovery=result.recovery)
        except Exception as exc:
            return OperationResult(op_id, "audit_failed", f"{status}: {reason}; result audit failed: {exc}",
                                   digest, result.executed, verified, result.stdout, result.stderr,
                                   audit_complete=False)
        return result

    def _identity(self):
        try:
            identity = self.system.resolve_identity()
        except Exception as exc:
            raise _Stop("identity_unavailable", str(exc)) from exc
        if not isinstance(identity, Identity) or not identity.ordinary():
            raise _Stop("identity_denied", "Run as an ordinary account without sudo, root or setuid identity")
        return identity

    def _authorize(self, identity, prepared):
        # This gate is unconditional, even if a custom policy mistakenly allows admin.
        if prepared.contract.privilege is Privilege.AUTHENTICATED_ADMIN:
            raise _Stop("authentication_authorization_required", "Trusted privilege broker is unavailable; administrative actions cannot execute")
        if self.policy.allows(identity, prepared.contract.identifier) is not True:
            raise _Stop("authorization_denied", "Account/action is not allowed by the independent operation policy")

    def _observations(self, operation, phase, execution=None):
        requirements = (operation.prepared.mandatory_checks if phase == "validation"
                        else operation.prepared.postconditions)
        digest = fingerprint(operation)
        if not requirements:
            raise _Stop("validation_failed", "Required observation list is empty")
        deadline = self.clock() + self.validation_timeout
        observations = []
        for required in requirements:
            if self.clock() >= deadline:
                raise _Stop(f"{phase}_failed", "Observation budget expired before completion")
            try:
                if phase == "validation":
                    observed = self.system.check(operation.operation_id, required, operation.identity)
                else:
                    observed = self.system.verify(operation.operation_id, required,
                                                  operation.prepared, execution, operation.identity)
            except Exception as exc:
                observed = Observation(operation.operation_id, required, False, f"Observation failed: {exc}")
            valid = (isinstance(observed, Observation) and observed.operation_id == operation.operation_id
                     and observed.requirement == required and type(observed.ok) is bool
                     and isinstance(observed.reason, str) and isinstance(observed.evidence, str))
            passed = valid and observed.ok and self.clock() < deadline
            self._emit(operation.operation_id, phase, "passed" if passed else "failed", digest,
                       requirement=required.identifier,
                       reason=observed.reason if valid else "Missing, malformed or uncorrelated observation",
                       evidence_sha256=hashlib.sha256(observed.evidence.encode()).hexdigest() if valid else "")
            if not passed:
                raise _Stop(f"{phase}_failed", f"Required {required.identifier} did not pass completely")
            observations.append(observed)
        return tuple(observations)

    def prepare(self, request: dict) -> Approval | OperationResult:
        op_id = str(uuid4())
        digest = ""
        try:
            self._emit(op_id, "received", "pending")
            if not isinstance(request, dict) or set(request) != {"action", "parameters"} or not isinstance(request["parameters"], dict):
                raise _Stop("invalid_request", "Expected only action and a parameters object; client identity/approval claims are forbidden")
            # Snapshot the JSON envelope and validate using the existing registry.
            request_json = json.dumps(request, sort_keys=True, separators=(",", ":"), allow_nan=False)
            snapshot = json.loads(request_json)
            preliminary = self.registry.prepare(snapshot["action"], snapshot["parameters"])
            identity = self._identity()
            self._emit(op_id, "identity", "resolved", uid=identity.uid, euid=identity.euid)
            self._authorize(identity, preliminary)
            self._emit(op_id, "authorization", "allowed", action=preliminary.contract.identifier, uid=identity.uid)
            final = self.registry.prepare(snapshot["action"], snapshot["parameters"])
            operation = Operation(op_id, identity, request_json, final)
            digest = fingerprint(operation)
            self._emit(op_id, "constructed", "ready", digest, action=final.contract.identifier)
            observations = self._observations(operation, "validation")
            token = secrets.token_urlsafe(32)
            self._emit(op_id, "approval", "issued", digest)
            with self._lock:
                # Expired approvals are removed; tokens never survive process restart.
                self._pending = {k: v for k, v in self._pending.items() if v.expires > self.clock()}
                self._pending[token] = _Pending(operation, digest, observations, self.clock() + self.ttl)
            return Approval(operation, token)
        except _Stop as exc:
            return self._finish(op_id, exc.status, exc.reason, digest)
        except (ActionError, TypeError, ValueError) as exc:
            return self._finish(op_id, "invalid_request", str(exc), digest)
        except Exception as exc:
            return self._finish(op_id, "preparation_failed", str(exc), digest)

    def execute(self, approval: Approval) -> OperationResult:
        execution = None
        # Only server-issued tokens are recognized. Always use the server ID for audit.
        with self._lock:
            pending = (self._pending.pop(approval.token, None)
                       if isinstance(approval, Approval) and isinstance(approval.token, str) else None)
        if pending is None:
            return self._finish(str(uuid4()), "approval_invalid", "Unknown or already consumed approval")
        operation = pending.operation
        op_id, digest = operation.operation_id, pending.digest
        try:
            if self.clock() >= pending.expires:
                raise _Stop("approval_expired", "Approval expired; revalidation is required")
            if not hmac.compare_digest(fingerprint(approval.operation), digest):
                raise _Stop("approval_invalid", "Approved operation was altered; revalidation is required")
            if not hmac.compare_digest(fingerprint(operation), digest):
                raise _Stop("approval_invalid", "Stored operation changed; revalidation is required")
            identity = self._identity()
            if identity != operation.identity:
                raise _Stop("identity_denied", "Requesting identity changed since validation")
            self._authorize(identity, operation.prepared)
            snapshot = json.loads(operation.request_json)
            fresh = self._observations(operation, "validation")
            if fresh != pending.observations:
                raise _Stop("state_changed", "Required system state changed since approval; revalidation is required")
            reconstructed = self.registry.prepare(snapshot["action"], snapshot["parameters"])
            if reconstructed != operation.prepared or fingerprint(operation) != digest:
                raise _Stop("approval_invalid", "Operation/registry changed; revalidation is required")
            self._authorize(identity, operation.prepared)
            self._emit(op_id, "execution", "starting", digest, argv=list(operation.prepared.argv[:3]))
            if self.clock() >= pending.expires:
                raise _Stop("approval_expired", "Approval expired before dispatch; revalidation is required")
            try:
                returned = self.system.execute(op_id, operation.prepared, identity)
            except Exception as exc:
                execution = Execution(op_id, operation.prepared.argv, None, started=None,
                                      error=f"Execution adapter failed; side effects are unconfirmed: {exc}")
                raise _Stop("execution_failed", execution.error) from exc
            if (not isinstance(returned, Execution) or returned.operation_id != op_id
                    or returned.argv != operation.prepared.argv
                    or type(returned.started) is not bool
                    or not all(isinstance(value, str) for value in (returned.stdout, returned.stderr, returned.error))):
                execution = Execution(op_id, operation.prepared.argv, None, started=None, error="Execution state is unconfirmed")
                raise _Stop("execution_failed", "Adapter returned an uncorrelated execution result")
            execution = returned
            self._emit(op_id, "execution", "completed", digest, returncode=execution.returncode,
                       started=execution.started, error=execution.error)
            if not execution.started or execution.error or type(execution.returncode) is not int or execution.returncode != 0:
                raise _Stop("execution_failed", execution.error or f"Command exited {execution.returncode}")
            self._observations(operation, "verification", execution)
            return self._finish(op_id, "succeeded", "All required postconditions verified", digest, execution, True)
        except _Stop as exc:
            return self._finish(op_id, exc.status, exc.reason, digest, execution)
        except Exception as exc:
            return self._finish(op_id, "operation_failed", str(exc), digest, execution)

    def run(self, request: dict) -> OperationResult:
        prepared = self.prepare(request)
        return self.execute(prepared) if isinstance(prepared, Approval) else prepared
