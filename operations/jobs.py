"""Durable bounded jobs; no automatic replay after uncertain dispatch."""
from dataclasses import asdict
import hashlib
import json
import queue
import threading
import time
from uuid import uuid4

from .registry import Privilege
from .service import Approval

READS = frozenset({"disk.usage", "memory.usage", "ports.listen", "service.status", "process.list", "resource.forecast"})
TERMINAL = frozenset({"succeeded", "failed", "cancelled", "unknown", "review_required", "interrupted_before_dispatch"})


def digest(request, workspace, uid, prepared):
    # Bind the resolved backend target, fixed program/argv, server privilege,
    # mandatory checks and postconditions as well as the wire request.
    contract = prepared.contract
    binding = {"action": contract.identifier, "privilege": contract.privilege.value,
               "timeout": contract.timeout_s, "recovery": contract.recovery_supported,
               "parameters": asdict(prepared.parameters), "argv": prepared.argv,
               "stdin_sha256": hashlib.sha256(prepared.stdin).hexdigest(),
               "checks": [asdict(check) for check in prepared.mandatory_checks],
               "postconditions": [asdict(check) for check in prepared.postconditions]}
    return hashlib.sha256(json.dumps({"schema": 2, "request": request, "workspace": workspace,
        "uid": uid, "prepared": binding}, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


class Jobs:
    def __init__(self, store, registry, uid, service_factory, broker, *, clock=time.time, incidents=None, conflicts=None):
        self.store, self.registry, self.uid = store, registry, uid
        self.service_factory, self.broker, self.clock = service_factory, broker, clock
        # Optional read-only source of recent monitor incidents (requirement 41).
        self.incidents = incidents
        # Optional read-only conflict analysis (requirements 19-21): (action, parameters) -> dict.
        self.conflicts = conflicts
        self.queue, self.lock = queue.Queue(maxsize=128), threading.RLock()
        self.degraded = None
        self.stop_event, self.cancels = threading.Event(), {}
        self.worker = threading.Thread(target=self._loop, daemon=True, name="linxai-jobs")

    def reconcile_restart(self):
        # Recovery never replays a mutation whose execution may have started.
        for row in self.store.list("job", 1000):
            if row["state"] in {"dispatching", "cancelling"}:
                row["state"] = "unknown"
                row["recovery"] = "Read-only reconciliation required; never auto-retry"
                self.save(row)
            elif row["state"] in {"preview", "queued", "validating", "approved"}:
                row["state"] = "interrupted_before_dispatch"
                self.save(row)

    def save(self, row):
        row["updated"] = self.clock()
        self.store.put("job", row["id"], row)

    def preview(self, request, *, text="", plan=None):
        prepared = self.registry.prepare(request["action"], request["parameters"])
        request = json.loads(json.dumps(request, allow_nan=False))
        target = {"account_uid": self.uid, "workspace": self.registry.permitted_workspace}
        asset_name = getattr(prepared.parameters, "asset", None)
        if asset_name is not None:
            asset = json.loads(self.registry.assets_json)[asset_name]
            target.update(asset=asset_name, **{key: asset[key] for key in ("platform", "host", "port", "username", "expected_uid", "path") if key in asset})
        row = {"id": str(uuid4()), "uid": self.uid, "state": "preview", "request": request, "target": target,
               "digest": digest(request, self.registry.permitted_workspace, self.uid, prepared),
               "plan": {key: plan[key] for key in ("intent", "target", "port", "pre_conditions") if plan and key in plan},
               "expires": self.clock() + 60, "created": self.clock(), "text": text[:8192],
               "privilege": prepared.contract.privilege.value,
               "mandatory_checks": [r.identifier for r in prepared.mandatory_checks],
               "postconditions": [r.identifier for r in prepared.postconditions], "recovery": "unsupported"}
        row.update(self._security_context(prepared))
        if self.conflicts is not None:
            try:
                row["conflicts"] = self.conflicts(prepared.contract.identifier, request["parameters"])
            except Exception as exc:
                row["conflicts"] = {"decision": "warn", "findings": [{"level": "warn", "code": "analysis_unavailable",
                                                                     "detail": type(exc).__name__}], "alternatives": []}
        self.save(row)
        return row

    def _security_context(self, prepared):
        # Advisory only: not part of the digest, never blocks or authorizes.
        if self.incidents is None:
            return {"security_context": "not_configured", "security_warnings": []}
        from security.warnings import preview_warnings
        try:
            incidents = self.incidents()
        except Exception:
            return {"security_context": "unavailable", "security_warnings": []}
        if incidents is None:
            return {"security_context": "monitor_not_connected", "security_warnings": []}
        warnings = preview_warnings(incidents, action=prepared.contract.identifier,
                                    privilege=prepared.contract.privilege.value, now=self.clock())
        return {"security_context": "checked", "security_warnings": warnings}

    def confirm(self, key, approved_digest):
        with self.lock:
            if self.degraded or self.stop_event.is_set():
                raise ValueError("Job worker unavailable; admission disabled")
            row = self.store.get("job", key)
            if not row or row["state"] != "preview" or row["expires"] <= self.clock():
                raise ValueError("Preview expired, consumed or absent")
            prepared = self.registry.prepare(row["request"]["action"], row["request"]["parameters"])
            expected = digest(row["request"], self.registry.permitted_workspace, self.uid, prepared)
            if approved_digest != row["digest"] or expected != row["digest"] or row["uid"] != self.uid:
                raise PermissionError("Preview action/parameters/target changed; preview again")
            if (row.get("conflicts") or {}).get("decision") == "block":
                raise ValueError("Preview analysis found a certain failure; review its findings/alternatives and preview again")
            if self.queue.full():
                raise ValueError("Job admission queue is full")
            row["state"] = "queued"
            self.save(row)
            self.queue.put_nowait(key)
            return row

    def cancel(self, key):
        with self.lock:
            row = self.store.get("job", key)
            if not row:
                raise ValueError("Unknown job")
            if row["state"] in {"preview", "queued"}:
                row["state"] = "cancelled"
                self.save(row)
                return row
            if row["state"] in {"validating", "approved", "dispatching"} and row["request"]["action"] in READS and key in self.cancels:
                self.cancels[key].set()
                row["state"] = "cancelling"
                self.save(row)
                return row
            raise ValueError("This phase/action cannot be safely cancelled; inspect its result")

    def process(self, key):
        with self.lock:
            row = self.store.get("job", key)
            if not row or row["state"] != "queued":
                return
            event = self.cancels[key] = threading.Event()
            row["state"] = "validating"
            self.save(row)
        result, dispatching = None, False
        try:
            prepared = self.registry.prepare(row["request"]["action"], row["request"]["parameters"])
            if row["uid"] != self.uid or digest(row["request"], self.registry.permitted_workspace, self.uid, prepared) != row["digest"]:
                raise PermissionError("Confirmed request or resolved target changed; preview again")
            if prepared.contract.privilege is Privilege.AUTHENTICATED_ADMIN:
                row.update(state="dispatching", operation_id=key)
                self.save(row)  # Durable intent before sending a privileged request.
                dispatching = True
                result = self.broker.run(row["request"], operation_id=key)
            else:
                service = self.service_factory(event)
                service_prepared = service.registry.prepare(row["request"]["action"], row["request"]["parameters"])
                if digest(row["request"], service.registry.permitted_workspace, self.uid, service_prepared) != row["digest"]:
                    raise PermissionError("Execution service target differs from confirmed preview")
                service.system.progress = lambda op_id, stream, tail: self.store.put("progress", key, {"operation_id": op_id, "stream": stream, "tail": tail})
                approval = service.prepare(row["request"])
                if isinstance(approval, Approval):
                    row.update(state="approved", operation_id=approval.operation.operation_id)
                    self.save(row)
                    row["state"] = "dispatching"
                    self.save(row)
                    dispatching = True
                    result = service.execute(approval)
                else:
                    result = approval
            data = asdict(result)
            for name in ("stdout", "stderr"):
                data[name] = data[name][:16384]
            state = "succeeded" if result.status == "succeeded" else "failed"
            if result.executed is None:
                state = "unknown"
            elif result.executed and not result.verified and row["request"]["action"] not in READS:
                state = "review_required"
            elif event.is_set() and "Cancelled" in result.reason:
                state = "cancelled"
            row.update(state=state, result=data, operation_id=result.operation_id)
            self.save(row)
        except Exception as exc:
            row.update(state="unknown" if dispatching else "failed", error=type(exc).__name__, recovery="review_required" if dispatching else "unsupported")
            self.save(row)
        finally:
            with self.lock:
                self.cancels.pop(key, None)

    def reconcile(self, key):
        row = self.store.get("job", key)
        if not row or row["state"] not in {"unknown", "review_required"}:
            raise ValueError("Only uncertain jobs need reconciliation")
        service = self.service_factory(threading.Event())
        request = row["request"]
        if request["action"].startswith("service."):
            result = service.run({"action": "service.status", "parameters": {"service": request["parameters"]["service"]}})
            observation = {"current_state": asdict(result), "original_dispatch": "unknown; this read does not prove the original execution"}
        elif request["action"] in {"file.create", "directory.create"}:
            from .service import Execution
            prepared = self.registry.prepare(request["action"], request["parameters"])
            identity = service.system.resolve_identity()
            # These are filesystem observations, not fabricated command-exit evidence.
            observed = [service.system.verify(str(uuid4()), required, prepared,
                        Execution("not-dispatched", prepared.argv, None, started=False), identity)
                        for required in prepared.postconditions if required.identifier != "exit_code"]
            observation = {"current_postconditions_match": all(o.ok for o in observed),
                           "checks": [asdict(o) for o in observed], "original_dispatch": "unknown"}
        else:
            raise ValueError("No validated read-only reconciliation for this action")
        row["reconciliation"] = observation
        self.save(row)
        return row

    def _loop(self):
        while not self.stop_event.is_set():
            try:
                key = self.queue.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                self.process(key)
            except Exception as exc:
                self.degraded = type(exc).__name__
                self.stop_event.set()
            finally:
                self.queue.task_done()

    def start(self):
        self.worker.start()

    def close(self):
        self.stop_event.set()
        if self.worker.is_alive():
            self.worker.join(timeout=2)
