"""Ordinary-user application API and durable jobs, independent of desktop lifetime."""
from dataclasses import asdict
import argparse
import json
import os
from pathlib import Path
import socket
import stat
import threading

from ai.local_planner import Planner
from . import ipc
from .audit import JsonlAudit
from .broker import BrokerClient
from .jobs import Jobs
from .registry import ActionRegistry
from .service import LocalPolicy, OperationService
from .store import Store
from .supervised import SupervisedLinuxAdapter
from .workflows import WorkflowSystem, assets


class Agent:
    def __init__(self, state, workspace=None, *, model=None, broker=None):
        system = SupervisedLinuxAdapter()
        identity = system.resolve_identity()
        if not identity.ordinary():
            raise PermissionError("Agent requires an ordinary Linux account")
        self.uid, self.state = identity.uid, Path(state).absolute()
        self.store = Store(self.state / "application.sqlite")
        self.registry = ActionRegistry(workspace, actor_uid=self.uid, assets_json=assets(self.state / "assets.json", self.uid))
        self.planner = Planner(self.registry, model)
        self.audit = JsonlAudit(self.state / "operations.jsonl")
        def service(event):
            adapter = WorkflowSystem()
            adapter.cancel_event = event
            return OperationService(self.registry, adapter, LocalPolicy(self.uid), self.audit)
        self.jobs = Jobs(self.store, self.registry, self.uid, service, broker or BrokerClient(),
                         incidents=self.recent_incidents, conflicts=self.analyze_conflicts)
        from security.response import Responses, ResponseWorker
        self.responses = Responses(self.registry, self.jobs, model)
        self.response_worker = ResponseWorker(lambda: Store(self.state / "security.sqlite"), self.responses)

    def explain(self, method, request):
        """Log viewer (requirement 61) and deterministic explain mode (62)."""
        from .explain import explain_anomaly, explain_incident, explain_job, tail_jsonl
        ledger = self.state / "operations.jsonl"
        if method == "logs":
            limit = request["limit"]
            if type(limit) is not int or not 1 <= limit <= 200:
                raise ValueError("limit must be 1..200")
            return {"records": tail_jsonl(ledger, limit), "incidents": (self.recent_incidents() or [])[:10]}
        key = str(request["id"])[:64]
        row = self.store.get("job", key)
        if row:
            audit = tail_jsonl(ledger, 200, operation_id=row.get("operation_id")) if row.get("operation_id") else []
            return {"kind": "job", "id": key, "explanation": explain_job(row, audit)}
        database = self.state / "security.sqlite"
        if database.exists():
            security = Store(database)
            try:
                incident, anomaly = security.get("incident", key), security.get("anomaly", key)
            finally:
                security.close()
            if incident:
                return {"kind": "incident", "id": key, "explanation": explain_incident(incident)}
            if anomaly:
                return {"kind": "anomaly", "id": key, "explanation": explain_anomaly(anomaly)}
        raise ValueError("No job, incident or anomaly with that id")

    @staticmethod
    def analyze_conflicts(action, parameters):
        from .conflicts import analyze
        return analyze(action, parameters)

    def recent_incidents(self):
        """Read-only incident snapshot for preview warnings; None if no monitor state."""
        database = self.state / "security.sqlite"
        if not database.exists():
            return None
        security = Store(database)
        try:
            return security.list("incident", 50)
        finally:
            security.close()

    def handle(self, uid, request):
        if uid != self.uid:
            raise PermissionError("Wrong API peer")
        if not isinstance(request, dict) or request.get("version") != 1 or type(request.get("version")) is not int:
            raise ValueError("API version 1 required")
        method = request.get("method")
        fields = {"preview": {"text"}, "confirm": {"id", "digest"}, "cancel": {"id"}, "reconcile": {"id"},
                  "jobs": set(), "job": {"id"}, "status": set(), "activity": set(), "security": set(), "propose_response": {"incident_id"}, "revoke_policy": {"policy_id"}, "typed_preview": {"request"}, "restore_job": {"id"}, "device_inspect": {"asset"}, "device_preview": {"asset","interface","enabled"},
                  "logs": {"limit"}, "explain": {"id"}}
        if method not in fields or set(request) != {"version", "method"} | fields[method]:
            raise ValueError("Unsupported API request or authority fields")
        if method in {"device_inspect","device_preview"}:
            service=self.jobs.service_factory(threading.Event())
            inspected=service.run({"action":"device.inspect","parameters":{"asset":request["asset"]}})
            if inspected.status!="succeeded" or not inspected.verified:raise ValueError("Device inspection failed: "+inspected.reason)
            if method=="device_inspect":return asdict(inspected)
            from uuid import uuid4
            typed={"action":"device.interface.set","parameters":{"asset":request["asset"],"interface":request["interface"],"enabled":request["enabled"],
                   "expected_revision":json.loads(inspected.stdout)["revision"],"transaction_id":str(uuid4())}}
            return self.jobs.preview(typed,text="Configured device interface change")
        if method == "typed_preview":
            typed=request["request"]
            if not isinstance(typed,dict) or set(typed)!={"action","parameters"}:raise ValueError("Only typed action and parameters")
            return self.jobs.preview(typed)
        if method == "restore_job":
            row=self.store.get("job",request["id"])
            proposal=(row or {}).get("result",{}).get("restoration")
            if not proposal:raise ValueError("No captured validated restoration is available")
            return self.jobs.preview(proposal,text="Restoration of job "+request["id"])
        if method == "propose_response":
            security = Store(self.state / "security.sqlite")
            try: incident = security.get("incident", request["incident_id"])
            finally: security.close()
            if not incident: raise ValueError("Unknown incident")
            return self.responses.propose(incident)
        if method == "revoke_policy":
            return self.jobs.preview({"action": "response.policy.revoke", "parameters": {"policy_id": request["policy_id"]}}, text="Revoke scoped policy")
        if method == "preview":
            history = [{"text": row.get("text", ""), "plan": row.get("plan", {}), "request": row.get("request")} for row in reversed(self.store.list("job", 5))]
            typed, plan = self.planner.propose(request["text"], history)
            return self.jobs.preview(typed, text=request["text"], plan=plan)
        if method in {"logs", "explain"}:
            return self.explain(method, request)
        if method == "confirm":
            return self.jobs.confirm(request["id"], request["digest"])
        if method == "reconcile":
            return self.jobs.reconcile(request["id"])
        if method == "cancel":
            return self.jobs.cancel(request["id"])
        if method == "job":
            row = self.store.get("job", request["id"])
            if row is None: raise ValueError("Unknown job")
            row["progress"] = self.store.get("progress", request["id"])
            return row
        if method in {"jobs", "activity"}:
            return {"jobs": [{"id": row["id"], "state": row["state"], "action": row["request"]["action"],
                              "operation_id": row.get("operation_id", ""), "updated": row["updated"]}
                             for row in self.store.list("job", 100)]}
        if method == "security":
            database = self.state / "security.sqlite"
            if not database.exists():
                return {"status": "not_connected", "reason": "Independent monitor has not recorded state", "incidents": []}
            security = Store(database)
            try:
                import time
                status = security.get("monitor", "status") or {"state": "unknown"}
                if time.time() - status.get("updated", 0) > 5: status["state"] = "stale"
                from security.policy_daemon import PolicyClient
                try: policies=PolicyClient().call("status")
                except Exception: policies={"state":"unavailable; no kernel enforcement acceptance inferred"}
                return {"status": status, "incidents": security.list("incident", 20), "anomalies": security.list("anomaly", 20), "policies": policies,
                        "enforcement": "Only independently qualified active policies assert scoped prevention"}
            finally:
                security.close()
        from security.face import FaceClient
        try:face=FaceClient().call("status")
        except Exception:face={"state":"unavailable; trusted OS password required"}
        return {"face":face,"uid": self.uid, "worker_degraded": self.jobs.degraded, "response": self.response_worker.health, "workspace": self.registry.permitted_workspace, "queue": self.jobs.queue.qsize(),
                "assets": {name:{"platform":asset["platform"]} for name,asset in json.loads(self.registry.assets_json).items()},
                "broker": "OS authorization required for administrative requests", "model": "local; contacted only on a planning request"}


class AgentClient:
    def __init__(self, path=None):
        self.path = Path(path or Path.home() / ".linxai/agent.sock")

    def call(self, method, **fields):
        uid = os.getuid()
        SupervisedLinuxAdapter()._directories(self.path.parent, uid, private_leaf=True)
        info = self.path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
            raise PermissionError("Untrusted application socket")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(40)
            sock.connect(str(self.path))
            if ipc.credentials(sock)[1] != uid:
                raise PermissionError("Wrong application peer")
            ipc.send(sock, {"version": 1, "method": method, **fields})
            value = ipc.receive(sock, timeout=40)
        if value.get("status") != "ok":
            raise ValueError(value.get("reason", "Application request failed"))
        return value["result"]


def serve(agent, path, stop=None):
    import fcntl
    path = Path(path)
    lock = os.open(path.parent / "agent.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    info = os.fstat(lock)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != agent.uid or info.st_nlink != 1 or info.st_mode & 0o077:
        os.close(lock)
        raise PermissionError("Unsafe agent lock")
    owns_socket = False
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.path.lexists(path):
            info = path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != agent.uid:
                raise PermissionError("Unknown socket entry; review before starting")
            path.unlink()  # Private directory + exclusive lifetime lock proves stale.
        agent.jobs.reconcile_restart()
        slots = threading.BoundedSemaphore(4)
        def handle(conn):
            with conn:
                try:
                    conn.settimeout(5)
                    uid = ipc.credentials(conn)[1]
                    if uid != agent.uid: raise PermissionError("Wrong peer")
                    request = ipc.receive(conn)
                    value = agent.handle(uid, request)
                    conn.settimeout(5)
                    ipc.send(conn, {"status": "ok", "result": value})
                except Exception as exc:
                    try:
                        ipc.send(conn, {"status": "error", "reason": f"{type(exc).__name__}: {str(exc)[:512]}"})
                    except Exception:
                        pass
                finally:
                    slots.release()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            owns_socket = True
            path.chmod(0o600)
            server.listen(8)
            server.settimeout(0.25)
            agent.jobs.start()
            agent.response_worker.thread.start()
            while not stop or not stop.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                if not slots.acquire(blocking=False):
                    conn.close()
                    continue
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
    finally:
        agent.response_worker.stop.set()
        agent.jobs.close()
        if owns_socket and path.exists() and stat.S_ISSOCK(path.lstat().st_mode) and path.lstat().st_uid == agent.uid:
            path.unlink()
        os.close(lock)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", default=str(Path.home() / ".linxai"))
    parser.add_argument("--workspace", help="Owner-configured private permitted workspace")
    args = parser.parse_args(argv)
    agent = Agent(args.state, args.workspace)
    serve(agent, Path(args.state) / "agent.sock")


if __name__ == "__main__":
    main()
