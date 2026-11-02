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


class Agent:
    def __init__(self, state, workspace=None, *, model=None, broker=None):
        system = SupervisedLinuxAdapter()
        identity = system.resolve_identity()
        if not identity.ordinary():
            raise PermissionError("Agent requires an ordinary Linux account")
        self.uid, self.state = identity.uid, Path(state).absolute()
        self.store = Store(self.state / "application.sqlite")
        self.registry = ActionRegistry(workspace)
        self.planner = Planner(self.registry, model)
        self.audit = JsonlAudit(self.state / "operations.jsonl")
        def service(event):
            adapter = SupervisedLinuxAdapter()
            adapter.cancel_event = event
            return OperationService(self.registry, adapter, LocalPolicy(self.uid), self.audit)
        self.jobs = Jobs(self.store, self.registry, self.uid, service, broker or BrokerClient())

    def handle(self, uid, request):
        if uid != self.uid:
            raise PermissionError("Wrong API peer")
        if not isinstance(request, dict) or request.get("version") != 1 or type(request.get("version")) is not int:
            raise ValueError("API version 1 required")
        method = request.get("method")
        fields = {"preview": {"text"}, "confirm": {"id", "digest"}, "cancel": {"id"}, "reconcile": {"id"},
                  "jobs": set(), "job": {"id"}, "status": set(), "activity": set(), "security": set()}
        if method not in fields or set(request) != {"version", "method"} | fields[method]:
            raise ValueError("Unsupported API request or authority fields")
        if method == "preview":
            history = [{"text": row.get("text", ""), "plan": row.get("plan", {})} for row in reversed(self.store.list("job", 5))]
            typed, plan = self.planner.propose(request["text"], history)
            return self.jobs.preview(typed, text=request["text"], plan=plan)
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
                return {"status": status, "incidents": security.list("incident", 20), "enforcement": "Entry observations do not prove prevention"}
            finally:
                security.close()
        return {"uid": self.uid, "worker_degraded": self.jobs.degraded, "workspace": self.registry.permitted_workspace, "queue": self.jobs.queue.qsize(),
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
