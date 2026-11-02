"""Protected independently supervised policy lifecycle and root-only mutation API."""
import json
import os
from pathlib import Path
import signal
import socket
import stat
import threading

from operations import ipc
from operations.broker import RootAudit
from operations.store import Store
from operations.supervised import SupervisedLinuxAdapter
from .kernel import Kernel
from .policy import Authority
from .sensor import SensorClient


class PolicyClient:
    def __init__(self, path="/run/linxai-policy/control.sock"):
        self.path = Path(path)
    def call(self, method, **fields):
        SupervisedLinuxAdapter()._directories(self.path.parent, 0)
        info = self.path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0: raise PermissionError("Untrusted policy socket")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(15);sock.connect(str(self.path))
            if ipc.credentials(sock)[1] != 0: raise PermissionError("Untrusted policy peer")
            ipc.send(sock,{"version":1,"method":method,**fields})
            result=ipc.receive(sock,timeout=15)
        if result.get("status")!="ok": raise PermissionError(result.get("reason","Policy request failed"))
        return result["result"]


def handle(authority, uid, request, audit):
    if not isinstance(request,dict) or request.get("version")!=1 or type(request.get("version")) is not int:
        raise ValueError("Policy protocol version required")
    method=request.get("method")
    fields={"status":set(),"preview":{"actor_uid","parameters","revoke"},
            "apply":{"actor_uid","parameters","operation_id"},"revoke":{"actor_uid","parameters","operation_id"},
            "verify":{"policy_id"},"qualify":set(),"automatic":{"actor_uid","parameters","operation_id","digest"}}
    if method not in fields or set(request)!={"version","method"}|fields[method]: raise ValueError("Unsupported policy request")
    if uid not in {0,authority.config["owner_uid"]}: raise PermissionError("Wrong policy peer")
    if method=="status":
        return {"owner_uid":authority.config["owner_uid"],"qualified":authority.kernel.qualified(),
                "auto_enabled":authority.config["auto_enabled"],"policies":authority.store.list("policy",32)}
    if uid!=0: raise PermissionError("Only the independently authorized root broker may request mutation/evidence checks")
    if method=="preview":
        if type(request["revoke"]) is not bool: raise ValueError("Invalid revocation selector")
        return authority.preview(request["actor_uid"],request["parameters"],revoke=request["revoke"])
    if method=="automatic":return authority.automatic(request["actor_uid"],request["parameters"],request["operation_id"],request["digest"])
    if method=="verify": return authority.verify(request["policy_id"])
    if method=="qualify": return authority.kernel.qualify()
    operation_id=ipc.request_id(request["operation_id"])
    audit.append({"operation_id":operation_id,"phase":"policy","status":"starting","fingerprint":"",
                  "details":{"method":method,"policy_id":request["parameters"].get("policy_id")}})
    result=(authority.apply(request["actor_uid"],request["parameters"],operation_id) if method=="apply" else
            authority.revoke(request["actor_uid"],request["parameters"],operation_id))
    audit.append({"operation_id":operation_id,"phase":"policy","status":"completed","fingerprint":"",
                  "details":{"method":method,"policy_id":result["id"],"state":result["state"]}})
    return result


def main():
    from broker_entry import verify_bundle
    verify_bundle(Path(__file__).absolute().parent.parent)
    path=Path("/etc/linxai/response.json")
    system=SupervisedLinuxAdapter();system._directories(path.parent,0)
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022: raise PermissionError("Unsafe response configuration")
    config=json.loads(path.read_text())
    store=Store("/var/lib/linxai-policy/policies.sqlite",uid=0)
    stop=threading.Event();signal.signal(signal.SIGTERM,lambda *_:stop.set())
    socket_path=Path("/run/linxai-policy/control.sock");system._directories(socket_path.parent,0)
    import fcntl
    lock=os.open(socket_path.parent/"policy.lock",os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if os.path.lexists(socket_path):
        info=socket_path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0: raise PermissionError("Unknown policy socket entry")
        socket_path.unlink()
    kernel=Kernel(store,config["owner_uid"])
    source=SensorClient()
    authority=Authority(config,store,kernel,lambda key:source.call("event",id=key)["event"])
    audit=RootAudit("/var/lib/linxai-policy/audit.jsonl")
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(str(socket_path));socket_path.chmod(0o666);server.listen(4);server.settimeout(0.25)
        try:
            while not stop.is_set():
                authority.tick()
                try:conn,_=server.accept()
                except socket.timeout:continue
                with conn:
                    try:
                        conn.settimeout(2);uid=ipc.credentials(conn)[1]
                        if uid not in {0,config["owner_uid"]}:raise PermissionError("Wrong policy peer")
                        request=ipc.receive(conn,timeout=2)
                        result=handle(authority,uid,request,audit)
                        ipc.send(conn,{"status":"ok","result":result})
                    except Exception as exc:
                        try:ipc.send(conn,{"status":"error","reason":type(exc).__name__})
                        except Exception:pass
        finally:
            socket_path.unlink(missing_ok=True);os.close(lock)
