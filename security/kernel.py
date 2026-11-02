"""Native BCC LSM provider. Constructed only by the protected kernel daemon."""
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time
from uuid import uuid4

PROBE = """import errno,json,socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if len(sys.argv)>3 and sys.argv[3]=="udp" else socket.SOCK_STREAM);s.settimeout(1)
try:s.connect((sys.argv[1],int(sys.argv[2])));result=0
except OSError as e:result=e.errno
finally:s.close()
print(json.dumps({'errno':result}))
"""


class Kernel:
    real = True
    def __init__(self, store, owner_uid):
        if os.getuid() != 0 or os.geteuid() != 0: raise PermissionError("Protected root kernel provider required")
        if "bpf" not in Path("/sys/kernel/security/lsm").read_text().strip().split(","):
            raise RuntimeError("Active BPF LSM is unavailable; configuration flags alone are insufficient")
        from bcc import BPF
        self.store, self.owner_uid = store, owner_uid
        self.host = hashlib.sha256(Path("/etc/machine-id").read_bytes()).hexdigest()
        self.boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        source = Path(__file__).with_name("enforce.c").read_text()
        self.digest = hashlib.sha256(source.encode()).hexdigest()
        self.bpf = BPF(text=source)
        self.blocks, self.denied = self.bpf["blocks"], self.bpf["denied"]

    def now(self):
        return time.clock_gettime_ns(time.CLOCK_BOOTTIME)

    def key(self, policy):
        return self.blocks.Key(policy["uid"], struct.unpack("=I", socket.inet_aton(policy["address"]))[0], policy["port"], 0)

    def token(self, policy):
        from uuid import UUID
        return int(UUID(policy["id"])) & ((1 << 64)-1) or 1

    def qualified(self):
        row = self.store.get("qualification", self.boot)
        return bool(row and row.get("program") == self.digest and row.get("origin") == "actual_kernel_probe" and row.get("passed") is True)

    def contains(self, policy):
        try:
            value = self.blocks[self.key(policy)]
            return value.token == self.token(policy) and value.expires_ns == policy["expires_ns"]
        except KeyError:
            return False

    def scope_available(self, uid, address, port):
        try:
            value = self.blocks[self.key({"uid":uid,"address":address,"port":port})]
            return self.now() >= value.expires_ns
        except KeyError:
            return True

    def install(self, policy):
        key = self.key(policy)
        try:
            value = self.blocks[key]
            if self.now() < value.expires_ns and value.token != self.token(policy):
                raise PermissionError("An existing kernel policy owns this exact scope")
        except KeyError:
            pass
        self.denied[key] = self.denied.Leaf(0)
        self.blocks[key] = self.blocks.Leaf(policy["expires_ns"], self.token(policy))
        if not self.contains(policy): raise RuntimeError("Kernel map readback failed")

    def remove(self, policy):
        if self.contains(policy):
            del self.blocks[self.key(policy)]
            try: del self.denied[self.key(policy)]
            except KeyError: pass

    def count(self, policy):
        try: return self.denied[self.key(policy)].value
        except KeyError: return 0

    def probe(self, uid, address, port, protocol="tcp"):
        import pwd
        account = pwd.getpwuid(uid)
        result = subprocess.run(["/usr/bin/python3", "-I", "-c", PROBE, address, str(port), protocol],
                                shell=False, user=uid, group=account.pw_gid, extra_groups=[], cwd="/",
                                env={"PATH":"/usr/bin:/bin","LANG":"C"}, capture_output=True, timeout=3)
        if result.returncode != 0 or len(result.stdout) > 1024: raise RuntimeError("Native probe failed")
        return json.loads(result.stdout)["errno"]

    def verify_denial(self, policy):
        import errno
        before = self.count(policy)
        outcome = self.probe(policy["uid"], policy["address"], policy["port"])
        return outcome == errno.EPERM and self.count(policy) > before

    def qualify(self):
        # Root-only explicit target lab; all sockets are newly created loopback fixtures.
        sockets = []
        policy = None
        try:
            for address in ("127.0.0.1", "127.0.0.1"):
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.bind((address, 0)); server.listen(8); sockets.append(server)
            port, near_port = sockets[0].getsockname()[1], sockets[1].getsockname()[1]
            near = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            near.bind(("127.0.0.2", port)); near.listen(8); sockets.append(near)
            policy = {"id":str(uuid4()),"uid":self.owner_uid,"address":"127.0.0.1","port":port,
                      "expires_ns":self.now()+10_000_000_000}
            if self.probe(self.owner_uid,"127.0.0.1",port) != 0: raise RuntimeError("Baseline fixture unavailable")
            self.install(policy)
            if not self.verify_denial(policy): raise RuntimeError("Actual scoped kernel denial not observed")
            if self.probe(0,"127.0.0.1",port) != 0: raise RuntimeError("Benign UID near-match blocked")
            if self.probe(self.owner_uid,"127.0.0.1",near_port) != 0: raise RuntimeError("Benign port near-match blocked")
            if self.probe(self.owner_uid,"127.0.0.2",port) != 0: raise RuntimeError("Benign address near-match blocked")
            if self.probe(self.owner_uid,"127.0.0.1",port,"udp") != 0: raise RuntimeError("Benign UDP near-match blocked")
            self.remove(policy)
            if self.probe(self.owner_uid,"127.0.0.1",port) != 0: raise RuntimeError("Revocation did not restore fixture")
            policy["expires_ns"] = self.now()+20_000_000
            self.install(policy)
            time.sleep(0.05)
            if self.probe(self.owner_uid,"127.0.0.1",port) != 0: raise RuntimeError("Kernel expiry did not allow fixture")
            result = {"passed":True,"origin":"actual_kernel_probe","program":self.digest,"boot":self.boot,
                      "cases":["deny","uid-near-match","port-near-match","address-near-match","udp-near-match","revoke","expiry"]}
            self.store.put("qualification", self.boot, result)
            return result
        finally:
            if policy: self.remove(policy)
            for server in sockets: server.close()
