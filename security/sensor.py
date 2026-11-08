"""Protected root sensor transport. BCC is imported only in explicit sensor startup."""
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import queue
import signal
import socket
import stat
import threading
import time
from uuid import uuid4

from operations import ipc
from operations.broker import Peer
from operations.store import Store
from operations.supervised import SupervisedLinuxAdapter
from .events import admit, normalize

EVIDENCE_LIMIT = 2000   # root event evidence rows
STALE_AFTER = 3.0       # seconds without a capture-loop iteration
LOSS_WINDOW = 10.0      # seconds a capture loss keeps health degraded


class Buffer:
    def __init__(self, host, boot, store=None, *, capacity=2048, source="simulated", clock=time.monotonic):
        self.host, self.boot, self.store, self.source, self.clock = host, boot, store, source, clock
        self.events, self.lock = deque(maxlen=capacity), threading.RLock()
        self.epoch, self.sequence = str(uuid4()), 0
        self.last_loss = None
        # status["state"] is the capture lifecycle (starting/ready/unavailable);
        # poll() derives the reported health from it plus staleness and recent loss.
        self.status = {"state": "starting", "kernel_lost": 0, "queue_dropped": 0, "buffer_evicted": 0,
                       "invalid": 0, "filtered": 0, "store_errors": 0, "hooks": [], "source": source,
                       "last_poll": None}

    def loss(self, counter, amount=1):
        """Count a capture loss (kernel/queue/invalid/storage) and mark it recent."""
        with self.lock:
            self.status[counter] += int(amount)
            self.last_loss = self.clock()

    def filtered(self, amount=1):
        with self.lock: self.status["filtered"] += int(amount)

    def publish(self, record):
        """Normalize and publish one record; raises on invalid input (counted)."""
        try:
            event = normalize(record, self.host, self.boot, source=self.source)
        except Exception:
            self.loss("invalid")
            raise
        self._commit([event])
        return event

    def publish_many(self, records):
        """Normalize a batch, persist it in one transaction and publish it.
        Invalid records are counted individually without dropping the rest."""
        events = []
        for record in records:
            try:
                events.append(normalize(record, self.host, self.boot, source=self.source))
            except Exception:
                self.loss("invalid")
        self._commit(events)
        return events

    def _commit(self, events):
        if not events:
            return
        if self.store:
            try:
                self.store.write_batch([("event", e["id"], e, False, EVIDENCE_LIMIT) for e in events],
                                       prune={"event": max(0, EVIDENCE_LIMIT - len(events))})
            except Exception:
                # Root evidence persistence failed; live transport still delivers
                # the events so detection continues, and health reports the loss.
                self.loss("store_errors")
        with self.lock:
            for event in events:
                if len(self.events) == self.events.maxlen: self.status["buffer_evicted"] += 1
                self.sequence += 1
                event["sequence"] = self.sequence
                self.events.append(event)

    def health(self):
        with self.lock:
            health, now = dict(self.status), self.clock()
            stale = health["last_poll"] is not None and now - health["last_poll"] > STALE_AFTER
            recent_loss = self.last_loss is not None and now - self.last_loss < LOSS_WINDOW
            if health["state"] == "ready" and (stale or recent_loss):
                health["state"] = "degraded"
            health["capture_stale"], health["recent_loss"] = stale, recent_loss
            return health

    def poll(self, cursor, epoch):
        if type(cursor) is not int or cursor < 0 or (epoch is not None and not isinstance(epoch, str)):
            raise ValueError("Invalid sensor cursor")
        with self.lock:
            reset = epoch != self.epoch
            if reset: cursor = 0
            oldest = self.events[0]["sequence"] if self.events else self.sequence + 1
            gap = max(0, oldest - cursor - 1)
            events = [dict(event) for event in self.events if event["sequence"] > cursor][:32]
            return {"schema": 1, "epoch": self.epoch, "cursor": events[-1]["sequence"] if events else max(cursor, self.sequence),
                    "reset": reset, "gap": gap, "events": events, "health": self.health()}


class SensorClient:
    trusted = True
    def __init__(self, path="/run/linxai-sensor/events.sock"):
        self.path = Path(path)
    def call(self, method, **fields):
        SupervisedLinuxAdapter()._directories(self.path.parent, 0)
        info = self.path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
            raise PermissionError("Untrusted sensor socket")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(str(self.path))
            if ipc.credentials(sock)[1] != 0: raise PermissionError("Sensor is not root")
            ipc.send(sock, {"version": 1, "method": method, **fields})
            return ipc.receive(sock)
    def poll(self, cursor, epoch):
        return self.call("poll", cursor=cursor, epoch=epoch)


def capture(buffer, stop):
    try:
        _capture(buffer, stop)
    except BaseException as exc:
        buffer.status.update(state="unavailable", error=type(exc).__name__)


def _capture(buffer, stop):
    # Reuse existing probes/callback decoding; bypass the legacy unbounded log writer.
    from ebpf.daemon import eBPFDaemon
    incoming = queue.Queue(maxsize=1024)
    class Collector(eBPFDaemon):
        def _write_event(self, event_type, payload):
            record = {"event_type": event_type, "payload": payload}
            if not admit(record):
                buffer.filtered()
                return
            try:
                incoming.put_nowait(record)
            except queue.Full:
                buffer.loss("queue_dropped")
        def _on_lost(self, cpu, lost=None):
            buffer.loss("kernel_lost", cpu if lost is None else lost)
    collector = Collector("/var/lib/linxai-sensor/unused.jsonl", filter_noise=False)
    probes = []
    try:
        for loader in (collector._load_execve, collector._load_connect, collector._load_openat):
            probes.append(loader())
        buffer.status.update(state="ready", hooks=["execve", "connect", "openat"])
        while not stop.is_set():
            for probe in probes: probe.perf_buffer_poll(timeout=50)
            batch = []
            for _ in range(256):
                try: batch.append(incoming.get_nowait())
                except queue.Empty: break
            try:
                buffer.publish_many(batch)
            except Exception:
                buffer.loss("invalid", len(batch))
            finally:
                for _ in batch: incoming.task_done()
            with buffer.lock: buffer.status["last_poll"] = buffer.clock()
    except BaseException as exc:
        buffer.status.update(state="unavailable", error=type(exc).__name__)
    finally:
        for probe in probes:
            try: probe.cleanup()
            except Exception: pass


def main():
    from broker_entry import verify_bundle
    verify_bundle(Path(__file__).absolute().parent.parent)
    config_path = Path("/etc/linxai/broker.json")
    system = SupervisedLinuxAdapter()
    system._directories(config_path.parent, 0)
    info = config_path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError("Unsafe owner configuration")
    owner_uid = json.loads(config_path.read_text())["owner_uid"]
    if type(owner_uid) is not int or owner_uid <= 0: raise ValueError("Ordinary owner required")
    state = Store("/var/lib/linxai-sensor/events.sqlite", uid=0)
    host = hashlib.sha256(Path("/etc/machine-id").read_bytes()).hexdigest()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    buffer = Buffer(host, boot, state, source="kernel")
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    path = Path("/run/linxai-sensor/events.sock")
    system._directories(path.parent, 0)
    import fcntl
    lock = os.open(path.parent / "collector.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if os.path.lexists(path):
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0: raise PermissionError("Unknown sensor socket entry")
        path.unlink()
    thread = threading.Thread(target=capture, args=(buffer, stop), daemon=True)
    thread.start()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        path.chmod(0o666)
        server.listen(4)
        server.settimeout(0.25)
        try:
            while not stop.is_set():
                try: conn, _ = server.accept()
                except socket.timeout: continue
                with conn:
                    try:
                        conn.settimeout(2)
                        peer_uid = ipc.credentials(conn)[1]
                        if peer_uid not in {0, owner_uid}: raise PermissionError("Wrong sensor peer")
                        if peer_uid != 0: Peer.read(conn)
                        request = ipc.receive(conn, timeout=2)
                        if request.get("version") != 1 or type(request.get("version")) is not int: raise ValueError("Version required")
                        if request.get("method") == "poll" and set(request) == {"version", "method", "cursor", "epoch"}:
                            result = buffer.poll(request["cursor"], request["epoch"])
                        elif request.get("method") == "event" and set(request) == {"version", "method", "id"}:
                            result = {"event": state.get("event", ipc.request_id(request["id"]))}
                        else: raise ValueError("Unsupported sensor request")
                        ipc.send(conn, result)
                    except Exception:
                        pass
        finally:
            stop.set()
            thread.join(timeout=2)
            path.unlink(missing_ok=True)
            os.close(lock)
