"""Independent ordinary-user deterministic incident daemon; never invokes AI."""
import argparse
import os
from pathlib import Path
import signal
import stat
import threading
import time

from operations.store import Store
from operations.supervised import SupervisedLinuxAdapter
from .events import detect, validate
from .sensor import SensorClient


class Monitor:
    def __init__(self, store, source):
        self.store, self.source = store, source
        self.status = self.store.get("monitor", "status") or {"cursor": 0, "epoch": None, "events": 0, "incidents": 0, "invalid": 0, "gaps": 0}

    def tick(self):
        try:
            batch = self.source.poll(self.status["cursor"], self.status["epoch"])
            if batch.get("schema") != 1 or not isinstance(batch.get("events"), list) or len(batch["events"]) > 32:
                raise ValueError("Malformed sensor batch")
            if type(batch.get("cursor")) is not int or batch["cursor"] < 0 or type(batch.get("gap")) is not int or batch["gap"] < 0:
                raise ValueError("Invalid batch cursor/loss")
            if not isinstance(batch.get("health"), dict) or batch["health"].get("state") not in {"starting", "ready", "degraded", "unavailable"}:
                raise ValueError("Invalid capture health")
            self.status.update(state=batch["health"]["state"], health=batch["health"], trusted_source=bool(self.source.trusted),
                               epoch=batch["epoch"], updated=time.time())
            self.status["gaps"] += batch["gap"]
            for event in batch["events"]:
                try:
                    validate(event)
                    if not self.source.trusted: event["source"] = "simulated"
                    if self.store.get("event", event["id"]): continue
                    self.store.prune("event", 1999)
                    self.store.put("event", event["id"], event, replace=False, limit=2000)
                    incident = detect(event)
                    if incident:
                        self.store.prune("incident", 999)
                        self.store.put("incident", incident["id"], incident, replace=False)
                        self.status["incidents"] += 1
                    self.status["events"] += 1
                except Exception:
                    self.status["invalid"] += 1
                    self.status["state"] = "degraded"
            self.status["cursor"] = batch["cursor"]
        except Exception as exc:
            self.status.update(state="unavailable", error=type(exc).__name__, updated=time.time())
        self.store.put("monitor", "status", self.status)
        return self.status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", default=str(Path.home() / ".linxai"))
    args = parser.parse_args(argv)
    identity = SupervisedLinuxAdapter().resolve_identity()
    if not identity.ordinary(): raise PermissionError("Monitor requires ordinary account")
    store = Store(Path(args.state) / "security.sqlite")
    import fcntl
    lock = os.open(Path(args.state) / "monitor.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    info = os.fstat(lock)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != identity.uid or info.st_nlink != 1 or info.st_mode & 0o077:
        raise PermissionError("Unsafe monitor lock")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    monitor = Monitor(store, SensorClient())
    try:
        while not stop.is_set():
            monitor.tick()
            stop.wait(0.5)
    finally:
        store.close()
        os.close(lock)
