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


BATCH = 32          # sensor serves at most 32 events per poll
DRAIN_POLLS = 16    # polls per wake while the sensor still has a full batch
EVENT_LIMIT, INCIDENT_LIMIT = 2000, 1000
LAKE_INTERVAL_S = 600   # medallion refresh cadence


class Monitor:
    def __init__(self, store, source, baseline=None, lineage=None, facts=None):
        self.store, self.source = store, source
        # Requirement 42: procfs ancestry for real-kernel incidents only (evidence, not authority).
        if lineage is None and source.trusted:
            from .lineage import lineage
        self.lineage = lineage
        # Widened detection: procfs facts (socket-bound shells, renamed tools) for real-kernel events.
        if facts is None and source.trusted:
            from .procfacts import ToolCatalog, facts as procfs_facts
            tools = ToolCatalog()
            facts = lambda event: procfs_facts(event, tools=tools)
        self.facts = facts
        self.status = self.store.get("monitor", "status") or {"cursor": 0, "epoch": None, "events": 0, "incidents": 0, "invalid": 0, "gaps": 0}
        self.last_batch = 0
        # Optional learned gold baseline (security.lake); advisory anomalies only.
        self.baseline = baseline

    def tick(self):
        self.last_batch = 0
        try:
            batch = self.source.poll(self.status["cursor"], self.status["epoch"])
            if batch.get("schema") != 1 or not isinstance(batch.get("events"), list) or len(batch["events"]) > BATCH:
                raise ValueError("Malformed sensor batch")
            if type(batch.get("cursor")) is not int or batch["cursor"] < 0 or type(batch.get("gap")) is not int or batch["gap"] < 0:
                raise ValueError("Invalid batch cursor/loss")
            if not isinstance(batch.get("health"), dict) or batch["health"].get("state") not in {"starting", "ready", "degraded", "unavailable"}:
                raise ValueError("Invalid capture health")
            pending = dict(self.status)
            pending.update(state=batch["health"]["state"], health=batch["health"], trusted_source=bool(self.source.trusted),
                           epoch=batch["epoch"], updated=time.time())
            pending["gaps"] += batch["gap"]
            events, incidents, anomalies, seen = [], [], [], set()
            for event in batch["events"]:
                try:
                    validate(event)
                    if not self.source.trusted: event["source"] = "simulated"
                    if event["id"] in seen or self.store.get("event", event["id"]): continue
                    seen.add(event["id"])
                    if self.facts and event["kind"] in {"process_exec", "network_connect"}:
                        try:
                            found = self.facts(event)
                            if found: event["facts"] = found
                        except Exception:
                            pass                          # facts are optional evidence; rules still run
                    events.append(event)
                    incident = detect(event)
                    if incident and self.lineage:
                        try:
                            incident["lineage"] = self.lineage(event)
                        except Exception:
                            incident["lineage"] = {"identity": "unavailable", "chain": []}
                    if incident: incidents.append(incident)
                    elif self.baseline and self.source.trusted:
                        from .lake import score
                        anomaly = score(event, self.baseline)
                        if anomaly: anomalies.append(anomaly)
                except Exception:
                    pending["invalid"] += 1
                    pending["state"] = "degraded"
            pending["events"] += len(events)
            pending["incidents"] += len(incidents)
            pending["cursor"] = batch["cursor"]
            pending.pop("error", None)
            records = ([("event", e["id"], e, False, EVENT_LIMIT) for e in events]
                       + [("incident", i["id"], i, False, INCIDENT_LIMIT) for i in incidents]
                       + [("anomaly", a["id"], a, False, INCIDENT_LIMIT) for a in anomalies]
                       + [("monitor", "status", pending, True, 1000)])
            pending["anomalies"] = pending.get("anomalies", 0) + len(anomalies)
            prune = {}
            if anomalies: prune["anomaly"] = max(0, INCIDENT_LIMIT - len(anomalies))
            if events: prune["event"] = max(0, EVENT_LIMIT - len(events))
            if incidents: prune["incident"] = max(0, INCIDENT_LIMIT - len(incidents))
            # One durable transaction per batch: events, incidents and the advanced
            # cursor commit together, so a failure retries the whole batch.
            self.store.write_batch(records, prune=prune)
            self.status = pending
            self.last_batch = len(batch["events"])
        except Exception as exc:
            self.status.update(state="unavailable", error=type(exc).__name__, updated=time.time())
            self.store.put("monitor", "status", self.status)
        return self.status

    def drain(self, stop=None):
        """Poll until the sensor has no full batch left (bounded per wake)."""
        for _ in range(DRAIN_POLLS):
            self.tick()
            if self.last_batch < BATCH or (stop is not None and stop.is_set()):
                break
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
    from .lake import Lake
    lake_store = Store(Path(args.state) / "lake.sqlite")
    lake = Lake(lake_store, store)
    monitor = Monitor(store, SensorClient(), baseline=lake.model())
    next_cycle = time.monotonic() + LAKE_INTERVAL_S
    try:
        while not stop.is_set():
            monitor.drain(stop)
            if time.monotonic() >= next_cycle:
                # Medallion refresh: bronze -> silver -> gold, then reload the baseline.
                try:
                    lake.run_cycle()
                    monitor.baseline = lake.model()
                except Exception as exc:
                    monitor.status["lake_error"] = type(exc).__name__
                next_cycle = time.monotonic() + LAKE_INTERVAL_S
            stop.wait(0.5)
    finally:
        lake_store.close()
        store.close()
        os.close(lock)


if __name__ == "__main__":
    raise SystemExit(main())
