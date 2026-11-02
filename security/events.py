"""Normalized untrusted evidence. Text never becomes an operation or authority."""
import hashlib
import ipaddress
import json
import time
from uuid import UUID, uuid4

KINDS = frozenset({"process_exec", "network_connect", "file_open"})


def integer(value, minimum=0):
    if type(value) is not int or value < minimum or value > 2**64 - 1:
        raise ValueError("Invalid bounded event integer")
    return value


def text(value, limit=1024):
    if not isinstance(value, str) or len(value.encode()) > limit or "\x00" in value:
        raise ValueError("Invalid bounded event text")
    return value


def normalize(record, host, boot, *, source):
    if not isinstance(record, dict) or record.get("event_type") not in KINDS:
        raise ValueError("Unsupported event kind")
    payload = record.get("payload")
    if not isinstance(payload, dict) or len(json.dumps(payload)) > 8192:
        raise ValueError("Invalid event payload")
    uid, pid = integer(payload.get("uid")), integer(payload.get("pid"), 1)
    start = payload.get("start_ns")
    if start is not None: start = integer(start, 1)
    timestamp = payload.get("monotonic_ns")
    if timestamp is not None: timestamp = integer(timestamp, 1)
    target = {}
    if record["event_type"] == "network_connect":
        target["address"] = str(ipaddress.ip_address(payload.get("dest_ip")))
        target["port"] = integer(payload.get("dest_port"), 1)
        if target["port"] > 65535: raise ValueError("Invalid event port")
    else:
        target["path"] = text(payload.get("filename", ""))
    subject = hashlib.sha256(f"{host}:{boot}:{uid}:{pid}:{start}".encode()).hexdigest() if start else None
    return {"schema": 1, "id": str(uuid4()), "host": text(host, 128), "boot": text(boot, 128),
            "kind": record["event_type"], "protocol": {6:"tcp",17:"udp"}.get(payload.get("protocol"),"unknown"), "uid": uid, "pid": pid, "ppid": integer(payload.get("ppid", 0)),
            "start_ns": start, "subject": subject, "process": text(payload.get("process", ""), 128),
            "monotonic_ns": timestamp, "received_ns": time.monotonic_ns(),
            "received_boottime_ns": time.clock_gettime_ns(time.CLOCK_BOOTTIME) if hasattr(time,"CLOCK_BOOTTIME") else None, "target": target,
            "source": source, "identity_quality": "kernel_start_identity" if start and timestamp and source == "kernel" else "incomplete_or_simulated",
            "result": "entry_observation; syscall outcome unknown"}


def validate(event):
    if not isinstance(event, dict) or len(json.dumps(event)) > 16384 or event.get("schema") != 1:
        raise ValueError("Invalid normalized event")
    if str(UUID(event["id"])) != event["id"] or event["kind"] not in KINDS:
        raise ValueError("Invalid event identity/kind")
    integer(event["uid"])
    integer(event["pid"], 1)
    text(event["host"], 128)
    text(event["boot"], 128)
    if event["kind"] == "network_connect":
        ipaddress.ip_address(event["target"]["address"])
        if not 1 <= integer(event["target"]["port"], 1) <= 65535: raise ValueError("Invalid port")
    else:
        text(event["target"]["path"])
    return event


def detect(event):
    validate(event)
    rule = None
    if event["kind"] == "file_open" and event["uid"] != 0 and event["target"]["path"] in {"/etc/shadow", "/etc/sudoers"}:
        rule = "sensitive_file_attempt"
    elif event["kind"] == "process_exec" and event["target"]["path"].startswith(("/tmp/", "/dev/shm/")):
        rule = "temporary_executable_attempt"
    elif event["kind"] == "network_connect" and event["target"]["port"] in {4444, 1337}:
        rule = "unusual_connection_attempt"
    if rule is None: return None
    return {"schema": 1, "id": event["id"], "event_id": event["id"], "state": "observed",
            "rule": rule, "severity": "warning", "evidence": event,
            "interpretation": "Deterministic suspicion; entry observation does not prove malicious intent or prevention",
            "response": "none", "created": time.time()}
