"""Normalized untrusted evidence. Text never becomes an operation or authority."""
import hashlib
import ipaddress
import json
import time
from uuid import UUID, uuid4

KINDS = frozenset({"process_exec", "network_connect", "file_open"})
# File opens are only evidence for the deterministic file rule; every other open
# on a running host is high-volume noise that starved the capture path on target.
WATCHED_FILES = frozenset({"/etc/shadow", "/etc/sudoers", "/etc/gshadow"})
WATCHED_DIRS = ("/etc/sudoers.d/",)
TEMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")


def canonical(path):
    """Collapse '//', '/./' and '..' in an absolute path the kernel reported as typed by the
    process, so '/tmp//x' or '/etc/./shadow' cannot step around a rule (QA 13 Nov 2026).
    Relative paths stay as reported; they need the kernel-resolved path to be judged."""
    import posixpath
    if not (isinstance(path, str) and path.startswith("/")):
        return path
    return posixpath.normpath("/" + path.lstrip("/"))     # normpath keeps a leading '//' (POSIX); Linux does not


def watched(path):
    path = canonical(path)
    return path in WATCHED_FILES or (isinstance(path, str) and path.startswith(WATCHED_DIRS))
AF_INET = 2
# Requirement 39: a shell or raw network tool making an outbound TCP connection is the
# kernel-visible shape of a reverse shell (e.g. bash /dev/tcp, nc -e, socat exec).
# Task names (comm) are at most 15 characters, as reported by the sensor.
SHELL_TOOLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "fish", "nc", "ncat", "netcat", "nc.openbsd",
                         "nc.traditional", "socat", "telnet"})
# Requirement 39: execution of well-known offensive tooling (advisory; admins may use some).
ATTACK_TOOLS = frozenset({"nmap", "masscan", "hydra", "john", "hashcat", "msfconsole", "msfvenom", "sqlmap",
                          "nikto", "ncat", "nc.traditional", "socat", "chisel", "mimipenguin", "linpeas.sh"})
# Requirement 38: destination ports conventionally used by backdoors/C2 rather than services.
UNUSUAL_PORTS = frozenset({1337, 4444, 5554, 6666, 6667, 9999, 12345, 31337})


def admit(record):
    """Cheap pre-queue relevance filter for raw sensor records. Returns False for
    records no rule or response can use: unwatched file opens and connects that
    are not IPv4 with a real port (AF_UNIX/IPv6 arrive as 0.0.0.0:0). Process
    executions are always kept. Unknown shapes are kept so normalize() can count
    them as invalid instead of hiding them."""
    if not isinstance(record, dict):
        return True
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return True
    kind = record.get("event_type")
    if kind == "file_open":
        return watched(payload.get("filename"))
    if kind == "network_connect":
        family = payload.get("family")
        return (family is None or family == AF_INET) and payload.get("dest_port") not in (0, None)
    return True


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
    path = canonical(event["target"].get("path", ""))
    if event["kind"] == "file_open" and event["uid"] != 0 and watched(path):
        rule = "sensitive_file_attempt"
    elif event["kind"] == "process_exec" and path.startswith(TEMP_DIRS):
        rule = "temporary_executable_attempt"
    elif event["kind"] == "process_exec" and path.rsplit("/", 1)[-1] in ATTACK_TOOLS:
        rule = "attack_tool_execution"
    elif event["kind"] == "network_connect" and event.get("protocol") != "udp" and event.get("process") in SHELL_TOOLS:
        rule = "shell_network_connection"
    elif event["kind"] == "network_connect" and event["target"]["port"] in UNUSUAL_PORTS:
        rule = "unusual_connection_attempt"
    if rule is None: return None
    return {"schema": 1, "id": event["id"], "event_id": event["id"], "state": "observed",
            "rule": rule, "severity": "warning", "evidence": event,
            "interpretation": "Deterministic suspicion; entry observation does not prove malicious intent or prevention",
            "response": "none", "created": time.time()}
