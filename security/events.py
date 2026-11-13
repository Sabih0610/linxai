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


# Persistence (13 Nov 2026): places an attacker writes to survive a logout or reboot. Only
# opens with write intent count, so a shell reading ~/.bashrc at start-up is not an incident.
PERSISTENCE_SUFFIXES = ("/.ssh/authorized_keys", "/.ssh/authorized_keys2", "/.bashrc", "/.bash_profile", "/.bash_login",
                        "/.profile", "/.zshrc", "/.zprofile")
PERSISTENCE_PREFIXES = ("/etc/cron", "/var/spool/cron/", "/etc/systemd/system/", "/etc/profile.d/", "/etc/init.d/",
                        "/etc/rc.local", "/etc/ld.so.preload", "/etc/environment", "/etc/update-motd.d/")
PERSISTENCE_PARTS = ("/.config/systemd/user/", "/.config/autostart/", "/.local/share/systemd/user/")
# Root legitimately writes most system locations (package upgrades); for root only these count.
ROOT_PERSISTENCE = ("/etc/ld.so.preload", "/.ssh/authorized_keys", "/.ssh/authorized_keys2")
WRITE_FLAGS = 0o1 | 0o2 | 0o100 | 0o1000 | 0o2000      # O_WRONLY O_RDWR O_CREAT O_TRUNC O_APPEND


def writes(flags):
    return type(flags) is int and bool(flags & WRITE_FLAGS)


def persistence_target(path, uid=None):
    if not isinstance(path, str) or not path:
        return False
    path = canonical(path) if path.startswith("/") else "/" + path      # relative: judged by its tail
    if uid == 0:
        return path.startswith(ROOT_PERSISTENCE[:1]) or path.endswith(ROOT_PERSISTENCE[1:])
    return path.endswith(PERSISTENCE_SUFFIXES) or path.startswith(PERSISTENCE_PREFIXES) or any(p in path for p in PERSISTENCE_PARTS)


AF_INET, AF_INET6 = 2, 10
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
        filename = payload.get("filename")
        return watched(filename) or (writes(payload.get("flags")) and persistence_target(filename, payload.get("uid")))
    if kind == "network_connect":
        family = payload.get("family")
        return family in (None, AF_INET, AF_INET6) and payload.get("dest_port") not in (0, None)
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
        address = ipaddress.ip_address(payload.get("dest_ip"))
        if address.version == 6 and address.ipv4_mapped:      # ::ffff:a.b.c.d is an IPv4 destination
            address = address.ipv4_mapped
        target["address"] = str(address)
        target["port"] = integer(payload.get("dest_port"), 1)
        if target["port"] > 65535: raise ValueError("Invalid event port")
    else:
        target["path"] = text(payload.get("filename", ""))
        if record["event_type"] == "file_open" and type(payload.get("flags")) is int:
            target["write"] = writes(payload["flags"])
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
    rule, severity = None, "warning"
    path = canonical(event["target"].get("path", ""))
    facts = event.get("facts") if isinstance(event.get("facts"), dict) else {}    # procfs facts (security.procfacts)
    if event["kind"] == "process_exec" and facts.get("stdio_tcp") in {"self", "parent"}:
        rule, severity = "remote_shell_socket_stdio", "critical"     # reverse or bind shell, whatever launched it
    elif facts.get("tool_identity"):
        rule = "masqueraded_tool_execution" if event["kind"] == "process_exec" else "masqueraded_tool_connection"
        severity = "high"
    elif event["kind"] == "file_open" and event["target"].get("write") and persistence_target(path, event["uid"]):
        rule = "persistence_write_attempt"
    elif event["kind"] == "file_open" and event["uid"] != 0 and watched(path):
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
            "rule": rule, "severity": severity, "evidence": event,
            "interpretation": "Deterministic suspicion; entry observation does not prove malicious intent or prevention",
            "response": "none", "created": time.time()}
