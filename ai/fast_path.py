import re
import shlex

from executor.command_builder import SERVICE_ALIASES, build as build_command

STOPWORDS = {
    "please", "can", "you", "could", "would", "kindly", "for", "me",
    "the", "a", "an", "just", "now", "hey", "plz", "pls",
}


def classify_fast(user_input: str, context: dict | None = None) -> dict | None:
    text = _normalize(user_input)
    if not text:
        return None

    conditional = _conditional_service(text)
    if conditional:
        conditional["source"] = "fast_path"
        conditional["command"] = build_command(conditional["intent"], conditional).strip()
        return conditional
    # Partial matches must not discard conditions or additional operations.
    if re.search(r"\b(if|unless|when|provided|and|then|or)\b", text):
        return None

    file_plan = _file_create(_normalize_file_create(user_input))
    if file_plan:
        file_plan["source"] = "fast_path"
        file_plan["command"] = build_command(file_plan["intent"], file_plan).strip()
        return file_plan

    candidates = [text]
    reduced = _strip_stopwords(text)
    if reduced and reduced != text:
        candidates.append(reduced)

    plan = None
    for candidate in candidates:
        plan = (
            _identity_info(candidate)
            or _network_info(candidate)
            or _port_list(candidate)
            or _listener_without_service(candidate)
            or _service_count(candidate)
            or _service(candidate)
            or _port_check(candidate, context)
            or _package_install(candidate)
            or _system_query(candidate)
        )
        if plan:
            break

    if not plan:
        return None

    plan["source"] = "fast_path"
    plan["command"] = build_command(plan["intent"], plan).strip()
    return plan


def _normalize(user_input: str) -> str:
    text = (user_input or "").lower().strip()
    text = text.replace("'", "")
    text = re.sub(r"[?!;,]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _normalize_file_create(user_input: str) -> str:
    text = (user_input or "").strip()
    text = re.sub(r"[?!;,]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _strip_stopwords(text: str) -> str:
    return " ".join(
        token for token in text.split()
        if token and token not in STOPWORDS
    )


def _base(intent: str, target: str = "", **slots) -> dict:
    plan = {
        "intent": intent,
        "target": target,
        "port": "",
        "location": "",
        "content": "",
        "goal": "",
        "path": "",
        "stack": "",
        "repo_url": "",
        "pre_conditions": [],
        "command": "",
        "requires_sudo": False,
        "risk_level": "low",
        "rollback": "",
        "explanation": "",
        "suggestion": "",
    }
    plan.update(slots)
    return plan


def _identity_info(text: str) -> dict | None:
    if text in {
        "whats my name",
        "what is my name",
        "who am i",
        "whoami",
        "my user",
        "my username",
        "whos am i",
        "whos i",
    }:
        return _base(
            "system_info",
            "whoami",
            explanation="Shows the current Linux user.",
        )
    return None


def _network_info(text: str) -> dict | None:
    if text in {"ip", "my ip", "ip address", "whats my ip"} or text.startswith(
        ("ip ", "my ip ", "ip address ", "whats my ip ")
    ):
        return _base(
            "network_info",
            "ip_address",
            explanation="Shows IP addresses.",
        )

    if text in {"mac", "my mac", "mac address", "whats my mac"} or text.startswith(
        ("mac ", "my mac ", "mac address ", "whats my mac ")
    ):
        return _base(
            "network_info",
            "mac_address",
            explanation="Shows network interface MAC addresses.",
        )

    if text in {"hostname", "host name", "computer name"}:
        return _base(
            "network_info",
            "hostname",
            explanation="Shows the system hostname.",
        )
    return None


def _port_list(text: str) -> dict | None:
    if text in {"show ports", "list ports", "ports", "ss", "netstat", "show port"}:
        return _base("port_list", "", explanation="Lists listening ports.")
    return None


def _context_expects_port(context: dict | None) -> bool:
    if not context:
        return False
    if isinstance(context, dict):
        if context.get("expects_port"):
            return True
        recent = context.get("recent")
        if isinstance(recent, list) and recent:
            last = recent[-1].get("plan", {}) if isinstance(recent[-1], dict) else {}
            return last.get("intent") == "port_check" and not last.get("port")
    return False


def _conditional_service(text: str) -> dict | None:
    match = re.fullmatch(
        r"(?P<action>start|stop|restart)\s+(?:the\s+)?"
        r"(?P<service>[a-z0-9@_.-]+)(?:\s+service)?\s+"
        r"(?:only\s+)?if\s+port\s+(?P<port>\d{1,5})\s+"
        r"(?:is\s+)?(?:currently\s+)?(?P<state>free|unused|available|not (?:currently )?in use|occupied|in use)$",
        text,
    )
    if not match or not 1 <= int(match.group("port")) <= 65535:
        return None
    action, service = match.group("action"), match.group("service")
    service = service.removesuffix(".service")
    service = SERVICE_ALIASES.get(service, service)
    state = match.group("state")
    check = "port_occupied" if state in {"occupied", "in use"} else "port_free"
    return _base(
        "service_" + action, service,
        # This port is a precondition, not a listener configuration request.
        port="",
        pre_conditions=[{"check": "service_exists", "service": service},
                        {"check": check, "port": int(match.group("port"))}],
        requires_sudo=True, risk_level="medium", rollback="",
        explanation=f"{action.capitalize()}s {service} only if port {match.group('port')} is {state}.",
    )


def _port_check(text: str, context: dict | None) -> dict | None:
    port = None
    match = re.fullmatch(
        r"(?:whats(?: running on)?|what is(?: running on)?|who is using|what is running on|show|check)?\s*"
        r"port\s+(?P<port>\d{1,5})",
        text,
    )
    if match:
        port = int(match.group("port"))
    elif re.fullmatch(r"\d{1,5}", text):
        value = int(text)
        if _context_expects_port(context) or 1 <= value <= 65535:
            port = value

    if port is None or not 1 <= port <= 65535:
        return None

    return _base(
        "port_check",
        str(port),
        port=str(port),
        explanation=f"Checks what is listening on port {port}.",
    )


def _listener_without_service(text: str) -> dict | None:
    patterns = (
        r"^(?:start|run|create|open)\s+(?:any\s+service|a\s+service|service|"
        r"(?:a\s+)?(?:test\s+)?(?:listener|listening|server|something))\s+"
        r"(?:on|o|at|using)?\s*port\s+(?P<port>\d{1,5})$",
        r"^(?:start|run)\s+(?:on|o|at|using)?\s*port\s+(?P<port>\d{1,5})$",
    )
    for pattern in patterns:
        match = re.match(pattern, text)
        if not match:
            continue
        port = int(match.group("port"))
        if not 1 <= port <= 65535:
            return None
        return _base(
            "service_start",
            "",
            port=str(port),
            explanation=(
                f"No specific service was named for port {port}; ask the "
                "user whether to configure nginx or use a temporary listener."
            ),
        )
    return None


def _service_count(text: str) -> dict | None:
    patterns = (
        r"^how many\s+(?P<service>[a-z0-9@_.-]+)"
        r"(?:\s+(?:server|servers|process|processes|worker|workers))?"
        r"(?:\s+(?:are|is))?"
        r"(?:\s+(?:running|active|up))?$",
        r"^(?P<service>[a-z0-9@_.-]+)\s+(?:worker|workers|process|processes)\s+count$",
        r"^count\s+(?P<service>[a-z0-9@_.-]+)\s+(?:workers|processes|servers?)$",
    )
    for pattern in patterns:
        match = re.match(pattern, text)
        if not match:
            continue
        service = match.group("service")
        if service in {"many", "service", "services", "process", "processes"}:
            return None
        return _base(
            "process_list",
            service,
            query="service_count",
            command=_service_count_command(service),
            explanation=(
                f"Counts {service} processes and lists the ports it is "
                "listening on."
            ),
        )
    return None


def _service_count_command(service: str) -> str:
    quoted = shlex.quote(service)
    return (
        f"svc={quoted}; "
        "count=$(pgrep -c -x \"$svc\" 2>/dev/null || true); "
        "details=$(pgrep -a -x \"$svc\" 2>/dev/null || true); "
        "master=$(printf '%s\\n' \"$details\" | grep -c 'master process' || true); "
        "worker=$(printf '%s\\n' \"$details\" | grep -c 'worker process' || true); "
        "ports=$(ss -tlnp 2>/dev/null | "
        "awk -v svc=\"$svc\" '$0 ~ svc {print $4}' | "
        "sed -nE 's/.*:([0-9]+)$/\\1/p' | sort -n -u | paste -sd, -); "
        "printf 'SERVICE=%s\\nCOUNT=%s\\nMASTER=%s\\nWORKER=%s\\nPORTS=%s\\n' "
        "\"$svc\" \"$count\" \"$master\" \"$worker\" \"$ports\""
    )


def _service(text: str) -> dict | None:
    match = re.match(
        r"^(?P<action>start|stop|restart|status)\s+"
        r"(?:the\s+)?(?P<service>[a-z0-9@_.-]+)"
        r"(?:\s+(?:service))?"
        r"(?:\s+(?:on|at|using)\s+port\s+(?P<port>\d{1,5}))?$",
        text,
    )
    if not match:
        match = re.match(
            r"^(?P<service>[a-z0-9@_.-]+)\s+status$",
            text,
        )
        if not match:
            return None
        action = "status"
        service = match.group("service")
        port = ""
    else:
        action = match.group("action")
        service = match.group("service")
        port = match.group("port") or ""

    if service in {"any", "port", "ports", "package", "file", "folder"}:
        return None

    intent = {
        "start": "service_start",
        "stop": "service_stop",
        "restart": "service_restart",
        "status": "service_status",
    }[action]
    requires_sudo = intent in {"service_start", "service_stop", "service_restart"}
    risk = "medium" if requires_sudo else "low"
    rollback = ""
    if intent == "service_start":
        rollback = f"systemctl stop {service}"
    elif intent == "service_stop":
        rollback = f"systemctl start {service}"
    elif intent == "service_restart":
        rollback = f"systemctl stop {service}"

    return _base(
        intent,
        service,
        port=port,
        pre_conditions=[{"check": "service_exists", "service": service}],
        requires_sudo=requires_sudo,
        risk_level=risk,
        rollback=rollback,
        explanation=f"{action.capitalize()}s {service}.",
    )


def _package_install(text: str) -> dict | None:
    if "http://" in text or "https://" in text or " repo" in text or "repository" in text:
        return None

    match = re.match(
        r"^install\s+(?:the\s+)?(?P<pkg>[a-z0-9][a-z0-9+_.-]*(?:\s+[a-z0-9][a-z0-9+_.-]*)*)"
        r"(?:\s+package)?$",
        text,
    )
    if not match:
        return None

    pkg = match.group("pkg").strip()
    if pkg in {"package", "packages"}:
        return None
    if pkg.endswith(" package"):
        pkg = pkg[:-8].strip()

    return _base(
        "package_install",
        pkg,
        requires_sudo=True,
        risk_level="medium",
        rollback=f"apt remove -y {pkg}",
        explanation=f"Installs package {pkg}.",
    )


def _file_create(text: str) -> dict | None:
    match = re.match(
        r"^create\s+(?:a\s+)?(?P<kind>file|folder|directory)\s+"
        r"(?:(?:named|called)\s+)?(?P<target>\S+)"
        r"(?:\s+in\s+(?P<location>.+))?$",
        text,
        re.IGNORECASE,
    )
    if match:
        return _file_create_plan(
            match.group("kind"),
            match.group("target"),
            match.group("location") or "",
        )

    match = re.match(
        r"^create\s+(?:a\s+)?(?P<kind>file|folder|directory)\s+"
        r"in\s+(?P<location>.+)\s+(?P<target>\S+)$",
        text,
        re.IGNORECASE,
    )
    if match:
        return _file_create_plan(
            match.group("kind"),
            match.group("target"),
            match.group("location") or "",
        )

    return None


def _file_create_plan(kind: str, target: str, location: str) -> dict:
    kind = kind.lower()
    is_dir = kind in {"folder", "directory"}
    return _base(
        "file_create",
        target,
        location=location,
        kind="directory" if is_dir else "file",
        explanation=(
            f"Creates a {'directory' if is_dir else 'file'} named {target}."
        ),
    )


def _system_query(text: str) -> dict | None:
    if text in {"uptime", "how long running", "how long has this server been running"}:
        return _base(
            "system_uptime",
            "",
            explanation="Shows how long the machine has been running.",
        )

    if text in {"disk", "disk space", "check disk", "check disk space", "show disk space"}:
        return _base("disk_usage", "", explanation="Shows disk usage.")

    if text in {"memory", "free", "check memory", "memory usage", "show memory"}:
        return _base("memory_usage", "", explanation="Shows memory usage.")

    if text in {"cpu", "cpu usage", "check cpu", "show cpu"}:
        return _base("cpu_usage", "", explanation="Shows CPU usage.")

    if text in {"os version", "ubuntu version", "what os", "which distro"}:
        return _base(
            "network_info",
            "os",
            explanation="Shows the Linux distribution.",
        )

    if text in {"date", "time", "whoami", "who"}:
        return _base(
            "system_info",
            text,
            explanation=f"Runs {text}.",
        )

    match = re.fullmatch(r"(?P<tool>[a-z0-9+_.-]+)\s+version", text)
    if match:
        tool = match.group("tool")
        return _base(
            "system_info",
            tool,
            query="version",
            explanation=f"Shows {tool} version.",
        )

    return None
