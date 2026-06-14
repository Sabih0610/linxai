import re


def analyze(
    intent: str,
    command: str,
    stdout: str,
    stderr: str,
    exit_code: int,
) -> str | None:
    try:
        if intent == "port_check":
            return _analyze_port_check(command, stdout)
        if intent == "service_status":
            return _analyze_service_status(command, stdout)
        if intent == "process_list":
            service_count = _analyze_service_process_count(stdout)
            if service_count:
                return service_count
            return _analyze_process_list(command, stdout)
        if intent == "system_uptime":
            return _analyze_system_uptime(stdout)
        if intent == "disk_usage":
            return _analyze_disk_usage(stdout)
        if intent == "memory_usage":
            return _analyze_memory_usage(stdout)
        if intent == "network_info":
            return _analyze_network_info(command, stdout)
        if intent == "file_find":
            return _analyze_file_find(command, stdout)
    except Exception:
        return None
    return None


def _extract_port(command: str) -> str | None:
    patterns = (
        r"\bsport\s*=\s*:?(?P<port>\d+)\b",
        r"grep\s+['\"]?:?(?P<port>\d+)['\"]?",
        r":(?P<port>\d+)\b",
    )
    for pattern in patterns:
        match = re.search(pattern, command)
        if match:
            return match.group("port")
    return None


def _analyze_network_info(command: str, stdout: str) -> str | None:
    command = command.strip()
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]

    if "cat /sys/class/net" in command and "address" in command:
        macs = []
        for line in lines:
            match = re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", line)
            if match and line != "00:00:00:00:00:00" and line not in macs:
                macs.append(line.lower())
        if not macs:
            return "No hardware MAC address was found."
        if len(macs) == 1:
            return f"Your MAC address is {macs[0]}."
        return f"Your MAC addresses are {', '.join(macs)}."

    if command.startswith("ip -brief addr"):
        entries = []
        for line in lines:
            parts = line.split()
            if len(parts) < 3:
                continue
            iface = parts[0]
            addrs = [p for p in parts[2:] if "/" in p]
            if addrs:
                entries.append(f"{iface}: {', '.join(addrs)}")
        if entries:
            return f"IP addresses: {'; '.join(entries)}."
        return "No IP addresses were found."

    if command.startswith("hostnamectl --static") or command == "hostname":
        if lines:
            return f"Hostname: {lines[0]}."
        return None

    if command.startswith("lsb_release -d"):
        if not lines:
            return None
        desc = lines[0].split(":", 1)[1].strip() if ":" in lines[0] else lines[0]
        return f"OS: {desc}."

    return None


def _extract_find_name(command: str) -> str | None:
    match = re.search(r"-name\s+(['\"]?)(?P<name>.+?)\1(?:\s|$)", command)
    if match:
        return match.group("name")
    return None


def _extract_find_roots(command: str) -> list[str]:
    try:
        import shlex
        parts = shlex.split(command)
    except Exception:
        parts = command.split()

    if not parts or parts[0] != "find":
        return []

    roots = []
    for part in parts[1:]:
        if part.startswith("-") or part in {"(", ")"}:
            break
        roots.append(part)
    return roots


def _analyze_file_find(command: str, stdout: str) -> str | None:
    name = _extract_find_name(command)
    roots = _extract_find_roots(command)
    if not name:
        return None

    matches = [line.strip() for line in stdout.splitlines() if line.strip()]
    if matches:
        shown = ", ".join(matches[:3])
        if len(matches) > 3:
            shown += f", and {len(matches) - 3} more"
        return f"Found {len(matches)} matches: {shown}."

    root_text = ", ".join(roots) if roots else "the selected roots"
    return f"No file named '{name}' found under {root_text}."


def _parse_local_endpoint(endpoint: str) -> tuple[str, str] | None:
    endpoint = endpoint.strip()
    if not endpoint:
        return None

    if endpoint.startswith("["):
        match = re.match(r"^\[(?P<addr>[^\]]+)\]:(?P<port>\d+)$", endpoint)
        if match:
            return match.group("addr"), match.group("port")

    match = re.match(r"^(?P<addr>.*):(?P<port>\d+)$", endpoint)
    if match:
        return match.group("addr") or "*", match.group("port")
    return None


def _analyze_port_check(command: str, stdout: str) -> str | None:
    target_port = _extract_port(command)
    rows = [line for line in stdout.splitlines() if line.strip()]
    data_rows = [
        line for line in rows
        if not line.lstrip().startswith(("State", "Netid"))
    ]

    if not data_rows and target_port:
        return f"Nothing is listening on port {target_port}."
    if not data_rows:
        return None

    for line in data_rows:
        parts = line.split()
        if len(parts) < 5:
            continue

        local_idx = 4 if parts[0].lower() in {"tcp", "udp", "tcp6", "udp6"} else 3
        if len(parts) <= local_idx:
            continue

        parsed = _parse_local_endpoint(parts[local_idx])
        if not parsed:
            continue

        addr, port = parsed
        if target_port and port != target_port:
            continue

        proc_field = " ".join(parts[local_idx + 2:]) if len(parts) > local_idx + 2 else ""
        proc_match = re.search(
            r'users:\(\("(?P<name>[^"]+)",pid=(?P<pid>\d+)',
            proc_field,
        )
        if not proc_match:
            return f"Port {port} is listening on {addr}, but the process was not visible."

        name = proc_match.group("name")
        pid = proc_match.group("pid")
        return f"Port {port} is used by {name} (PID {pid}), listening on {addr}."

    if target_port:
        return f"Nothing is listening on port {target_port}."
    return None


def _service_from_command(command: str) -> str | None:
    match = re.search(
        r"\bsystemctl\s+(?:status|is-active)\s+(?P<service>[\w@.-]+)",
        command,
    )
    if not match:
        return None
    return re.sub(r"\.service$", "", match.group("service"))


def _analyze_service_status(command: str, stdout: str) -> str | None:
    service = _service_from_command(command)
    if not service:
        return None

    active_match = re.search(
        r"Active:\s+(?P<state>\w+)"
        r"(?:\s+\((?P<detail>[^)]+)\))?"
        r"(?:\s+since\s+(?P<since>[^;]+))?",
        stdout,
    )
    if active_match:
        state = active_match.group("state")
        detail = active_match.group("detail")
        since = active_match.group("since")
        if state == "active":
            running = detail or "running"
            if since:
                return f"{service} is active ({running}) since {since.strip()}."
            return f"{service} is active ({running})."
        if state == "inactive":
            return f"{service} is inactive (stopped)."
        if state == "failed":
            return f"{service} is failed."
        return f"{service} is {state}."

    status = stdout.strip().splitlines()[0].strip() if stdout.strip() else ""
    if status == "active":
        return f"{service} is active (running)."
    if status in {"inactive", "unknown"}:
        return f"{service} is inactive (stopped)."
    if status == "failed":
        return f"{service} is failed."
    return None


def _process_name(command: str) -> str:
    first = command.strip().split()[0] if command.strip() else "?"
    first = first.strip("[]")
    first = first.split("/")[-1] or first
    return first.rstrip(":") or first


def _parse_etime(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None

    days = 0
    if "-" in value:
        day_text, value = value.split("-", 1)
        try:
            days = int(day_text)
        except ValueError:
            return None

    parts = value.split(":")
    try:
        nums = [int(part) for part in parts]
    except ValueError:
        return None

    if len(nums) == 3:
        hours, minutes, seconds = nums
    elif len(nums) == 2:
        hours = 0
        minutes, seconds = nums
    else:
        return None
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def _format_duration(seconds: int) -> str:
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, _ = divmod(seconds, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes or not parts:
        parts.append(f"{minutes}m")
    return " ".join(parts)


def _analyze_elapsed_processes(stdout: str) -> str | None:
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) < 2:
        return None

    entries = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        name, etime, pid = parts[0], parts[1], parts[2]
        seconds = _parse_etime(etime)
        if seconds is None:
            continue
        if name in {"COMMAND", "ps"}:
            continue
        entries.append((seconds, name, pid))

    if not entries:
        return None

    around_hour = [
        item for item in entries
        if 45 * 60 <= item[0] <= 90 * 60
    ]
    selected = around_hour or sorted(entries, reverse=True)[:5]
    selected = sorted(selected, key=lambda item: item[0], reverse=True)[:5]
    rendered = [
        f"{name} (PID {pid}, {_format_duration(seconds)})"
        for seconds, name, pid in selected
    ]

    if around_hour:
        return f"These have been running about 1 hour: {', '.join(rendered)}."
    return (
        f"Longest-running processes: {', '.join(rendered)}. "
        "Full list is available via 'details'."
    )


def _parse_key_values(stdout: str) -> dict[str, str]:
    values = {}
    for line in stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().upper()
        if key:
            values[key] = value.strip()
    return values


def _as_int(value: str | None) -> int:
    try:
        return int((value or "").strip())
    except ValueError:
        return 0


def _analyze_service_process_count(stdout: str) -> str | None:
    values = _parse_key_values(stdout)
    if "SERVICE" not in values or "COUNT" not in values:
        return None

    service = values.get("SERVICE", "").strip()
    if not service:
        return None

    count = _as_int(values.get("COUNT"))
    master = _as_int(values.get("MASTER"))
    worker = _as_int(values.get("WORKER"))
    ports = []
    for port in values.get("PORTS", "").split(","):
        port = port.strip()
        if re.fullmatch(r"\d{1,5}", port):
            ports.append(port)
    port_text = (
        f"listening on ports {', '.join(ports)}"
        if ports else "no listening TCP ports found"
    )

    if count == 0:
        return f"{service}: no running processes; {port_text}."

    if service == "nginx" and (master or worker):
        return (
            f"{service}: {master} master + {worker} worker processes, "
            f"{port_text} (one instance with multiple listeners, not "
            "multiple servers)."
        )

    noun = "process" if count == 1 else "processes"
    return f"{service}: {count} running {noun}; {port_text}."


def _analyze_process_list(command: str, stdout: str) -> str | None:
    if "etime" in command and "pid" in command:
        elapsed = _analyze_elapsed_processes(stdout)
        if elapsed:
            return elapsed

    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) < 2:
        return None

    rows = lines[1:]
    processes = []
    for line in rows:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        try:
            cpu = float(parts[2])
        except ValueError:
            cpu = 0.0
        processes.append((cpu, _process_name(parts[10])))

    if not processes:
        return None

    top = []
    seen = set()
    for _, name in sorted(processes, key=lambda item: item[0], reverse=True):
        if name in seen:
            continue
        seen.add(name)
        top.append(name)
        if len(top) == 3:
            break

    if not top:
        return f"{len(processes)} processes running. Full list is available via 'details'."

    return (
        f"{len(processes)} processes running. "
        f"Top by CPU: {', '.join(top)}. "
        f"Full list is available via 'details'."
    )


def _analyze_system_uptime(stdout: str) -> str | None:
    text = " ".join(line.strip() for line in stdout.splitlines() if line.strip())
    if not text:
        return None
    if text.startswith("up "):
        text = text[3:]
    text = text.replace(",", "")
    return f"The machine has been up for {text}."


def _analyze_disk_usage(stdout: str) -> str | None:
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) < 2:
        return None

    target = None
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[-1] == "/":
            target = parts
            break
    if target is None:
        target = lines[1].split()
    if len(target) < 5:
        return None

    size, used, avail, pct = target[1], target[2], target[3], target[4]
    return f"Disk: {used} used of {size} ({pct}). {avail} free."


def _parse_size(value: str) -> float | None:
    match = re.match(r"^(?P<num>\d+(?:\.\d+)?)(?P<unit>[KMGTPE]i?|B)?$", value)
    if not match:
        return None

    num = float(match.group("num"))
    unit = (match.group("unit") or "Mi").lower()
    factors = {
        "b": 1 / (1024 * 1024),
        "k": 1 / 1024,
        "ki": 1 / 1024,
        "m": 1,
        "mi": 1,
        "g": 1024,
        "gi": 1024,
        "t": 1024 * 1024,
        "ti": 1024 * 1024,
        "p": 1024 * 1024 * 1024,
        "pi": 1024 * 1024 * 1024,
    }
    return num * factors.get(unit, 1)


def _format_memory_value(value: str) -> str:
    if re.match(r"^\d+(?:\.\d+)?$", value):
        return f"{value}Mi"
    return value


def _analyze_memory_usage(stdout: str) -> str | None:
    lines = [line for line in stdout.splitlines() if line.strip()]
    mem_line = None
    for line in lines:
        if line.startswith("Mem:"):
            mem_line = line
            break
    if not mem_line:
        return None

    parts = mem_line.split()
    if len(parts) < 4:
        return None

    total = parts[1]
    used = parts[2]
    available = parts[6] if len(parts) > 6 else parts[3]

    total_num = _parse_size(total)
    used_num = _parse_size(used)
    if not total_num or used_num is None:
        return None

    pct = int(round((used_num / total_num) * 100))
    return (
        f"Memory: {_format_memory_value(used)} used of "
        f"{_format_memory_value(total)} ({pct}%). "
        f"{_format_memory_value(available)} available."
    )
