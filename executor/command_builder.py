import os
import posixpath
import re
import shlex

from ui.safe_paths import safe_cwd


PRUNE_PATHS = ("/proc", "/sys", "/dev", "/run")
DEFAULT_ROOTS = ("/etc", "/opt", "/var")
LOCATION_FILLERS = {"the", "folder", "directory", "dir"}
LOCATION_SEARCH_BASES = ("/home", "/opt", "/var")
KNOWN_ROOT_DIRS = {
    "home": "/home",
    "tmp": "/tmp",
    "opt": "/opt",
    "var": "/var",
    "etc": "/etc",
    "root": "/root",
    "usr": "/usr",
    "mnt": "/mnt",
    "srv": "/srv",
}
SERVICE_ALIASES = {
    "apache": "apache2",
    "httpd": "apache2",
}


def build(intent: str, slots) -> str:
    data = slots if isinstance(slots, dict) else {}
    if intent == "file_find":
        return _build_file_find(data)
    if intent == "file_create":
        return _build_file_create(data)
    if intent == "port_check":
        return _build_port_check(data)
    if intent == "port_list":
        return "ss -tlnp"
    if intent == "network_info":
        return _build_network_info(data)
    if intent == "service_status":
        return _build_service_status(data)
    if intent == "package_install":
        return _build_package_install(data)
    if intent in {
        "disk_usage", "memory_usage", "cpu_usage", "system_uptime",
        "system_info", "kernel_info",
    }:
        return _build_system_query(intent, data)
    if intent in {"service_start", "service_stop", "service_restart"}:
        return _build_service_command(intent, data)
    # QA fix (13 Nov 2026): an unknown intent used to return the model's own `command`
    # text, which the legacy controller ran with shell=True (and sudo when the plan asked).
    # The model never supplies executable text: unknown intents build nothing and are refused.
    return ""


def _user_home() -> str:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            return pwd.getpwnam(sudo_user).pw_dir
        except Exception:
            pass
    return os.path.expanduser("~")


def _is_root_path(value: str) -> bool:
    return value.startswith(("/", "~", "./", "../")) or value in {".", ".."}


def _extract_name(slots: dict) -> str | None:
    for key in ("name", "filename"):
        value = str(slots.get(key, "")).strip()
        if value:
            return os.path.basename(value)

    command = str(slots.get("command", "")).strip()
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    for idx, part in enumerate(parts):
        if part == "-name" and idx + 1 < len(parts):
            return parts[idx + 1]

    target = str(slots.get("target", "")).strip()
    if target and not _is_root_path(target):
        return os.path.basename(target)
    if target and os.path.basename(target) and "." in os.path.basename(target):
        return os.path.basename(target)
    return None


def _extract_roots(slots: dict) -> list[str]:
    roots = []
    for key in ("path", "dir", "directory", "root"):
        value = str(slots.get(key, "")).strip()
        if value and value != "/":
            roots.append(value)

    target = str(slots.get("target", "")).strip()
    if target and _is_root_path(target):
        if target != "/":
            if os.path.basename(target) and "." in os.path.basename(target):
                roots.append(os.path.dirname(target) or ".")
            else:
                roots.append(target)

    command = str(slots.get("command", "")).strip()
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if parts and parts[0] == "find":
        for part in parts[1:]:
            if part.startswith("-") or part in {"(", ")"}:
                break
            if part != "/":
                roots.append(part)

    cleaned = []
    for root in roots:
        root = os.path.expanduser(root)
        if root and root != "/" and root not in cleaned:
            cleaned.append(root)
    return cleaned


def _default_roots() -> list[str]:
    roots = [_user_home(), *DEFAULT_ROOTS, safe_cwd()]
    cleaned = []
    for root in roots:
        if root and root != "/" and root not in cleaned:
            cleaned.append(root)
    return cleaned


def _build_file_find(slots: dict) -> str:
    name = _extract_name(slots)
    if not name:
        name = "*"

    roots = _extract_roots(slots) or _default_roots()
    quoted_roots = " ".join(shlex.quote(root) for root in roots)
    quoted_name = shlex.quote(name)
    prune = r"\( " + " -o ".join(f"-path {p}" for p in PRUNE_PATHS) + r" \)"
    return (
        f"find {quoted_roots} -xdev {prune} -prune "
        f"-o -name {quoted_name} -print 2>/dev/null"
    )


def _extract_port(slots: dict) -> str:
    for key in ("port", "target"):
        value = str(slots.get(key, "")).strip()
        if value.isdigit() and 1 <= int(value) <= 65535:
            return value

    command = str(slots.get("command", "")).strip()
    patterns = (
        r"\bsport\s*=\s*:?(?P<port>\d{1,5})\b",
        r"grep\s+['\"]?:?(?P<port>\d{1,5})['\"]?",
        r":(?P<port>\d{1,5})\b",
    )
    for pattern in patterns:
        match = re.search(pattern, command)
        if not match:
            continue
        port = match.group("port")
        if 1 <= int(port) <= 65535:
            return port
    return ""


def _build_port_check(slots: dict) -> str:
    port = _extract_port(slots)
    if port:
        slots["port"] = port
        return f'ss -tlnp "sport = :{port}"'
    command = str(slots.get("command", "")).strip()
    return command or "ss -tlnp"


def _build_network_info(slots: dict) -> str:
    target = str(slots.get("target", "")).strip().lower()
    if target in {"ip", "ip_address", "address", "addresses"}:
        return "ip -brief addr"
    if target in {"mac", "mac_address", "hardware_address"}:
        return "cat /sys/class/net/*/address"
    if target in {"hostname", "host", "host_name"}:
        return "hostnamectl --static"
    if target in {"os", "distro", "os_version", "ubuntu_version"}:
        return "lsb_release -d"
    return str(slots.get("command", "")).strip()


def _build_service_status(slots: dict) -> str:
    target = _clean_service_target(str(slots.get("target", "")).strip())
    if not target:
        return _strip_systemctl_user(str(slots.get("command", "")).strip())
    slots["target"] = target
    return f"systemctl status {shlex.quote(target)}"


def _package_targets(slots: dict) -> list[str]:
    target = str(slots.get("target", "")).strip()
    if not target:
        target = str(slots.get("package", "")).strip()
    if not target:
        return []
    try:
        parts = shlex.split(target)
    except ValueError:
        parts = target.split()
    return [part for part in parts if part]


def _build_package_install(slots: dict) -> str:
    packages = _package_targets(slots)
    if not packages:
        return str(slots.get("command", "")).strip()
    quoted = " ".join(shlex.quote(pkg) for pkg in packages)
    return f"apt install -y {quoted}"


def _build_system_query(intent: str, slots: dict) -> str:
    target = str(slots.get("target", "")).strip().lower()
    query = str(slots.get("query", "")).strip().lower()

    if intent == "disk_usage":
        return "df -h --exclude-type=fuse.sshfs"
    if intent == "memory_usage":
        return "free -h"
    if intent == "cpu_usage":
        return "top -bn1 | grep Cpu"
    if intent == "system_uptime":
        return "uptime -p"
    if intent == "kernel_info":
        return "uname -r"

    if target in {"date", "time"}:
        return "date"
    if target == "whoami":
        return "whoami"
    if target == "who":
        return "who"
    if query == "version" and target:
        return f"{shlex.quote(target)} --version"
    if target in {"os", "os_version", "ubuntu_version", "distro"}:
        return "lsb_release -d"
    return str(slots.get("command", "")).strip() or "uname -a"


def _expand_create_path(path: str) -> str:
    path = str(path or "").strip()
    if path == "~" or path.startswith("~/"):
        return path.replace("~", _user_home(), 1)
    return os.path.expanduser(path)


def _has_parent(path: str) -> bool:
    return bool(posixpath.dirname(path.strip().rstrip("/")))


def _has_file_extension(path: str) -> bool:
    base = posixpath.basename(path.rstrip("/"))
    if base.startswith(".") and base not in {".", ".."}:
        return True
    return bool(posixpath.splitext(base)[1])


def _target_from_slots(slots: dict) -> str:
    for key in ("target", "name", "filename"):
        value = str(slots.get(key, "")).strip()
        if value:
            return value
    return ""


def _location_from_slots(slots: dict) -> str:
    for key in ("location", "parent", "parentdir", "folder", "directory", "dir"):
        value = str(slots.get(key, "")).strip()
        if value:
            return value
    return ""


def _split_location(value: str) -> list[str]:
    try:
        parts = shlex.split(value or "", posix=True)
    except ValueError:
        parts = (value or "").split()
    return [
        part for part in parts
        if part and part.strip().lower() not in LOCATION_FILLERS
    ]


def _normalize_location(value: str) -> str:
    parts = _split_location(value)
    if not parts:
        return ""

    first_segment = parts[0].split("/", 1)[0].lower()
    if first_segment in KNOWN_ROOT_DIRS:
        mapped_root = KNOWN_ROOT_DIRS[first_segment]
        cwd_relative = os.path.join(safe_cwd(), first_segment)
        if not os.path.isdir(cwd_relative):
            suffix_parts = []
            if "/" in parts[0]:
                suffix_parts.append(parts[0].split("/", 1)[1])
            suffix_parts.extend(parts[1:])
            current = mapped_root
            for part in suffix_parts:
                if part:
                    current = posixpath.join(current, part)
            return current

    if len(parts) > 1 and _is_root_path(parts[0]):
        current = parts[0]
        for part in parts[1:]:
            current = posixpath.join(current, part)
        return current

    if len(parts) > 1 and any(
        "/" in part or part.startswith(("~", ".", "..")) for part in parts
    ):
        current = parts[0]
        for part in parts[1:]:
            current = posixpath.join(current, part)
        return current

    return " ".join(parts)


def _is_bare_location(value: str) -> bool:
    if not value:
        return False
    return (
        "/" not in value
        and not value.startswith(("~", ".", ".."))
        and not os.path.isabs(value)
    )


def _is_known_root_location(value: str) -> bool:
    normalized = _expand_create_path(value)
    return any(
        normalized == root or normalized.startswith(root + "/")
        for root in KNOWN_ROOT_DIRS.values()
    )


def _dedupe_paths(paths: list[str]) -> list[str]:
    seen = set()
    cleaned = []
    for path in paths:
        if not path:
            continue
        expanded = os.path.abspath(os.path.expanduser(path))
        key = os.path.realpath(expanded)
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(expanded)
    return cleaned


def _location_search_bases() -> list[str]:
    return _dedupe_paths([safe_cwd(), _user_home(), *LOCATION_SEARCH_BASES])


def _existing_location_matches(name: str) -> list[str]:
    matches = []
    for base in _location_search_bases():
        candidate = os.path.join(base, name)
        if os.path.isdir(candidate):
            matches.append(candidate)
    return _dedupe_paths(matches)


def resolve_file_create_location(slots: dict) -> dict:
    for key in ("file_create_location_ambiguous", "file_create_location_choices"):
        slots.pop(key, None)

    raw_location = _location_from_slots(slots)
    location = _normalize_location(raw_location)
    if not location:
        slots["location"] = ""
        slots.pop("file_create_location_note", None)
        return {"status": "ok", "location": ""}

    if _is_known_root_location(location) or not _is_bare_location(location):
        slots["location"] = _expand_create_path(location)
        return {"status": "ok", "location": slots["location"]}

    cwd_candidate = os.path.abspath(os.path.join(safe_cwd(), location))
    if os.path.isdir(cwd_candidate):
        slots["location"] = cwd_candidate
        slots["file_create_location_note"] = (
            f"Using existing folder {cwd_candidate}."
        )
        return {"status": "ok", "location": cwd_candidate}

    matches = _existing_location_matches(location)
    if len(matches) == 1:
        slots["location"] = matches[0]
        slots["file_create_location_note"] = (
            f"Using existing folder {matches[0]}."
        )
        return {"status": "ok", "location": matches[0]}

    if len(matches) > 1:
        slots["location"] = location
        slots["file_create_location_ambiguous"] = True
        slots["file_create_location_choices"] = matches
        return {"status": "ambiguous", "location": location, "choices": matches}

    new_location = os.path.abspath(os.path.join(safe_cwd(), location))
    slots["location"] = new_location
    slots["file_create_location_note"] = (
        f"Creating new folder {new_location}."
    )
    return {"status": "ok", "location": new_location}


def _shell_parts(command: str) -> list[str]:
    try:
        return shlex.split(command or "", posix=True)
    except ValueError:
        return (command or "").split()


def _path_from_redirect(parts: list[str]) -> str:
    for idx, part in enumerate(parts[:-1]):
        if part in {">", ">>", "1>", "1>>"}:
            return parts[idx + 1]
    for part in parts:
        match = re.match(r"^(?:1?>|1?>>)(.+)$", part)
        if match:
            return match.group(1)
    return ""


def _path_from_create_command(command: str) -> str:
    parts = _shell_parts(command)
    if not parts:
        return ""

    redirected = _path_from_redirect(parts)
    if redirected:
        return redirected

    tool = posixpath.basename(parts[0])
    if tool in {"touch", "mkdir"}:
        candidates = [p for p in parts[1:] if p and not p.startswith("-")]
        if candidates:
            return candidates[-1]
    return ""


def _content_from_slots(slots: dict) -> str:
    for key in ("content", "text", "body"):
        value = slots.get(key)
        if value is not None and str(value) != "":
            return str(value)
    return ""


def _requested_directory(slots: dict, target_path: str) -> bool:
    if _has_file_extension(target_path):
        return False

    command = str(slots.get("command", "")).strip().lower()
    explanation = str(slots.get("explanation", "")).lower()
    kind = str(
        slots.get("kind")
        or slots.get("type")
        or slots.get("object_type")
        or slots.get("target_type")
        or ""
    ).lower()

    if kind in {"file", "regular_file"}:
        return False
    if command.startswith(("touch", "printf", "echo")) or _path_from_redirect(
        _shell_parts(command)
    ):
        return False
    if "file" in explanation:
        return False

    if kind in {"folder", "directory", "dir"}:
        return True
    if command.startswith("mkdir"):
        return True
    if "folder" in explanation or "directory" in explanation:
        return True
    return False


def _full_create_path(slots: dict) -> str:
    target = _target_from_slots(slots)
    resolution = resolve_file_create_location(slots)
    location = "" if resolution.get("status") == "ambiguous" else _location_from_slots(slots)
    command_path = _path_from_create_command(str(slots.get("command", "")))

    if location:
        base_source = target or command_path
        base = posixpath.basename(str(base_source).rstrip("/"))
        if (
            not target
            and base
            and posixpath.basename(location.rstrip("/")) == base
            and _has_file_extension(base)
        ):
            location = posixpath.dirname(location.rstrip("/")) or "."
            slots["location"] = location
        return _expand_create_path(posixpath.join(location, base))

    if command_path and (
        not target
        or (not _has_parent(target) and posixpath.basename(command_path) == target)
    ):
        target = command_path

    return _expand_create_path(target)


def _build_file_create(slots: dict) -> str:
    path = _full_create_path(slots)
    if slots.get("file_create_location_ambiguous"):
        choices = ", ".join(slots.get("file_create_location_choices", []))
        msg = (
            "Multiple matching folders exist. Choose one before creating the "
            f"file: {choices}"
        )
        return f"printf '%s\\n' {shlex.quote(msg)} >&2; false"

    if not path:
        return str(slots.get("command", "")).strip()

    is_directory = _requested_directory(slots, path)
    slots["target"] = path
    slots["file_create_kind"] = "directory" if is_directory else "file"

    if is_directory:
        return f"mkdir -p {shlex.quote(path)}"

    parent = posixpath.dirname(path.rstrip("/")) or "."
    quoted_parent = shlex.quote(parent)
    quoted_path = shlex.quote(path)
    content = _content_from_slots(slots)

    if content:
        return (
            f"mkdir -p {quoted_parent} && "
            f"printf '%s\\n' {shlex.quote(content)} > {quoted_path}"
        )
    return f"mkdir -p {quoted_parent} && touch {quoted_path}"


def _strip_systemctl_user(command: str) -> str:
    if not command:
        return ""
    parts = _shell_parts(command)
    if not parts:
        return command.strip()
    cleaned = [part for part in parts if part != "--user"]
    if cleaned != parts:
        return " ".join(shlex.quote(part) for part in cleaned)
    return command.strip()


def _clean_service_target(target: str) -> str:
    parts = _shell_parts(target)
    if not parts:
        cleaned_target = target.strip()
        suffix = ".service" if cleaned_target.endswith(".service") else ""
        base = cleaned_target[:-8] if suffix else cleaned_target
        mapped = SERVICE_ALIASES.get(base.lower(), base)
        return f"{mapped}{suffix}" if suffix else mapped
    cleaned = [part for part in parts if part and part != "--user"]
    if not cleaned:
        return ""
    target = cleaned[0]
    suffix = ".service" if target.endswith(".service") else ""
    base = target[:-8] if suffix else target
    mapped = SERVICE_ALIASES.get(base.lower(), base)
    return f"{mapped}{suffix}" if suffix else mapped


def _service_target_from_command(command: str, action: str) -> str:
    parts = _shell_parts(command)
    if not parts:
        return ""
    for idx, part in enumerate(parts):
        if part != action:
            continue
        for candidate in parts[idx + 1:]:
            if candidate.startswith("-"):
                continue
            return _clean_service_target(candidate)
    return ""


def _build_service_command(intent: str, slots: dict) -> str:
    action = {
        "service_start": "start",
        "service_stop": "stop",
        "service_restart": "restart",
    }[intent]
    target = _clean_service_target(str(slots.get("target", "")).strip())
    if not target:
        target = _service_target_from_command(
            str(slots.get("command", "")),
            action,
        )
    if not target:
        return _strip_systemctl_user(str(slots.get("command", "")).strip())

    slots["target"] = target
    return f"systemctl {action} {shlex.quote(target)}"
