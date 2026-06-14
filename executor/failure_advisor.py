import posixpath
import re
import shlex


NEVER_INSTALL = {
    "touch", "cat", "ls", "cd", "echo", "mkdir", "rm", "cp", "mv", "pwd",
    "chmod", "chown", "printf", "test", "grep", "find", "head", "tail",
    "sed", "awk",
}

PACKAGE_BY_BINARY = {
    "pip": "python3-pip",
    "pip3": "python3-pip",
    "node": "nodejs npm",
    "npm": "nodejs npm",
    "nc": "netcat-openbsd",
    "ncat": "ncat",
    "netcat": "netcat-openbsd",
    "python": "python3",
}

SAME_NAME_PACKAGES = {
    "curl", "wget", "git", "htop", "jq", "tree", "nmap", "tcpdump", "lsof",
    "vim", "nano", "rsync", "tmux", "screen", "strace",
}

FILE_WRITE_TOOLS = {
    "touch", "cp", "mv", "install", "ln", "tee", "dd", "mkdir", "truncate",
}


def diagnose(
    intent: str,
    command: str,
    stderr: str,
    exit_code: int,
    state_registry,
) -> dict | None:
    try:
        text = stderr or ""
        lowered = text.lower()

        if any(s in lowered for s in (
            "address already in use",
            "bind",
            "port",
        )):
            return _port_conflict(command, text, state_registry)

        if any(s in lowered for s in (
            "permission denied",
            "must be root",
            "operation not permitted",
        )):
            return _permission_denied(command)

        if "no such file or directory" in lowered:
            missing_path = _missing_target_path(command, text)
            if missing_path:
                return missing_path

        missing_binary = _extract_missing_binary(command, text)
        if missing_binary:
            if missing_binary in NEVER_INSTALL:
                return _path_or_usage_error(command, missing_binary)
            return _missing_tool(missing_binary)

        if "unit" in lowered and (
            "not found" in lowered or "could not be found" in lowered
        ):
            return _missing_unit(command, text)
    except Exception:
        return None
    return None


def _result(
    explanation: str,
    suggestion: str,
    suggested_command: str | None = None,
) -> dict:
    return {
        "explanation": explanation,
        "suggestion": suggestion,
        "suggested_command": suggested_command,
        "needs_confirit": bool(suggested_command),
    }


def _extract_port(command: str, stderr: str = "") -> int | None:
    sources = (command or "", stderr or "")
    patterns = (
        r"(?:--port|-p)\s+['\"]?(?P<port>\d{2,5})\b",
        r"\bport\s+(?P<port>\d{2,5})\b",
        r"\b:(?P<port>\d{2,5})\b",
        r"\b(?P<port>80|443|8080|8443|3000|5000|8000|9000)\b",
    )
    for source in sources:
        for pattern in patterns:
            match = re.search(pattern, source, re.IGNORECASE)
            if not match:
                continue
            port = int(match.group("port"))
            if 0 < port <= 65535:
                return port
    return None


def _swap_port(command: str, old_port: int, new_port: int = 2222) -> str | None:
    old = str(old_port)
    new = str(new_port)
    replacements = (
        (rf"(--port\s+['\"]?){old}\b", rf"\g<1>{new}"),
        (rf"(-p\s+['\"]?){old}\b", rf"\g<1>{new}"),
        (rf":{old}\b", f":{new}"),
        (rf"\b{old}\b", new),
    )
    for pattern, repl in replacements:
        swapped, count = re.subn(pattern, repl, command, count=1)
        if count:
            return swapped
    return None


def _port_conflict(command: str, stderr: str, state_registry) -> dict | None:
    port = _extract_port(command, stderr)
    if not port:
        return None

    info = None
    if state_registry is not None:
        try:
            state_registry.refresh()
            info = state_registry.get_port_info(port)
        except Exception:
            info = None

    proc = "another process"
    pid = "unknown"
    if info:
        proc = info.get("process") or proc
        pid = info.get("pid") or pid

    return _result(
        f"Port {port} is already used by {proc} (PID {pid}).",
        f"Use a different port (e.g. 2222) or stop {proc} first?",
        _swap_port(command, port),
    )


def _permission_denied(command: str) -> dict | None:
    command = command.strip()
    if not command:
        return None
    if command.startswith("sudo "):
        suggested = None
    else:
        suggested = "sudo " + command
    return _result(
        "This action needs root privileges.",
        "Retry with sudo?",
        suggested,
    )


def _shell_tool(command: str) -> str | None:
    tokens = _shell_tokens(command)
    if not tokens:
        return None

    tool = tokens[0]
    tool = tool.split("/")[-1]
    if not tool or tool in {"sh", "bash", "env", "command"}:
        return None
    return tool


def _shell_tokens(command: str) -> list[str]:
    try:
        tokens = shlex.split((command or "").strip(), posix=True)
    except ValueError:
        tokens = (command or "").strip().split()

    if tokens and tokens[0] == "sudo":
        tokens = tokens[1:]

    if tokens and tokens[0] == "env":
        tokens = tokens[1:]
        while tokens and ("=" in tokens[0] or tokens[0].startswith("-")):
            tokens = tokens[1:]

    if tokens and tokens[0] == "command":
        tokens = tokens[1:]

    return tokens


def _clean_tool_name(tool: str) -> str:
    tool = (tool or "").strip().strip("'\"`")
    tool = tool.rstrip(":")
    return tool.split("/")[-1]


def _extract_missing_binary(command: str, stderr: str) -> str | None:
    patterns = (
        r"/bin/sh:\s+\d+:\s+(\S+):\s+not found",
        r"(\S+):\s+command not found",
    )
    for pattern in patterns:
        match = re.search(pattern, stderr or "", re.IGNORECASE)
        if match:
            tool = _clean_tool_name(match.group(1))
            return tool or None

    if re.search(r"\bcommand not found\b", stderr or "", re.IGNORECASE):
        return _shell_tool(command)

    return None


def _missing_tool(tool: str) -> dict | None:
    package = _package_for_tool(tool)
    if not package:
        return _result(
            f"{tool} is not installed.",
            f"I do not know the apt package for {tool}. Install the correct package and retry.",
            None,
        )

    return _result(
        f"{tool} is not installed.",
        "Install it?",
        f"apt install -y {package}",
    )


def _package_for_tool(tool: str) -> str | None:
    if tool in NEVER_INSTALL:
        return None
    if tool in PACKAGE_BY_BINARY:
        return PACKAGE_BY_BINARY[tool]
    if tool in SAME_NAME_PACKAGES:
        return tool
    return None


def _missing_target_path(command: str, stderr: str) -> dict | None:
    if not _is_file_write_command(command):
        return None

    parent = _extract_parent_dir(command)
    if not parent:
        parent = _extract_parent_dir_from_stderr(stderr)
    if not parent:
        return None

    suggested = f"mkdir -p {shlex.quote(parent)} && {command.strip()}"
    return _result(
        "The target directory does not exist.",
        "Create the parent directory first?",
        suggested,
    )


def _path_or_usage_error(command: str, tool: str) -> dict | None:
    missing_path = _missing_target_path(command, "")
    if missing_path:
        return missing_path
    return _result(
        f"{tool} is a standard system tool, so this looks like a path or usage error.",
        "Check the target path and command syntax, then try again.",
        None,
    )


def _extract_parent_dir(command: str) -> str | None:
    tokens = _shell_tokens(command)
    if not tokens:
        return None

    redirected = _parent_from_redirection(tokens)
    if redirected:
        return redirected

    tool = tokens[0].split("/")[-1]
    args = tokens[1:]
    if tool == "dd":
        for arg in args:
            if arg.startswith("of="):
                return _parent_from_path(arg[3:])
        return None

    if tool in {"cat", "echo", "printf"}:
        return None

    if tool not in FILE_WRITE_TOOLS:
        return None

    paths = [
        arg for arg in args
        if arg and not arg.startswith("-") and not _looks_like_option_value(arg)
    ]
    if not paths:
        return None

    return _parent_from_path(paths[-1])


def _is_file_write_command(command: str) -> bool:
    tokens = _shell_tokens(command)
    if not tokens:
        return False
    if _parent_from_redirection(tokens):
        return True
    tool = tokens[0].split("/")[-1]
    return tool in FILE_WRITE_TOOLS


def _parent_from_redirection(tokens: list[str]) -> str | None:
    redirect_tokens = {">", ">>", "1>", "1>>"}
    for i, token in enumerate(tokens[:-1]):
        if token in redirect_tokens:
            parent = _parent_from_path(tokens[i + 1])
            if parent:
                return parent

    for token in tokens:
        match = re.match(r"^(?:1?>|1?>>)(.+)$", token)
        if match:
            parent = _parent_from_path(match.group(1))
            if parent:
                return parent

    return None


def _looks_like_option_value(arg: str) -> bool:
    return re.fullmatch(r"\d+", arg) is not None


def _parent_from_path(path: str) -> str | None:
    path = (path or "").strip().strip("'\"")
    if not path or path.startswith("-") or "://" in path:
        return None
    if path in {"/", ".", ".."}:
        return None
    parent = posixpath.dirname(path.rstrip("/"))
    if parent in {"", "."}:
        return None
    return parent


def _extract_parent_dir_from_stderr(stderr: str) -> str | None:
    match = re.search(
        r"(?:cannot\s+\w+|cannot\s+touch|can't\s+\w+)\s+['\"](?P<path>[^'\"]+)['\"]",
        stderr or "",
        re.IGNORECASE,
    )
    if match:
        return _parent_from_path(match.group("path"))
    return None


def _missing_unit(command: str, stderr: str) -> dict | None:
    if "systemctl" not in command:
        return None

    name = None
    match = re.search(
        r"Unit\s+(?P<name>[\w@.-]+)(?:\.service)?\s+"
        r"(?:not found|could not be found)",
        stderr,
        re.IGNORECASE,
    )
    if match:
        name = re.sub(r"\.service$", "", match.group("name"))
    else:
        cmd_match = re.search(
            r"\bsystemctl\s+\w+\s+(?P<name>[\w@.-]+)",
            command,
        )
        if cmd_match:
            name = re.sub(r"\.service$", "", cmd_match.group("name"))

    if not name:
        return None

    return _result(
        f"There is no service named {name}.",
        "Did you mean a different service?",
        None,
    )
