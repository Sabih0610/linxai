import os
import posixpath
import re
import shlex


PROTECTED_PATHS = {
    "/",
    "/bin",
    "/sbin",
    "/usr",
    "/usr/bin",
    "/usr/sbin",
    "/lib",
    "/lib64",
    "/etc",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/var",
    "/root",
    "/home",
    "/usr/lib",
}

SAFE_REDIRECT_TARGETS = {
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
    "/dev/stdout",
    "/dev/stderr",
}

CRITICAL_FILE_TARGETS = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
}

SHELL_SEPARATORS = {";", "&&", "||", "|"}


def check_destructive_command(command: str) -> dict | None:
    tokens = _shell_tokens(command)
    if not tokens:
        return None

    for segment in _split_segments(tokens):
        segment = _strip_wrappers(segment)
        if not segment:
            continue

        redirect = _check_redirects(segment)
        if redirect:
            return redirect

        tool = posixpath.basename(segment[0])
        if tool in {"rm", "rmdir"}:
            finding = _check_rm_like(segment, "Removing")
        elif tool in {"apt", "apt-get"}:
            finding = _check_apt_remove(segment)
        elif tool == "mv":
            finding = _check_targets(segment[1:], "Moving", skip_options=True)
        elif tool in {"chmod", "chown"}:
            finding = _check_recursive_metadata_change(segment, tool)
        elif tool == "dd":
            finding = _check_dd(segment)
        elif tool == "mkfs" or tool.startswith("mkfs."):
            finding = _check_mkfs(segment)
        else:
            finding = None

        if finding:
            return finding

    return None


def _shell_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command or "", posix=True)
    except ValueError:
        return (command or "").split()


def _split_segments(tokens: list[str]) -> list[list[str]]:
    segments = []
    current = []
    for token in tokens:
        if token in SHELL_SEPARATORS:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return segments


def _strip_wrappers(tokens: list[str]) -> list[str]:
    tokens = list(tokens)
    while tokens:
        if tokens[0] == "sudo":
            tokens = tokens[1:]
            continue
        if tokens[0] == "command":
            tokens = tokens[1:]
            continue
        if tokens[0] == "env":
            tokens = tokens[1:]
            while tokens and ("=" in tokens[0] or tokens[0].startswith("-")):
                tokens = tokens[1:]
            continue
        break
    return tokens


def _check_redirects(tokens: list[str]) -> dict | None:
    for index, token in enumerate(tokens):
        target = None
        if token in {">", ">>", "1>", "1>>", "2>", "2>>", "&>"} and index + 1 < len(tokens):
            target = tokens[index + 1]
        else:
            match = re.match(r"^(?:(?:[12])?>>|(?:[12])?>|&>)(?P<target>.+)$", token)
            if match:
                target = match.group("target")

        if not target:
            continue
        if _is_fd_redirect(target) or _is_safe_redirect_target(target):
            continue

        protected = protected_target(target) or _critical_file_target(target)
        if protected:
            return _finding(protected, "Overwriting")

    return None


def _check_rm_like(tokens: list[str], action: str) -> dict | None:
    targets = _target_args(tokens[1:], skip_options=True)
    return _check_targets(targets, action, skip_options=False)


def _check_apt_remove(tokens: list[str]) -> dict | None:
    if len(tokens) < 2 or tokens[1] not in {"remove", "purge"}:
        return None
    targets = _target_args(tokens[2:], skip_options=True)
    return _check_targets(targets, "Removing", skip_options=False)


def _check_recursive_metadata_change(tokens: list[str], tool: str) -> dict | None:
    args = tokens[1:]
    recursive = any(_is_recursive_option(arg) for arg in args)
    if not recursive:
        return None

    non_options = _target_args(args, skip_options=True)
    if len(non_options) >= 2:
        targets = non_options[1:]
    else:
        targets = non_options

    action = "Recursively changing ownership of"
    if tool == "chmod":
        action = "Recursively changing permissions on"
    return _check_targets(targets, action, skip_options=False)


def _check_dd(tokens: list[str]) -> dict | None:
    for token in tokens[1:]:
        if not token.startswith("of="):
            continue
        target = token[3:]
        protected = protected_target(target) or _device_target(target)
        if protected:
            return _finding(protected, "Overwriting")
    return None


def _check_mkfs(tokens: list[str]) -> dict | None:
    targets = _target_args(tokens[1:], skip_options=True)
    for target in targets:
        protected = protected_target(target) or _device_target(target)
        if protected:
            return _finding(protected, "Formatting")
    return None


def _check_targets(args: list[str], action: str,
                   skip_options: bool = True) -> dict | None:
    targets = _target_args(args, skip_options=skip_options)
    for target in targets:
        protected = protected_target(target)
        if protected:
            return _finding(protected, action)
    return None


def _target_args(args: list[str], skip_options: bool = True) -> list[str]:
    targets = []
    stop_options = False
    skip_next_redirect_target = False
    for arg in args:
        if skip_next_redirect_target:
            skip_next_redirect_target = False
            continue
        if arg == "--":
            stop_options = True
            continue
        if _is_separate_redirection_token(arg):
            skip_next_redirect_target = True
            continue
        if skip_options and not stop_options and arg.startswith("-"):
            continue
        if _is_redirection_token(arg):
            continue
        targets.append(arg)
    return targets


def _is_recursive_option(arg: str) -> bool:
    if not arg.startswith("-") or arg == "--":
        return False
    return "R" in arg or "recursive" in arg


def _is_redirection_token(arg: str) -> bool:
    return (
        _is_separate_redirection_token(arg)
        or re.match(r"^(?:(?:[12])?>>|(?:[12])?>|&>)", arg) is not None
    )


def _is_separate_redirection_token(arg: str) -> bool:
    return arg in {">", ">>", "1>", "1>>", "2>", "2>>", "&>", "<", "0<"}


def _is_fd_redirect(target: str) -> bool:
    return (target or "").strip().startswith("&")


def _is_safe_redirect_target(path: str) -> bool:
    normalized = _normalize_path(path, resolve=False)
    return normalized in SAFE_REDIRECT_TARGETS


def protected_target(path: str) -> str | None:
    raw_normalized = _normalize_path(path, resolve=False)
    if not raw_normalized:
        return None

    raw_match = _match_protected(raw_normalized)
    if raw_match:
        return raw_match

    resolved = _normalize_path(path, resolve=True)
    if not resolved:
        return None

    return _match_protected(resolved)


def _critical_file_target(path: str) -> str | None:
    raw_normalized = _normalize_path(path, resolve=False)
    if raw_normalized in CRITICAL_FILE_TARGETS:
        return raw_normalized

    resolved = _normalize_path(path, resolve=True)
    if resolved in CRITICAL_FILE_TARGETS:
        return resolved

    return None


def _device_target(path: str) -> str | None:
    raw_normalized = _normalize_path(path, resolve=False)
    if raw_normalized.startswith("/dev/") and not _is_safe_redirect_target(raw_normalized):
        return raw_normalized

    resolved = _normalize_path(path, resolve=True)
    if resolved.startswith("/dev/") and not _is_safe_redirect_target(resolved):
        return resolved

    return None


def _match_protected(normalized: str) -> str | None:
    if normalized in {"/*", "/"}:
        return "/"

    for protected in sorted(PROTECTED_PATHS, key=len, reverse=True):
        if protected == "/":
            continue
        if normalized == protected or normalized == f"{protected}/*":
            return protected
        if protected.startswith(normalized.rstrip("/") + "/"):
            return normalized

    return None


def _normalize_path(path: str, resolve: bool) -> str:
    path = (path or "").strip().strip("'\"")
    if not path:
        return ""

    if path.endswith("/*"):
        base = path[:-2] or "/"
        normalized_base = _normalize_path(base, resolve=resolve)
        return f"{normalized_base}/*" if normalized_base != "/" else "/*"

    if not path.startswith("/"):
        return ""

    if resolve and os.name == "posix":
        try:
            return os.path.realpath(path)
        except Exception:
            pass

    return posixpath.normpath(path)


def _finding(path: str, action: str) -> dict:
    return {
        "path": path,
        "action": action,
        "reason": _reason(path, action),
    }


def _reason(path: str, action: str) -> str:
    if action == "Removing":
        consequence = "Removing it would break the system."
    elif action == "Moving":
        consequence = "Moving it would break the system."
    elif action.startswith("Recursively"):
        consequence = "Changing it recursively would break the system."
    elif action == "Formatting":
        consequence = "Formatting it would destroy critical system data."
    else:
        consequence = "Overwriting it would break the system."

    return (
        f"Blocked: '{path}' is a critical system directory. "
        f"{consequence} This action is not permitted."
    )


if __name__ == "__main__":
    assert check_destructive_command(
        "which node >/dev/null 2>&1 && which npm >/dev/null 2>&1 || apt install -y nodejs npm"
    ) is None
    assert check_destructive_command("rm -rf /bin") is not None
    assert check_destructive_command("rm -rf /home") is not None
    assert check_destructive_command("rm -rf /var") is not None
    assert check_destructive_command("rm -rf /") is not None
    assert check_destructive_command("rm -rf /usr") is not None
    assert check_destructive_command("rm -rf /etc") is not None
    assert check_destructive_command("echo hi >/dev/null") is None
    assert check_destructive_command("dd if=/tmp/image of=/dev/sda") is not None
    assert check_destructive_command("dd if=/tmp/x of=/dev/sda") is not None
    assert check_destructive_command("echo hi > /etc/passwd") is not None
    assert check_destructive_command("cat /proc/cpuinfo") is None
    assert check_destructive_command("rm -rf /home/linxai/oldproject") is None
    assert check_destructive_command("rm -rf /var/www/site") is None
    assert check_destructive_command("chown -R u /home/u/app") is None
    assert check_destructive_command(
        "rm -rf /home/linxai/development/node_modules"
    ) is None
