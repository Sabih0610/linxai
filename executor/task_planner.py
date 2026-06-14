from __future__ import annotations

import os
import posixpath
import re
import shlex
from typing import TypedDict


class Step(TypedDict):
    id: str
    description: str
    command: str
    check: str
    produces: str
    requires: list[str]
    on_fail: str


def plan(intent, slots) -> list[Step]:
    data = slots if isinstance(slots, dict) else {}
    if intent != "env_setup":
        return []

    goal = " ".join(
        str(data.get(key, "") or "")
        for key in ("goal", "target", "explanation", "command")
    ).lower()
    stack = str(data.get("stack", "") or "").lower()
    repo_url = _repo_url(data) or _repo_url({"goal": goal})

    if repo_url:
        return _repo_install(repo_url, _path(data))
    if stack == "mern" or "mern" in goal or ("react" in goal and "node" in goal):
        return _mern_setup(_path(data) or "./mern-app")
    if (
        stack in {"python", "python_env", "venv"}
        or "python environment" in goal
        or "python env" in goal
    ):
        return _python_env(_path(data) or ".")
    return []


def fix_command(capability: str) -> str:
    cap = (capability or "").strip().lower()
    if cap in {"npm", "node", "nodejs", "npx"}:
        return _ensure_node_npm()
    if cap == "git":
        return _ensure_tool("git", ["git"], "git --version")
    if cap in {"pip3", "python_pip"}:
        return _ensure_tool("pip3", ["python3-pip"], "pip3 --version")
    if cap == "python_venv_tool":
        return (
            "python3 -m venv --help >/dev/null 2>&1 || "
            f"({_apt_install(['python3-venv'])})"
        )
    return ""


def _repo_url(slots: dict) -> str:
    for key in ("repo_url", "url", "repository", "target", "goal"):
        value = str(slots.get(key, "") or "").strip()
        match = re.search(r"https?://\S+", value)
        if match:
            return match.group(0).rstrip(".,);")
    return ""


def _path(slots: dict) -> str:
    for key in ("path", "location", "dir", "directory"):
        value = str(slots.get(key, "") or "").strip()
        if value:
            return os.path.expanduser(value)
    return ""


def _repo_name(repo_url: str) -> str:
    name = repo_url.rstrip("/").rsplit("/", 1)[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "repo"


def _clone_dir(repo_url: str, path: str) -> str:
    repo_name = _repo_name(repo_url)
    if path:
        cleaned = path.rstrip("/")
        if posixpath.basename(cleaned) == repo_name:
            return cleaned
        return posixpath.join(cleaned, repo_name)
    return posixpath.join(".", repo_name)


def _q(value: str) -> str:
    return shlex.quote(value)


def _apt_install(packages: list[str]) -> str:
    pkgs = " ".join(_q(pkg) for pkg in packages)
    return (
        "if [ \"$(id -u)\" -eq 0 ]; then "
        f"apt-get update && apt-get install -y {pkgs}; "
        "else "
        f"sudo apt-get update && sudo apt-get install -y {pkgs}; "
        "fi"
    )


def _ensure_tool(tool: str, packages: list[str], version_cmd: str = "") -> str:
    install = _apt_install(packages)
    verify = version_cmd or f"{tool} --version"
    return (
        f"which {_q(tool)} >/dev/null 2>&1 || ({install}); "
        f"which {_q(tool)} >/dev/null 2>&1 && {verify}"
    )


def _ensure_node_npm() -> str:
    install_node = _apt_install(["nodejs", "npm"])
    install_npm = _apt_install(["npm"])
    return (
        "if which node >/dev/null 2>&1 && which npm >/dev/null 2>&1; then "
        "node -v && npm -v; "
        f"else {install_node}; fi; "
        f"if ! which npm >/dev/null 2>&1; then {install_npm}; fi; "
        "node -v && npm -v"
    )


def _repo_install(repo_url: str, path: str) -> list[Step]:
    clone_dir = _clone_dir(repo_url, path)
    parent_dir = posixpath.dirname(clone_dir.rstrip("/")) or "."
    q_clone = _q(clone_dir)
    q_parent = _q(parent_dir)
    q_url = _q(repo_url)

    ensure_pip = _ensure_tool("pip3", ["python3-pip"], "pip3 --version")
    ensure_npm = _ensure_node_npm()
    install_deps = (
        "found=0; "
        f"if [ -f {q_clone}/requirements.txt ]; then "
        "found=1; "
        f"({ensure_pip}) && pip3 install -r {q_clone}/requirements.txt; "
        "fi; "
        f"if [ -f {q_clone}/package.json ]; then "
        "found=1; "
        f"({ensure_npm}) && (cd {q_clone} && npm install); "
        "fi; "
        "if [ \"$found\" -eq 0 ]; then "
        "echo 'No requirements.txt or package.json found; clone complete.'; "
        "fi"
    )
    deps_check = (
        "ok=1; "
        f"if [ -f {q_clone}/requirements.txt ]; then "
        "which pip3 >/dev/null 2>&1 || ok=0; "
        "fi; "
        f"if [ -f {q_clone}/package.json ]; then "
        f"[ -d {q_clone}/node_modules ] || ok=0; "
        "fi; "
        f"[ -d {q_clone} ] || ok=0; "
        "[ \"$ok\" -eq 1 ]"
    )

    return [
        {
            "id": "ensure_git",
            "description": "Ensure git is installed",
            "command": _ensure_tool("git", ["git"], "git --version"),
            "check": "which git >/dev/null 2>&1",
            "produces": "git",
            "requires": [],
            "on_fail": "Install git, then retry the repository setup.",
        },
        {
            "id": "clone_repo",
            "description": f"Clone repository into {clone_dir}",
            "command": (
                f"mkdir -p {q_parent} && "
                f"if [ -d {q_clone}/.git ]; then "
                f"git -C {q_clone} pull; "
                f"else git clone {q_url} {q_clone}; fi"
            ),
            "check": f"[ -d {q_clone} ] && [ -d {q_clone}/.git ]",
            "produces": "repo",
            "requires": ["git"],
            "on_fail": "Check the repository URL and network access, then retry cloning.",
        },
        {
            "id": "install_repo_deps",
            "description": "Detect project type and install dependencies",
            "command": install_deps,
            "check": deps_check,
            "produces": "repo_deps",
            "requires": ["repo"],
            "on_fail": "Install the missing language package manager, then rerun dependency installation.",
        },
    ]


def _mern_setup(path: str) -> list[Step]:
    base = path.rstrip("/") or "."
    server = posixpath.join(base, "server")
    client = posixpath.join(base, "client")
    q_base = _q(base)
    q_server = _q(server)
    q_client = _q(client)

    return [
        {
            "id": "ensure_node_npm",
            "description": "Ensure nodejs and npm are installed",
            "command": _ensure_node_npm(),
            "check": "node -v >/dev/null 2>&1 && npm -v >/dev/null 2>&1",
            "produces": "npm",
            "requires": [],
            "on_fail": "Install nodejs and npm, then retry the MERN setup.",
        },
        {
            "id": "create_mern_dirs",
            "description": f"Create MERN directories under {base}",
            "command": f"mkdir -p {q_client} {q_server}",
            "check": f"[ -d {q_client} ] && [ -d {q_server} ]",
            "produces": "mern_dirs",
            "requires": [],
            "on_fail": "Create the target directory with writable permissions, then retry.",
        },
        {
            "id": "install_server_deps",
            "description": "Initialize Express server dependencies",
            "command": (
                f"cd {q_server} && npm init -y && "
                "npm install express mongoose cors dotenv"
            ),
            "check": (
                f"[ -f {q_server}/package.json ] && "
                f"[ -d {q_server}/node_modules/express ] && "
                f"[ -d {q_server}/node_modules/mongoose ]"
            ),
            "produces": "server_deps",
            "requires": ["npm", "mern_dirs"],
            "on_fail": "Check npm connectivity and write permissions in the server directory.",
        },
        {
            "id": "scaffold_react_client",
            "description": "Scaffold React client",
            "command": (
                f"cd {q_base} && "
                "if [ -f client/package.json ]; then "
                "echo 'React client already exists.'; "
                "else npx --yes create-react-app client; fi"
            ),
            "check": f"[ -f {q_client}/package.json ]",
            "produces": "client_scaffold",
            "requires": ["npm", "mern_dirs"],
            "on_fail": "Check npm/npx availability and write permissions in the client directory.",
        },
    ]


def _python_env(path: str) -> list[Step]:
    base = path.rstrip("/") or "."
    venv = posixpath.join(base, "venv")
    q_base = _q(base)
    q_venv = _q(venv)

    return [
        {
            "id": "ensure_python_venv",
            "description": "Ensure python3-venv is installed",
            "command": (
                "python3 -m venv --help >/dev/null 2>&1 || "
                f"({_apt_install(['python3-venv'])})"
            ),
            "check": "python3 -m venv --help >/dev/null 2>&1",
            "produces": "python_venv_tool",
            "requires": [],
            "on_fail": "Install python3-venv, then retry the Python environment setup.",
        },
        {
            "id": "create_python_venv",
            "description": f"Create Python virtual environment at {venv}",
            "command": f"mkdir -p {q_base} && python3 -m venv {q_venv}",
            "check": f"[ -x {q_venv}/bin/python ]",
            "produces": "python_venv",
            "requires": ["python_venv_tool"],
            "on_fail": "Check that Python 3 and venv support are installed and the path is writable.",
        },
        {
            "id": "upgrade_venv_pip",
            "description": "Upgrade pip in the virtual environment",
            "command": f"{q_venv}/bin/python -m pip install --upgrade pip",
            "check": f"{q_venv}/bin/python -m pip --version >/dev/null 2>&1",
            "produces": "pip_ready",
            "requires": ["python_venv"],
            "on_fail": "Activate the virtual environment and retry pip upgrade manually.",
        },
    ]
