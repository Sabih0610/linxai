"""Linux adapters for the registry's bounded unprivileged action vocabulary."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from contextlib import ExitStack

from .registry import Privilege
from .service import Execution, Identity, Observation


class LinuxSystemAdapter:
    OUTPUT_LIMIT = 1024 * 1024

    def resolve_identity(self):
        if sys.platform != "linux":
            raise RuntimeError("Operations require Linux; Windows unit tests are not Linux integration")
        if os.getgid() != os.getegid():
            raise RuntimeError("Setgid execution is not an ordinary account context")
        import pwd
        uid, euid = os.getuid(), os.geteuid()
        return Identity(uid, euid, pwd.getpwuid(uid).pw_name)

    def _run(self, op_id, argv, stdin, timeout_s):
        # Defensive identity gate for check subprocesses as well as execution.
        if not self.resolve_identity().ordinary():
            return Execution(op_id, argv, None, started=False, error="Ordinary account required")
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "SYSTEMD_PAGER": "cat"}
        started = False
        try:
            # Files cap retained output without unbounded capture_output memory.
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                proc = subprocess.run(list(argv), input=stdin, stdout=out, stderr=err,
                                      shell=False, timeout=timeout_s, cwd="/", env=env,
                                      close_fds=True, start_new_session=True)
                started = True
                out.seek(0)
                err.seek(0)
                stdout, stderr = out.read(self.OUTPUT_LIMIT + 1), err.read(self.OUTPUT_LIMIT + 1)
            truncated = len(stdout) > self.OUTPUT_LIMIT or len(stderr) > self.OUTPUT_LIMIT
            return Execution(op_id, argv, proc.returncode,
                             stdout[:self.OUTPUT_LIMIT].decode("utf-8", errors="replace"),
                             stderr[:self.OUTPUT_LIMIT].decode("utf-8", errors="replace"),
                             error="Output limit exceeded" if truncated else "")
        except subprocess.TimeoutExpired:
            return Execution(op_id, argv, None, error="Command deadline exceeded")
        except OSError as exc:
            return Execution(op_id, argv, None, started=started, error=f"Command I/O or launch failed: {exc}")

    def execute(self, op_id, prepared, identity):
        if prepared.contract.privilege is not Privilege.UNPRIVILEGED:
            return Execution(op_id, prepared.argv, None, started=False, error="Trusted privilege broker required")
        if self.resolve_identity() != identity:
            return Execution(op_id, prepared.argv, None, started=False, error="Identity changed before dispatch")
        return self._run(op_id, prepared.argv, prepared.stdin, prepared.contract.timeout_s)

    @staticmethod
    def _signature(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_mode)

    def _directories(self, path, uid, *, private_leaf=False):
        """Ownership and no-symlink checks; do not modify existing permissions."""
        paths = list(reversed((Path(path), *Path(path).parents)))
        evidence = []
        for directory in paths:
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, uid}
                    or info.st_mode & 0o022):
                raise PermissionError("Directory chain has a symlink, foreign owner or untrusted writer")
            evidence.append((str(directory), self._signature(info)))
        if private_leaf and (info.st_uid != uid or info.st_mode & 0o077):
            raise PermissionError("Workspace must be private and owned by the requesting account")
        return json.dumps(evidence)

    def _trusted_executable(self, path):
        original = Path(path)
        resolved = original.resolve(strict=True)
        # Validate both the link's containing tree and the resolved executable.
        self._directories(original.parent, 0)
        self._directories(resolved.parent, 0)
        link_info, info = original.lstat(), resolved.stat()
        if (link_info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & (0o022 | stat.S_ISUID | stat.S_ISGID)
                or not os.access(resolved, os.X_OK)):
            raise PermissionError("Executable is not a trusted root-owned non-setuid binary")
        return json.dumps((str(resolved), self._signature(link_info), self._signature(info),
                           info.st_size, info.st_mtime_ns))

    def _service_properties(self, op_id, service):
        argv = ("/usr/bin/systemctl", "--no-pager", "show",
                "--property=Id,LoadState,ActiveState,SubState,UnitFileState", "--", service)
        self._trusted_executable(argv[0])
        result = self._run(op_id, argv, b"", 3)
        if result.error or result.returncode != 0:
            raise RuntimeError(result.error or "Service state query failed")
        return self._properties(result.stdout)

    @staticmethod
    def _properties(text):
        result = {}
        for line in text.splitlines():
            if "=" not in line:
                raise ValueError("Malformed service properties")
            key, value = line.split("=", 1)
            if key in result:
                raise ValueError("Duplicate service property")
            result[key] = value
        return result

    def check(self, op_id, required, identity):
        args, name = dict(required.arguments), required.identifier
        evidence = ""
        try:
            if name == "linux_runtime":
                ok = sys.platform == "linux"
            elif name == "trusted_executable":
                evidence = self._trusted_executable(args["path"])
                ok = True
            elif name == "unprivileged_identity":
                ok = identity.ordinary() and self.resolve_identity() == identity
            elif name == "readable_path":
                with open(args["path"], "rb") as stream:
                    ok = bool(stream.read(1))
            elif name == "socket_inventory_available":
                protocol = args["protocol"]
                if protocol not in {"tcp", "udp"}:
                    raise ValueError("Unknown protocol")
                for suffix in ("", "6"):
                    with open(f"/proc/net/{protocol}{suffix}", "rb") as stream:
                        if not stream.read(1):
                            raise ValueError("Socket inventory unavailable")
                ok = True
            elif name == "systemd_available":
                ok = Path("/run/systemd/system").is_dir()
            elif name in {"service_exists", "service_not_masked"}:
                props = self._service_properties(op_id, args["service"])
                ok = props.get("Id") == args["service"] and props.get("LoadState") == "loaded"
                if name == "service_not_masked":
                    ok = ok and props.get("UnitFileState") not in {None, "masked", "masked-runtime"}
                evidence = json.dumps({k: props.get(k) for k in ("Id", "LoadState")}, sort_keys=True)
            elif name == "workspace_safe":
                evidence = self._directories(args["workspace"], identity.uid, private_leaf=True)
                ok = True
            elif name in {"no_symlink_components", "parent_directory_writable", "target_absent"}:
                path = Path(args["path"])
                if name == "no_symlink_components":
                    evidence = self._directories(path.parent, identity.uid)
                    ok = not path.is_symlink()
                elif name == "parent_directory_writable":
                    evidence = self._directories(path, identity.uid)
                    ok = os.access(path, os.W_OK | os.X_OK)
                else:
                    ok = not os.path.lexists(path)
                    evidence = str(path)
            else:
                # Includes authenticated_authorization and TCP mutation conditions:
                # those actions cannot reach dispatch without the future broker.
                raise ValueError("No trusted check handler for this requirement")
            return Observation(op_id, required, bool(ok), "Required state observed" if ok else "Required state absent", evidence)
        except Exception as exc:
            return Observation(op_id, required, False, str(exc))

    def _entry(self, path, identity, *, read=False):
        path = Path(path)
        self._directories(path.parent, identity.uid)
        with ExitStack() as stack:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            parent = os.open("/", flags)
            stack.callback(os.close, parent)
            for part in path.parts[1:-1]:
                parent = os.open(part, flags, dir_fd=parent)
                stack.callback(os.close, parent)
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if info.st_uid != identity.uid or info.st_mode & 0o077:
                raise PermissionError("Created entry ownership/mode is unexpected")
            content = b""
            if read:
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                with os.fdopen(fd, "rb") as stream:
                    opened = os.fstat(stream.fileno())
                    if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                            or self._signature(opened) != self._signature(info)):
                        raise PermissionError("File identity changed while verifying")
                    content = stream.read(65537)
                    if len(content) > 65536:
                        raise ValueError("Created content exceeds bound")
            return info, content

    def verify(self, op_id, required, prepared, execution, identity):
        args, name = dict(required.arguments), required.identifier
        try:
            if name == "exit_code":
                ok = not execution.error and execution.returncode == args["value"]
            elif name == "disk_usage_observed":
                lines = execution.stdout.splitlines()
                ok = bool(lines and lines[0].startswith("Filesystem") and len(lines) > 1)
                for line in lines[1:]:
                    values = line.split()
                    if len(values) < 6:
                        raise ValueError("Malformed disk observation")
                    total, used, available = map(int, values[1:4])
                    ok = ok and total > 0 and 0 <= used <= total and 0 <= available <= total and bool(re.fullmatch(r"[0-9]+%", values[4]))
            elif name == "memory_usage_observed":
                lines = [line.split() for line in execution.stdout.splitlines() if line.startswith("Mem:")]
                ok = len(lines) == 1 and len(lines[0]) == 7
                if ok:
                    total, *values = map(int, lines[0][1:])
                    ok = total > 0 and all(0 <= n <= total for n in values)
            elif name == "listeners_observed":
                ok = True  # ss -H may correctly return no sockets.
                for line in execution.stdout.splitlines():
                    values = line.split()
                    if len(values) < 5:
                        raise ValueError("Malformed socket observation")
                    port = int(values[3].rsplit(":", 1)[1])
                    state = "LISTEN" if args["protocol"] == "tcp" else "UNCONN"
                    ok = ok and values[0] == state and 1 <= port <= 65535
                    ok = ok and all(int(n) >= 0 for n in values[1:3])
                    ok = ok and ("port" not in args or port == args["port"])
            elif name == "service_state_observed":
                props = self._properties(execution.stdout)
                states = {"active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance", "refreshing"}
                ok = (props.get("Id") == args["service"] and props.get("LoadState") == "loaded"
                      and props.get("ActiveState") in states and bool(props.get("SubState")))
            elif name in {"entry_type", "file_content_sha256", "entry_confined"}:
                if name == "entry_confined":
                    root = Path(args["workspace"])
                    Path(args["path"]).relative_to(root)
                    self._directories(root, identity.uid, private_leaf=True)
                info, content = self._entry(args["path"], identity, read=name == "file_content_sha256")
                if name == "entry_type":
                    ok = stat.S_ISREG(info.st_mode) if args["kind"] == "file" else stat.S_ISDIR(info.st_mode)
                elif name == "file_content_sha256":
                    ok = hashlib.sha256(content).hexdigest() == args["sha256"]
                else:
                    ok = not stat.S_ISLNK(info.st_mode)
            else:
                raise ValueError("No trusted postcondition handler")
            return Observation(op_id, required, bool(ok), "Postcondition verified" if ok else "Postcondition not satisfied")
        except Exception as exc:
            return Observation(op_id, required, False, str(exc))
