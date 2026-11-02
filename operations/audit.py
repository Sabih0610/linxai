"""Fail-reporting private JSONL ledger; never reuses the legacy best-effort logger."""
import json
import os
from pathlib import Path
import stat
import threading


class JsonlAudit:
    def __init__(self, path):
        self.path = Path(path).expanduser().absolute()
        self._lock = threading.Lock()

    def append(self, record):
        if not hasattr(os, "getuid") or os.getuid() == 0 or os.geteuid() != os.getuid():
            raise PermissionError("Audit writer requires an ordinary Linux identity")
        uid = os.getuid()
        import fcntl
        # Do not chmod/chown existing paths. Fail closed on unsafe log ownership.
        parent = self.path.parent
        if not parent.exists():
            parent.mkdir(mode=0o700)
        for directory in (parent, *parent.parents):
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, uid}
                    or info.st_mode & 0o022):
                raise PermissionError("Audit directory chain is unsafe")
        if parent.stat().st_uid != uid or parent.stat().st_mode & 0o077:
            raise PermissionError("Audit parent must be private and owned by the account")
        line = (json.dumps(record, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                        or info.st_nlink != 1 or info.st_mode & 0o077):
                    raise PermissionError("Audit file must be a private, singly linked owned regular file")
                view = memoryview(line)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("Incomplete audit write")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
