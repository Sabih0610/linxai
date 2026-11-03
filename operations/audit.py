"""Private, durable, bounded JSONL ledger; failures block operation admission."""
import json
import os
from pathlib import Path
import stat
import threading


class JsonlAudit:
    MAX_BYTES = 8 * 1024 * 1024
    GENERATIONS = 3
    MAX_RECORD = 65536

    def __init__(self, path):
        self.path = Path(path).expanduser().absolute()
        self._lock = threading.RLock()

    def _writer_uid(self):
        if not hasattr(os, "getuid") or os.getuid() == 0 or os.geteuid() != os.getuid():
            raise PermissionError("Audit writer requires an ordinary Linux identity")
        return os.getuid()

    @staticmethod
    def _safe_file(info, uid):
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1 or info.st_mode & 0o077:
            raise PermissionError("Audit file must be a private, singly linked owned regular file")

    def append(self, record):
        uid = self._writer_uid()
        import fcntl
        parent = self.path.parent
        if not parent.exists():
            parent.mkdir(mode=0o700)
        for directory in (parent, *parent.parents):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, uid} or info.st_mode & 0o022:
                raise PermissionError("Audit directory chain is unsafe")
        if parent.stat().st_uid != uid or parent.stat().st_mode & 0o077:
            raise PermissionError("Audit parent must be private and owned by the account")
        line = (json.dumps(record, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
        if len(line) > min(self.MAX_RECORD, self.MAX_BYTES):
            raise ValueError("Audit record exceeds retained-data budget")
        with self._lock:
            # A stable sidecar serializes rotation across independent CLI processes.
            lock = os.open(self.path.with_name(self.path.name + ".lock"),
                           os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                self._safe_file(os.fstat(lock), uid)
                fcntl.flock(lock, fcntl.LOCK_EX)
                paths = [self.path] + [self.path.with_name(self.path.name + f".{i}") for i in range(1, self.GENERATIONS + 1)]
                # Validate every destination before any rename, including dangling links.
                for path in paths:
                    if os.path.lexists(path):
                        self._safe_file(path.lstat(), uid)
                if self.path.exists() and self.path.stat().st_size + len(line) > self.MAX_BYTES:
                    for index in range(self.GENERATIONS, 0, -1):
                        if paths[index - 1].exists():
                            paths[index - 1].replace(paths[index])
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                try:
                    self._safe_file(os.fstat(fd), uid)
                    view = memoryview(line)
                    while view:
                        written = os.write(fd, view)
                        if written <= 0:
                            raise OSError("Incomplete audit write")
                        view = view[written:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                self._sync_parent(parent)
            finally:
                os.close(lock)

    @staticmethod
    def _sync_parent(parent):
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
