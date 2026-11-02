"""Private SQLite storage, bounded by rows, payload and maximum database pages."""
import json
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time

from .system import LinuxSystemAdapter


class Store:
    def __init__(self, path, *, uid=None):
        self.path = Path(path).absolute()
        self.uid = os.getuid() if uid is None else uid
        self.lock = threading.RLock()
        parent = self.path.parent
        if not parent.exists():
            parent.mkdir(mode=0o700)
        LinuxSystemAdapter()._directories(parent, self.uid, private_leaf=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid or info.st_nlink != 1 or info.st_mode & 0o077:
                raise PermissionError("Private singly-linked database required")
        finally:
            os.close(fd)
        self.db = sqlite3.connect(self.path, timeout=5, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA max_page_count=8192")
        with self.db:
            self.db.execute("CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, body TEXT NOT NULL, updated REAL NOT NULL, PRIMARY KEY(kind,id))")
            self.db.execute("PRAGMA user_version=1")

    def put(self, kind, key, body, *, replace=True, limit=1000):
        value = json.dumps(body, allow_nan=False, separators=(",", ":"))
        if len(value.encode()) > 196608 or len(str(key)) > 128 or len(kind) > 32:
            raise ValueError("Stored payload exceeds bound")
        with self.lock, self.db:
            existing = self.db.execute("SELECT 1 FROM records WHERE kind=? AND id=?", (kind, key)).fetchone()
            if not existing and self.db.execute("SELECT count(*) FROM records WHERE kind=?", (kind,)).fetchone()[0] >= limit:
                raise ValueError("Storage admission limit reached; archive records before admitting more")
            sql = "INSERT OR REPLACE" if replace else "INSERT"
            self.db.execute(f"{sql} INTO records VALUES (?,?,?,?)", (kind, key, value, time.time()))

    def get(self, kind, key):
        with self.lock:
            row = self.db.execute("SELECT body FROM records WHERE kind=? AND id=?", (kind, key)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, kind, limit=100):
        with self.lock:
            rows = self.db.execute("SELECT body FROM records WHERE kind=? ORDER BY updated DESC LIMIT ?", (kind, min(max(limit, 1), 1000))).fetchall()
        return [json.loads(row[0]) for row in rows]

    def close(self):
        self.db.close()
