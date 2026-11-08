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
        try:
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, 1}:
                raise ValueError("Unsupported storage schema; explicit migration required")
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA max_page_count=8192")
            with self.db:
                if version == 0:
                    self.db.execute("CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, body TEXT NOT NULL, updated REAL NOT NULL, PRIMARY KEY(kind,id))")
                columns = [(row[1], row[2], row[3], row[5]) for row in self.db.execute("PRAGMA table_info(records)")]
                expected = [("kind", "TEXT", 0, 1), ("id", "TEXT", 0, 2), ("body", "TEXT", 1, 0), ("updated", "REAL", 1, 0)]
                if columns != expected:
                    raise ValueError("Unsupported storage layout; explicit migration required")
                if version == 0:
                    self.db.execute("PRAGMA user_version=1")
        except Exception:
            self.db.close()
            raise

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

    def write_batch(self, records=(), *, prune=None):
        """Apply retention and several writes in ONE durable transaction.

        records: iterable of (kind, key, body, replace, limit). prune: {kind: keep}
        applied first. Same per-record bounds and admission limits as put(); any
        violation rolls back the whole batch. Durability settings are unchanged;
        this only removes per-record fsync cost on high-rate evidence paths."""
        prepared = []
        for kind, key, body, replace, limit in records:
            value = json.dumps(body, allow_nan=False, separators=(",", ":"))
            if len(value.encode()) > 196608 or len(str(key)) > 128 or len(kind) > 32:
                raise ValueError("Stored payload exceeds bound")
            prepared.append((kind, key, value, replace, limit))
        retention = dict(prune or {})
        for keep in retention.values():
            if type(keep) is not int or not 0 <= keep <= 10000:
                raise ValueError("Invalid retention bound")
        if not prepared and not retention:
            return
        with self.lock, self.db:
            for kind, keep in retention.items():
                self.db.execute("DELETE FROM records WHERE kind=? AND id NOT IN (SELECT id FROM records WHERE kind=? ORDER BY updated DESC LIMIT ?)", (kind, kind, keep))
            now = time.time()
            for kind, key, value, replace, limit in prepared:
                existing = self.db.execute("SELECT 1 FROM records WHERE kind=? AND id=?", (kind, key)).fetchone()
                if not existing and self.db.execute("SELECT count(*) FROM records WHERE kind=?", (kind,)).fetchone()[0] >= limit:
                    raise ValueError("Storage admission limit reached; archive records before admitting more")
                sql = "INSERT OR REPLACE" if replace else "INSERT"
                self.db.execute(f"{sql} INTO records VALUES (?,?,?,?)", (kind, key, value, now))

    def get(self, kind, key):
        with self.lock:
            row = self.db.execute("SELECT body FROM records WHERE kind=? AND id=?", (kind, key)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, kind, limit=100):
        with self.lock:
            rows = self.db.execute("SELECT body FROM records WHERE kind=? ORDER BY updated DESC LIMIT ?", (kind, min(max(limit, 1), 1000))).fetchall()
        return [json.loads(row[0]) for row in rows]

    def prune(self, kind, keep):
        if type(keep) is not int or not 0 <= keep <= 10000:
            raise ValueError("Invalid retention bound")
        with self.lock, self.db:
            self.db.execute("DELETE FROM records WHERE kind=? AND id NOT IN (SELECT id FROM records WHERE kind=? ORDER BY updated DESC LIMIT ?)", (kind, kind, keep))

    def close(self):
        self.db.close()
