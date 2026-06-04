# ai/context.py
import sqlite3
import json
import uuid
import os
import logging
from datetime import datetime
from typing import List, Dict

logger = logging.getLogger(__name__)


class ContextMemory:

    def __init__(self, db_path: str = "~/.linxai/context.db",
                 max_context: int = 5):
        self.db_path = os.path.expanduser(db_path)
        self.max_context = max_context
        self.session_id = str(uuid.uuid4())
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_schema()
        logger.info(f"Context memory ready — session: {self.session_id[:8]}...")

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                session   TEXT    NOT NULL,
                ts        TEXT    NOT NULL,
                input     TEXT    NOT NULL,
                plan      TEXT    NOT NULL,
                result    TEXT
            )
        """)
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_session ON history(session)"
        )
        self.conn.commit()

    def save(self, user_input: str, plan: dict, result: dict = None):
        self.conn.execute(
            "INSERT INTO history (session, ts, input, plan, result) VALUES (?, ?, ?, ?, ?)",
            (
                self.session_id,
                datetime.utcnow().isoformat() + "Z",
                user_input,
                json.dumps(plan),
                json.dumps(result) if result else None
            )
        )
        self.conn.commit()

    def get_recent(self, n: int = None) -> List[Dict]:
        limit = n or self.max_context
        cursor = self.conn.execute(
            "SELECT input, plan FROM history WHERE session = ? ORDER BY id DESC LIMIT ?",
            (self.session_id, limit)
        )
        rows = cursor.fetchall()
        return [{"input": r[0], "plan": json.loads(r[1])} for r in reversed(rows)]

    def save_security_alert(self, alert: dict):
        """
        Save a security alert from eBPF into context memory.
        The AI will see this on the next classify() call and warn the user.
        """
        try:
            self.conn.execute(
                """INSERT INTO history (session, ts, input, plan, result)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    self.session_id,
                    datetime.utcnow().isoformat() + "Z",
                    f"[SECURITY ALERT] {alert.get('event_type', '?')}",
                    json.dumps(alert),
                    json.dumps({"security_alert": True}),
                )
            )
            self.conn.commit()
            logger.info(
                f"Security alert saved to context: {alert.get('event_type', '?')}"
            )
        except Exception as e:
            logger.error(f"save_security_alert failed: {e}")

    def get_security_alerts(self, last_n: int = 5) -> list:
        """
        Return recent security alerts from context memory.
        """
        try:
            cur = self.conn.execute(
                """SELECT input, plan FROM history
                   WHERE session = ? AND input LIKE '[SECURITY ALERT]%'
                   ORDER BY id DESC LIMIT ?""",
                (self.session_id, last_n)
            )

            alerts = []

            for row in cur.fetchall():
                try:
                    alerts.append(json.loads(row[1]))
                except Exception:
                    pass

            return alerts

        except Exception as e:
            logger.error(f"get_security_alerts failed: {e}")
            return []

    def has_recent_security_alerts(self) -> bool:
        """
        Returns True if there are unacknowledged security alerts this session.
        """
        return len(self.get_security_alerts(last_n=3)) > 0

    def clear_session(self):
        self.conn.execute("DELETE FROM history WHERE session = ?", (self.session_id,))
        self.conn.commit()

    def close(self):
        self.conn.close()