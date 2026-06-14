from __future__ import annotations

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
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
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
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS working_memory (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                session   TEXT    NOT NULL,
                ts        TEXT    NOT NULL,
                kind      TEXT    NOT NULL,
                value     TEXT    NOT NULL
            )
        """)
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_working_memory_session "
            "ON working_memory(session, kind)"
        )
        self.conn.commit()

    def save(self, user_input: str, plan: dict, result: dict = None):
        try:
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
        except sqlite3.OperationalError as e:
            logger.error(f"save failed: {e}")
            try:
                self.conn.rollback()
            except Exception:
                pass
            try:
                self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
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
            except Exception as e2:
                logger.error(f"save retry failed: {e2}")

    def get_recent(self, n: int = None) -> List[Dict]:
        limit = n or self.max_context
        fetch_limit = max(limit * 5, 20)
        cursor = self.conn.execute(
            """SELECT input, plan, result FROM history
               WHERE session = ? ORDER BY id DESC LIMIT ?""",
            (self.session_id, fetch_limit)
        )
        rows = cursor.fetchall()
        recent = []

        for input_text, plan_json, result_json in reversed(rows):
            if input_text.startswith("[SECURITY ALERT]"):
                continue

            try:
                plan = json.loads(plan_json)
            except Exception:
                continue

            result = {}
            if result_json:
                try:
                    parsed = json.loads(result_json)
                    if isinstance(parsed, dict):
                        result = parsed
                except Exception:
                    result = {}

            result_intent = result.get("intent")
            plan_intent = plan.get("intent")
            if result_intent in ("unknown", "chat"):
                continue
            if plan_intent in ("unknown", "chat"):
                continue
            if result.get("skipped") is True:
                continue

            recent.append({"input": input_text, "plan": plan})

        return recent[-limit:]

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
            try:
                self.conn.rollback()
            except Exception:
                pass

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

    def remember_service_port(
        self,
        service: str,
        port: int | None,
        action: str = "",
    ):
        if not service and port is None:
            return

        payload = {
            "service": service or "",
            "port": port,
            "action": action or "",
        }
        try:
            self.conn.execute(
                """INSERT INTO working_memory (session, ts, kind, value)
                   VALUES (?, ?, ?, ?)""",
                (
                    self.session_id,
                    datetime.utcnow().isoformat() + "Z",
                    "service_port",
                    json.dumps(payload),
                )
            )
            self.conn.execute(
                """DELETE FROM working_memory
                   WHERE session = ? AND kind = 'service_port'
                   AND id NOT IN (
                       SELECT id FROM working_memory
                       WHERE session = ? AND kind = 'service_port'
                       ORDER BY id DESC LIMIT 5
                   )""",
                (self.session_id, self.session_id)
            )
            self.conn.commit()
        except Exception as e:
            logger.error(f"remember_service_port failed: {e}")
            try:
                self.conn.rollback()
            except Exception:
                pass

    def recent_service_ports(self, limit: int = 5) -> list[dict]:
        try:
            cur = self.conn.execute(
                """SELECT value FROM working_memory
                   WHERE session = ? AND kind = 'service_port'
                   ORDER BY id DESC LIMIT ?""",
                (self.session_id, limit)
            )
            items = []
            for row in cur.fetchall():
                try:
                    parsed = json.loads(row[0])
                except Exception:
                    continue
                if isinstance(parsed, dict):
                    items.append(parsed)
            return items
        except Exception as e:
            logger.error(f"recent_service_ports failed: {e}")
            return []

    def clear_session(self):
        self.conn.execute("DELETE FROM history WHERE session = ?", (self.session_id,))
        self.conn.execute(
            "DELETE FROM working_memory WHERE session = ?",
            (self.session_id,),
        )
        self.conn.commit()

    def close(self):
        self.conn.close()
