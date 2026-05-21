# logger/audit.py
# LINxAI Central Audit Logger
#
# Backward compatible with old Phase 7 CLI:
# - LOG_PATH_DEFAULT
# - query(..., session_id, last_n)
# - get_stats()
# - log_ai_classification()
# - log_cie_result()
# - log_execution()
# - log_ebpf_event()
# - log_system_start()
# - log_system_stop()
#
# Also supports Phase 11 integration:
# - log_ai_intent()
# - log_validation()
# - log_resource_event()
# - log_vps_event()
# - log_voice_event()
# - summary()
# - tail()
# - clear()

import os
import json
import uuid
import socket
import logging
import threading
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any


logger = logging.getLogger(__name__)

# New centralized Phase 11 path
DEFAULT_LOG_PATH = os.environ.get(
    "LINXAI_LOG_PATH",
    "/var/log/linxai/audit.jsonl"
)

# Backward compatibility for old logger/cli.py
LOG_PATH_DEFAULT = DEFAULT_LOG_PATH


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLogger:
    def __init__(self, log_path: str = LOG_PATH_DEFAULT, session_id: str = None):
        self.log_path = os.path.expanduser(log_path)
        self.session_id = session_id or str(uuid.uuid4())
        self.host = socket.gethostname()
        self._lock = threading.Lock()

        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    # ------------------------------------------------------------------
    # Core writer
    # ------------------------------------------------------------------

    def log(
        self,
        module: str,
        event_type: str,
        payload: Dict[str, Any] = None,
        level: str = "INFO",
    ) -> dict:
        record = {
            "timestamp": _now(),
            "session_id": self.session_id,
            "host": self.host,
            "module": module,
            "event_type": event_type,
            "level": level,
            "payload": payload or {},
        }

        line = json.dumps(record, default=str) + "\n"

        with self._lock:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line)
            except OSError as e:
                logger.error(f"AuditLogger write failed: {e}")

        return record

    # ------------------------------------------------------------------
    # AI logging
    # ------------------------------------------------------------------

    def log_ai_classification(
        self,
        user_input: str,
        plan: dict,
        context_turns: int = 0,
    ):
        """
        Legacy Phase 7 method.
        Used by old AI/demo pipeline code.
        """
        return self.log(
            "ai_engine",
            "intent_classified",
            {
                "user_input": user_input,
                "intent": plan.get("intent"),
                "target": plan.get("target"),
                "command": plan.get("command"),
                "requires_sudo": plan.get("requires_sudo"),
                "risk_level": plan.get("risk_level"),
                "pre_conditions_count": len(plan.get("pre_conditions", [])),
                "context_turns": context_turns,
                "plan": plan,
            },
        )

    def log_ai_intent(self, user_input: str, plan: dict):
        """
        New Phase 11 name.
        Internally uses old working method.
        """
        return self.log_ai_classification(user_input, plan)

    # ------------------------------------------------------------------
    # CIE logging
    # ------------------------------------------------------------------

    def log_cie_result(self, validation_result: dict):
        """
        Legacy Phase 7 method.

        Supports validation_result like:
        {
          "decision": "approve/block",
          "reason": "...",
          "checks_run": 5,
          "duration_ms": 123,
          "plan": {...}
        }
        """
        decision = (
            validation_result.get("decision")
            or validation_result.get("result")
            or "unknown"
        )

        level = "INFO" if decision in ("approve", "approved", "success") else "WARNING"

        return self.log(
            "cie",
            f"validation_{decision}",
            {
                "decision": decision,
                "result": validation_result.get("result"),
                "reason": validation_result.get("reason"),
                "checks_run": validation_result.get("checks_run"),
                "duration_ms": validation_result.get("duration_ms"),
                "intent": validation_result.get("plan", {}).get("intent"),
                "command": validation_result.get("plan", {}).get("command"),
                "validation": validation_result,
            },
            level=level,
        )

    def log_validation(self, plan: dict, validation: dict):
        """
        New Phase 11 method.

        Supports validation like:
        {
          "result": "approve/block",
          "reason": "..."
        }
        """
        merged = dict(validation)
        merged["plan"] = plan

        if "decision" not in merged:
            merged["decision"] = validation.get("result", "unknown")

        return self.log_cie_result(merged)

    # ------------------------------------------------------------------
    # Executor logging
    # ------------------------------------------------------------------

    def log_execution(self, result):
        """
        Supports both:
        - dict result
        - object with to_dict()
        """
        payload = result.to_dict() if hasattr(result, "to_dict") else dict(result)

        status = payload.get("status", "unknown")
        level = "INFO" if status == "success" else "ERROR"

        return self.log(
            "executor",
            f"command_{status}",
            payload,
            level=level,
        )

    # ------------------------------------------------------------------
    # eBPF logging
    # ------------------------------------------------------------------

    def log_ebpf_event(self, event_type_or_record, event_data: dict = None):
        """
        Backward and forward compatible.

        Old style:
            log_ebpf_event("process_exec", {...})

        New callback style:
            log_ebpf_event({
                "module": "ebpf",
                "event_type": "process_exec",
                "payload": {...}
            })
        """
        if isinstance(event_type_or_record, dict) and event_data is None:
            record = event_type_or_record

            if "event_type" in record and "payload" in record:
                return self.log(
                    "ebpf",
                    record.get("event_type", "kernel_event"),
                    record.get("payload", {}),
                    level=record.get("level", "INFO"),
                )

            return self.log("ebpf", "kernel_event", record)

        return self.log(
            "ebpf",
            str(event_type_or_record),
            event_data or {},
        )

    # ------------------------------------------------------------------
    # Resource / VPS / Voice logging
    # ------------------------------------------------------------------

    def log_resource_event(self, event_type: str, payload: dict):
        return self.log("resources", event_type, payload)

    def log_vps_event(self, event_type: str, payload: dict):
        status = payload.get("status")
        level = "INFO"

        if status == "blocked":
            level = "WARNING"
        elif status not in (None, "success"):
            level = "ERROR"

        return self.log("vps", event_type, payload, level=level)

    def log_voice_event(self, event_type: str, payload: dict):
        return self.log("voice", event_type, payload)

    # ------------------------------------------------------------------
    # System logging
    # ------------------------------------------------------------------

    def log_system_start(self):
        return self.log(
            "system",
            "startup",
            {
                "pid": os.getpid(),
                "session": self.session_id,
            },
        )

    def log_system_stop(self):
        return self.log(
            "system",
            "shutdown",
            {
                "session": self.session_id,
            },
        )

    # ------------------------------------------------------------------
    # Reading / querying
    # ------------------------------------------------------------------

    def read_all(self) -> List[dict]:
        if not os.path.exists(self.log_path):
            return []

        records = []

        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        except OSError as e:
            logger.error(f"AuditLogger read error: {e}")

        return records

    def query(
        self,
        module: str = None,
        event_type: str = None,
        session_id: str = None,
        level: str = None,
        last_n: int = 50,
        limit: Optional[int] = None,
    ) -> List[dict]:
        """
        Backward-compatible query.

        Old CLI calls:
            query(module=..., event_type=..., session_id=..., last_n=...)

        New code may call:
            query(module=..., level=..., limit=...)
        """
        records = self.read_all()

        if module:
            records = [r for r in records if r.get("module") == module]

        if event_type:
            records = [r for r in records if r.get("event_type") == event_type]

        if session_id:
            records = [
                r for r in records
                if str(r.get("session_id", "")).startswith(session_id)
            ]

        if level:
            records = [r for r in records if r.get("level") == level]

        final_limit = limit if limit is not None else last_n

        return records[-final_limit:]

    def query_session(self, last_n: int = 100) -> List[dict]:
        return self.query(session_id=self.session_id, last_n=last_n)

    def tail(self, n: int = 20) -> List[dict]:
        return self.query(last_n=n)

    # ------------------------------------------------------------------
    # Stats / summary
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        records = self.read_all()

        by_module: Dict[str, int] = {}
        by_level: Dict[str, int] = {}
        by_event: Dict[str, int] = {}

        for record in records:
            module = record.get("module", "unknown")
            level = record.get("level", "unknown")
            event = record.get("event_type", "unknown")

            by_module[module] = by_module.get(module, 0) + 1
            by_level[level] = by_level.get(level, 0) + 1
            by_event[event] = by_event.get(event, 0) + 1

        file_size_kb = 0

        if os.path.exists(self.log_path):
            try:
                file_size_kb = round(os.path.getsize(self.log_path) / 1024, 2)
            except OSError:
                file_size_kb = 0

        return {
            "total_records": len(records),
            "file_size_kb": file_size_kb,
            "log_path": self.log_path,
            "by_module": by_module,
            "by_level": by_level,
            "by_event": by_event,
        }

    def summary(self) -> dict:
        return self.get_stats()

    def clear(self):
        with self._lock:
            if os.path.exists(self.log_path):
                os.remove(self.log_path)


if __name__ == "__main__":
    audit = AuditLogger()

    audit.log_system_start()
    audit.log("logger", "standalone_test", {
        "message": "AuditLogger standalone test successful"
    })

    print("Audit log written to:", audit.log_path)
    print(json.dumps(audit.get_stats(), indent=2))