# logger/audit.py
import os
import json
import uuid
import logging
import threading
from datetime import datetime, timezone
from typing import List, Dict, Any

logger = logging.getLogger(__name__)
LOG_PATH_DEFAULT = os.path.expanduser("~/.linxai/audit.jsonl")


class AuditLogger:

    def __init__(self, log_path: str = LOG_PATH_DEFAULT, session_id: str = None):
        self.log_path = log_path
        self.session_id = session_id or str(uuid.uuid4())
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def log(self, module: str, event_type: str, payload: Dict[str, Any] = None) -> dict:
        record = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "module":     module,
            "event_type": event_type,
            "payload":    payload or {},
        }
        line = json.dumps(record, default=str) + "\n"
        with self._lock:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line)
            except OSError as e:
                logger.error(f"AuditLogger write failed: {e}")
        return record

    def log_ai_classification(self, user_input: str, plan: dict, context_turns: int = 0):
        self.log("ai_engine", "intent_classified", {
            "user_input":            user_input,
            "intent":                plan.get("intent"),
            "target":                plan.get("target"),
            "command":               plan.get("command"),
            "requires_sudo":         plan.get("requires_sudo"),
            "risk_level":            plan.get("risk_level"),
            "pre_conditions_count":  len(plan.get("pre_conditions", [])),
            "context_turns":         context_turns,
        })

    def log_cie_result(self, validation_result: dict):
        self.log("cie", f"validation_{validation_result.get('decision', 'unknown')}", {
            "decision":    validation_result.get("decision"),
            "reason":      validation_result.get("reason"),
            "checks_run":  validation_result.get("checks_run"),
            "duration_ms": validation_result.get("duration_ms"),
            "intent":      validation_result.get("plan", {}).get("intent"),
            "command":     validation_result.get("plan", {}).get("command"),
        })

    def log_execution(self, result):
        payload = result.to_dict() if hasattr(result, "to_dict") else result
        self.log("executor", f"command_{payload.get('status', 'unknown')}", payload)

    def log_ebpf_event(self, event_type: str, event_data: dict):
        self.log("ebpf", event_type, event_data)

    def log_system_start(self):
        self.log("system", "startup", {"pid": os.getpid(), "session": self.session_id})

    def log_system_stop(self):
        self.log("system", "shutdown", {"session": self.session_id})

    def query(self, module: str = None, event_type: str = None,
              session_id: str = None, last_n: int = 50) -> List[dict]:
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
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if module and record.get("module") != module:
                        continue
                    if event_type and record.get("event_type") != event_type:
                        continue
                    if session_id and record.get("session_id") != session_id:
                        continue
                    records.append(record)
        except OSError as e:
            logger.error(f"AuditLogger read error: {e}")
        return records[-last_n:]

    def query_session(self, last_n: int = 100) -> List[dict]:
        return self.query(session_id=self.session_id, last_n=last_n)

    def get_stats(self) -> dict:
        if not os.path.exists(self.log_path):
            return {"total_records": 0, "file_size_kb": 0}
        total = 0
        modules: Dict[str, int] = {}
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        total += 1
                        try:
                            r = json.loads(line)
                            m = r.get("module", "unknown")
                            modules[m] = modules.get(m, 0) + 1
                        except Exception:
                            pass
        except OSError:
            pass
        return {
            "total_records": total,
            "file_size_kb":  os.path.getsize(self.log_path) // 1024,
            "log_path":      self.log_path,
            "by_module":     modules,
        }