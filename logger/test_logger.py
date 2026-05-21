# logger/test_logger.py
# Phase 11 test suite for central logging.
#
# Run:
#   python3 logger/test_logger.py

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logger.audit import AuditLogger
from logger.integration import LoggingHub


def run_tests():
    print("=" * 55)
    print("  LINxAI Phase 11 — Logging Integration Test")
    print("=" * 55)
    print()

    test_log = "/tmp/linxai_phase11_audit.jsonl"

    if os.path.exists(test_log):
        os.remove(test_log)

    passed = 0
    total = 0

    def check(description, condition):
        nonlocal passed, total

        total += 1
        status = "✓" if condition else "✗"

        print(f"  [{status}] {description}")

        if condition:
            passed += 1

    audit = AuditLogger(log_path=test_log, session_id="phase11-test")

    # Basic logging
    audit.log("test", "basic_event", {"ok": True})

    check("Basic event written", os.path.exists(test_log))
    check("One record exists", len(audit.read_all()) == 1)

    # AI log
    plan = {
        "intent": "service_restart",
        "target": "nginx",
        "command": "systemctl restart nginx",
        "requires_sudo": True,
    }

    audit.log_ai_intent("restart nginx", plan)

    # CIE log
    validation = {
        "result": "approve",
        "reason": "All checks passed",
    }

    audit.log_validation(plan, validation)

    # Executor log
    audit.log_execution({
        "status": "success",
        "return_code": 0,
        "stdout": "done",
        "stderr": "",
        "duration_ms": 123,
        "command_issued": "sudo systemctl restart nginx",
    })

    # eBPF log
    audit.log_ebpf_event({
        "event_type": "process_exec",
        "payload": {
            "pid": 123,
            "process": "bash",
            "filename": "/bin/bash",
        },
    })

    # Resource log
    audit.log_resource_event("renice_applied", {
        "count": 1,
        "reason": "CPU above threshold",
    })

    # VPS log
    audit.log_vps_event("vps_command_executed", {
        "server": "local-vm",
        "status": "success",
        "command": "hostname",
        "stdout": "linxai-dev",
    })

    records = audit.read_all()

    check("Multiple records written", len(records) == 7)
    check("Tail returns latest records", len(audit.tail(3)) == 3)
    check("Query by module works", len(audit.query(module="ai_engine")) == 1)
    check("Query by event works", len(audit.query(event_type="process_exec")) == 1)
    check("Query by level works", len(audit.query(level="INFO")) >= 1)

    summary = audit.summary()

    check("Summary has total_records", summary["total_records"] == 7)
    check("Summary has ai_engine count", summary["by_module"].get("ai_engine") == 1)
    check("Summary has ebpf count", summary["by_module"].get("ebpf") == 1)
    check("Summary has vps count", summary["by_module"].get("vps") == 1)

    # LoggingHub callbacks
    hub = LoggingHub(log_path=test_log)
    hub.generic("hub_test", "callback_ok", {"ok": True})

    check(
        "LoggingHub writes callback event",
        len(AuditLogger(test_log).query(module="hub_test")) == 1
    )

    print()
    print("=" * 55)
    print(f"  RESULT: {passed}/{total} passed — {passed / total * 100:.0f}%")
    print(f"  Status: {'PASS ✓' if passed == total else 'PARTIAL'}")
    print("=" * 55)

    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)