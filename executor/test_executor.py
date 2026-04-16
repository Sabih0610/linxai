# executor/test_executor.py
# Test suite for the Execution Controller.
# Tests subprocess execution, timeout, forbidden command interception,
# structured result contract, and face auth fallback.
#
# Run: python3 executor/test_executor.py
# Run with sudo for sudo tests: sudo python3 executor/test_executor.py

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from executor.controller import ExecutionController
from executor.result import ExecutionResult, make_blocked_result

# Dev mode: face auth disabled so tests run without camera
controller = ExecutionController(use_face_auth=False)


def make_plan(intent, command, requires_sudo=False,
              risk="low", rollback=""):
    return {
        "intent": intent,
        "target": "",
        "pre_conditions": [],
        "command": command,
        "requires_sudo": requires_sudo,
        "risk_level": risk,
        "rollback": rollback,
        "explanation": "test",
    }


TEST_CASES = [

    # ── Basic execution ──────────────────────────────────────────────────────
    ("echo hello world",
     make_plan("system_info", "echo hello world"),
     lambda r: r.is_success() and "hello world" in r.stdout,
     "echo captures stdout correctly"),

    ("uname -r kernel version",
     make_plan("kernel_info", "uname -r"),
     lambda r: r.is_success() and len(r.stdout) > 0,
     "uname -r returns kernel version"),

    ("df -h disk usage",
     make_plan("disk_usage", "df -h"),
     lambda r: r.is_success() and "Filesystem" in r.stdout,
     "df -h returns filesystem table"),

    ("ps aux process list",
     make_plan("process_list", "ps aux"),
     lambda r: r.is_success() and "PID" in r.stdout,
     "ps aux returns process list"),

    ("cat /proc/meminfo memory",
     make_plan("memory_usage", "cat /proc/meminfo"),
     lambda r: r.is_success() and "MemTotal" in r.stdout,
     "reads /proc/meminfo successfully"),

    ("cat /proc/cpuinfo cpu",
     make_plan("cpu_usage", "cat /proc/cpuinfo"),
     lambda r: r.is_success() and "processor" in r.stdout,
     "reads /proc/cpuinfo successfully"),

    ("hostname command",
     make_plan("system_info", "hostname"),
     lambda r: r.is_success() and len(r.stdout) > 0,
     "hostname returns system name"),

    ("date command",
     make_plan("system_info", "date"),
     lambda r: r.is_success() and len(r.stdout) > 0,
     "date returns current time"),

    # ── Error handling ───────────────────────────────────────────────────────
    ("nonexistent command returns error",
     make_plan("system_info", "totally_fake_command_xyz_123"),
     lambda r: r.status == "error" and r.return_code != 0,
     "nonexistent command returns error status"),

    ("cat nonexistent file",
     make_plan("file_read", "cat /tmp/linxai_test_nonexistent_xyz.txt"),
     lambda r: r.status == "error" and r.return_code != 0,
     "cat on missing file returns error"),

    ("false command returns code 1",
     make_plan("system_info", "false"),
     lambda r: r.status == "error" and r.return_code == 1,
     "false command returns return_code=1"),

    # ── Result contract ──────────────────────────────────────────────────────
    ("result has all required fields",
     make_plan("system_info", "echo test"),
     lambda r: all(hasattr(r, f) for f in [
         "status", "return_code", "stdout", "stderr",
         "command", "intent", "duration_ms", "timestamp",
         "exec_id", "plan"
     ]),
     "result object has all required fields"),

    ("result exec_id is unique",
     make_plan("system_info", "echo a"),
     lambda r: len(r.exec_id) == 36,  # UUID format
     "exec_id is a valid UUID"),

    ("result duration_ms is measured",
     make_plan("system_info", "sleep 0.1"),
     lambda r: r.duration_ms >= 100,
     "duration_ms captures real elapsed time"),

    ("result to_dict is serialisable",
     make_plan("system_info", "echo json_test"),
     lambda r: isinstance(r.to_dict(), dict) and "status" in r.to_dict(),
     "to_dict() returns JSON-serialisable dict"),

    ("result summary is non-empty string",
     make_plan("system_info", "echo summary"),
     lambda r: isinstance(r.summary(), str) and len(r.summary()) > 0,
     "summary() returns non-empty string"),

    # ── Timeout ─────────────────────────────────────────────────────────────
    ("timeout kills long-running command",
     make_plan("system_info", "sleep 60"),
     lambda r: r.status == "timeout",
     "sleep 60 is killed by 2s timeout"),

    # ── Forbidden commands ───────────────────────────────────────────────────
    ("rm -rf / is intercepted",
     make_plan("file_delete", "rm -rf /"),
     lambda r: r.status == "blocked",
     "rm -rf / is blocked by safety guard"),

    ("shutdown is intercepted",
     make_plan("system_info", "shutdown -h now"),
     lambda r: r.status == "blocked",
     "shutdown is blocked by safety guard"),

    ("fork bomb is intercepted",
     make_plan("system_info", ":(){ :|:& };:"),
     lambda r: r.status == "blocked",
     "fork bomb pattern is blocked"),

    # ── execute_raw ──────────────────────────────────────────────────────────
    ("execute_raw works for ad-hoc commands",
     None,  # uses execute_raw directly
     None,
     "execute_raw returns correct result"),

    # ── make_blocked_result helper ───────────────────────────────────────────
    ("make_blocked_result has correct status",
     None,
     None,
     "make_blocked_result factory works correctly"),
]


def run_tests():
    # Use 2-second timeout for timeout test
    fast_controller = ExecutionController(use_face_auth=False, timeout_s=2)

    print("=" * 70)
    print("  LINxAI — Execution Controller Test Suite")
    print(f"  {len(TEST_CASES)} test cases | Target: 100% pass")
    print("=" * 70)
    print()

    passed = 0
    failed = []

    for i, (description, plan, assertion, detail) in enumerate(TEST_CASES, 1):

        try:
            # Special cases that don't use standard plan
            if description.startswith("execute_raw"):
                result = controller.execute_raw("echo raw_test", "system_info")
                ok = result.is_success() and "raw_test" in result.stdout

            elif description.startswith("make_blocked_result"):
                result = make_blocked_result("test", "fake cmd", "test reason")
                ok = result.status == "blocked" and result.return_code == -1

            elif description.startswith("timeout"):
                result = fast_controller.execute(plan)
                ok = assertion(result)

            else:
                result = controller.execute(plan)
                ok = assertion(result)

            status = "✓" if ok else "✗"
            print(f"  [{status}] {i:02d}. {description[:55]:<55}")

            if ok:
                passed += 1
            else:
                extra = ""
                if plan:
                    r = controller.execute(plan)
                    extra = f"status={r.status}, rc={r.return_code}, stderr='{r.stderr[:60]}'"
                failed.append({
                    "id": i,
                    "description": description,
                    "detail": detail,
                    "extra": extra
                })

        except Exception as e:
            print(f"  [E] {i:02d}. {description[:55]:<55} — EXCEPTION: {e}")
            failed.append({
                "id": i,
                "description": description,
                "detail": detail,
                "extra": str(e)
            })

    total = len(TEST_CASES)
    pct = passed / total * 100

    print()
    print("=" * 70)
    print(f"  RESULT: {passed}/{total} passed — {pct:.1f}%")
    print(f"  Status: {'PASS ✓' if passed == total else 'FAIL ✗'}")

    if failed:
        print(f"\n  Failed ({len(failed)}):")
        for f in failed:
            print(f"    #{f['id']}: {f['description']}")
            if f['extra']:
                print(f"      {f['extra']}")

    print("=" * 70)
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)