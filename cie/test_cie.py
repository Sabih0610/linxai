# cie/test_cie.py
# 40-case test suite for the Command Intelligence Engine.
# Target: 95% correct decisions (38/40) in under 500ms per validation.
# Per FYP proposal objective for Phase 5.
#
# Run: python3 cie/test_cie.py
# Run with sudo for full /proc access: sudo python3 cie/test_cie.py

import sys
import os
import time
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cie.validator import CommandIntelligenceEngine

cie = CommandIntelligenceEngine()


def make_plan(intent: str, command: str, pre_conditions: list,
              target: str = "", requires_sudo: bool = False) -> dict:
    return {
        "intent": intent,
        "target": target,
        "pre_conditions": pre_conditions,
        "command": command,
        "requires_sudo": requires_sudo,
        "risk_level": "medium",
        "rollback": "",
        "explanation": "test case"
    }


# ── Test case structure ───────────────────────────────────────────────────────
# Each entry: (description, plan_dict, expected_decision)
# expected_decision: "approve" | "block" | "warn"

TEST_CASES = [

    # ── No pre-conditions (always approve) ── (4 cases)
    (
        "no checks required",
        make_plan("cpu_usage", "top -bn1", []),
        "approve"
    ),
    (
        "no checks — disk usage",
        make_plan("disk_usage", "df -h", []),
        "approve"
    ),
    (
        "no checks — process list",
        make_plan("process_list", "ps aux", []),
        "approve"
    ),
    (
        "no checks — system info",
        make_plan("system_info", "uname -a", []),
        "approve"
    ),

    # ── Port free checks ── (6 cases)
    (
        "port 9999 is free → approve",
        make_plan("service_start", "systemctl start testapp",
                  [{"check": "port_free", "port": 9999}], "testapp"),
        "approve"
    ),
    (
        "port 9998 is free → approve",
        make_plan("service_start", "systemctl start anotherapp",
                  [{"check": "port_free", "port": 9998}]),
        "approve"
    ),
    (
        "port 22 is occupied (sshd) → block",
        make_plan("service_start", "systemctl start myssh",
                  [{"check": "port_free", "port": 22}]),
        "block"
    ),
    (
        "port 9876 is free → approve",
        make_plan("service_start", "systemctl start myapp",
                  [{"check": "port_free", "port": 9876}]),
        "approve"
    ),
    (
        "port 9997 is free → approve",
        make_plan("port_check", "ss -tlnp",
                  [{"check": "port_free", "port": 9997}]),
        "approve"
    ),
    (
        "multiple conditions: port free + service exists (nginx)",
        make_plan("service_restart", "systemctl restart nginx",
                  [
                      {"check": "port_free", "port": 9876},
                      {"check": "service_exists", "service": "nginx"},
                  ], "nginx"),
        "approve"  # port free + nginx installed
    ),

    # ── Service existence checks ── (5 cases)
    (
        "nginx service exists → approve",
        make_plan("service_start", "systemctl start nginx",
                  [{"check": "service_exists", "service": "nginx"}], "nginx"),
        "approve"
    ),
    (
        "ssh service exists → approve",
        make_plan("service_status", "systemctl status ssh",
                  [{"check": "service_exists", "service": "ssh"}], "ssh"),
        "approve"
    ),
    (
        "nonexistent service → block",
        make_plan("service_start", "systemctl start fakexyzservice",
                  [{"check": "service_exists", "service": "fakexyzservice"}],
                  "fakexyzservice"),
        "block"
    ),
    (
        "cron service exists → approve",
        make_plan("service_status", "systemctl status cron",
                  [{"check": "service_exists", "service": "cron"}]),
        "approve"
    ),
    (
        "another nonexistent service → block",
        make_plan("service_enable", "systemctl enable doesnotexist",
                  [{"check": "service_exists", "service": "doesnotexist"}]),
        "block"
    ),

    # ── Process checks ── (6 cases)
    (
        "systemd process is running → approve",
        make_plan("process_info", "ps -p 1",
                  [{"check": "process_running", "process": "1"}], "1"),
        "approve"
    ),
    (
        "PID 1 exists → approve",
        make_plan("process_info", "cat /proc/1/status",
                  [{"check": "process_running", "process": "1"}]),
        "approve"
    ),
    (
        "nonexistent PID → block",
        make_plan("process_kill", "kill 999999",
                  [{"check": "process_running", "process": "999999"}], "999999"),
        "block"
    ),
    (
        "fake process name → block",
        make_plan("process_kill", "killall fakeprocessxyz",
                  [{"check": "process_running", "process": "fakeprocessxyz"}]),
        "block"
    ),
    (
        "python3 or python not running check",
        make_plan("process_background", "python3 script.py &",
                  [{"check": "process_not_running", "process": "neverrunningxyz"}]),
        "approve"
    ),
    (
        "systemd not running (expects conflict on non-running)",
        make_plan("process_kill", "kill -9 999998",
                  [{"check": "process_running", "process": "999998"}]),
        "block"
    ),

    # ── File system checks ── (5 cases)
    (
        "/etc/hosts exists → approve",
        make_plan("file_read", "cat /etc/hosts",
                  [{"check": "file_exists", "path": "/etc/hosts"}]),
        "approve"
    ),
    (
        "/proc/meminfo exists → approve",
        make_plan("memory_usage", "cat /proc/meminfo",
                  [{"check": "file_exists", "path": "/proc/meminfo"}]),
        "approve"
    ),
    (
        "/nonexistent/path → block",
        make_plan("file_read", "cat /nonexistent/totally/fake/file",
                  [{"check": "file_exists", "path": "/nonexistent/totally/fake/file"}]),
        "block"
    ),
    (
        "/tmp is writable → approve",
        make_plan("file_create", "touch /tmp/testfile",
                  [{"check": "path_writable", "path": "/tmp"}]),
        "approve"
    ),
    (
        "disk space check on / → approve or warn",
        make_plan("package_install", "apt install htop",
                  [{"check": "disk_space", "path": "/", "min_free_gb": 0.1}]),
        "approve"  # Almost certainly has >100MB free
    ),

    # ── Multi-condition chains ── (6 cases)
    (
        "service exists + port free (both ok) → approve",
        make_plan("service_start", "systemctl start nginx",
                  [
                      {"check": "service_exists", "service": "nginx"},
                      {"check": "port_free", "port": 9876},
                  ], "nginx"),
        "approve"
    ),
    (
        "service exists + process not running (both ok) → approve",
        make_plan("service_start", "systemctl start nginx",
                  [
                      {"check": "service_exists", "service": "nginx"},
                      {"check": "process_not_running", "process": "neverrunxyz"},
                  ]),
        "approve"
    ),
    (
        "service exists + nonexistent process (second check blocks) → block",
        make_plan("process_kill", "kill $(pgrep nginx)",
                  [
                      {"check": "service_exists", "service": "nginx"},
                      {"check": "process_running", "process": "999997"},
                  ]),
        "block"
    ),
    (
        "file exists + path writable (both /tmp) → approve",
        make_plan("file_copy", "cp /etc/hosts /tmp/hosts_backup",
                  [
                      {"check": "file_exists", "path": "/etc/hosts"},
                      {"check": "path_writable", "path": "/tmp"},
                  ]),
        "approve"
    ),
    (
        "file not exists + path writable → approve",
        make_plan("file_create", "touch /tmp/linxai_new_test_file_xyz",
                  [
                      {"check": "file_not_exists", "path": "/tmp/linxai_new_test_file_xyz"},
                      {"check": "path_writable", "path": "/tmp"},
                  ]),
        "approve"
    ),
    (
        "port free + disk space + service exists → approve",
        make_plan("service_start", "systemctl start nginx",
                  [
                      {"check": "port_free", "port": 9994},
                      {"check": "disk_space", "path": "/", "min_free_gb": 0.05},
                      {"check": "service_exists", "service": "nginx"},
                  ]),
        "approve"
    ),

    # ── Resource checks ── (4 cases)
    (
        "memory available (256MB) → approve or warn",
        make_plan("package_install", "apt install python3",
                  [{"check": "memory_available", "min_free_mb": 256.0}]),
        "approve"  # Should have >256MB in 8GB VM
    ),
    (
        "memory available (very high threshold) → warn",
        make_plan("package_install", "apt install heavypackage",
                  [{"check": "memory_available", "min_free_mb": 99999.0}]),
        "warn"
    ),
    (
        "cpu load check (90% threshold) → approve or warn",
        make_plan("process_background", "python3 script.py &",
                  [{"check": "cpu_load", "max_load_pct": 90.0}]),
        "approve"  # Idle VM should be well under 90%
    ),
    (
        "disk space (tiny threshold 0.001GB) → approve",
        make_plan("file_create", "touch /tmp/x",
                  [{"check": "disk_space", "path": "/tmp", "min_free_gb": 0.001}]),
        "approve"
    ),

    # ── User checks ── (3 cases)
    (
        "user 'root' exists → approve",
        make_plan("user_groups", "groups root",
                  [{"check": "user_exists", "username": "root"}], "root"),
        "approve"
    ),
    (
        "user 'ubuntu' exists → approve",
        make_plan("user_groups", "groups ubuntu",
                  [{"check": "user_exists", "username": "ubuntu"}], "ubuntu"),
        "approve"
    ),
    (
        "user 'zzfakeuserxyz' does not exist → block",
        make_plan("user_remove", "userdel zzfakeuserxyz",
                  [{"check": "user_exists", "username": "zzfakeuserxyz"}]),
        "block"
    ),

    # ── Edge cases ── (1 case)
    (
        "unknown check type → approve (unknown = skip, not block)",
        make_plan("system_info", "uname -a",
                  [{"check": "totally_unknown_check_xyz", "param": 42}]),
        "approve"
    ),
]


def run_tests():
    print("=" * 70)
    print("  LINxAI — Command Intelligence Engine Test Suite")
    print(f"  {len(TEST_CASES)} scenarios | Target: ≥95% correct | Timeout: 500ms")
    print("=" * 70)
    print()

    passed = 0
    failed = []
    slow = []

    for i, (description, plan, expected) in enumerate(TEST_CASES, 1):
        t = time.perf_counter()
        result = cie.validate(plan)
        duration_ms = int((time.perf_counter() - t) * 1000)

        got = result["decision"]

        # Some checks can return either approve or warn depending on system state
        # We encode this with a "/" in expected
        if "/" in expected:
            ok = got in expected.split("/")
        else:
            ok = (got == expected)

        status = "✓" if ok else "✗"
        speed = f"{duration_ms}ms"
        speed_flag = " ⚠ SLOW" if duration_ms > 500 else ""

        print(
            f"  [{status}] {i:02d}. {description[:50]:<50} "
            f"got={got:<8} {speed}{speed_flag}"
        )

        if ok:
            passed += 1
        else:
            failed.append({
                "id": i,
                "description": description,
                "expected": expected,
                "got": got,
                "reason": result.get("reason", ""),
                "duration_ms": duration_ms
            })

        if duration_ms > 500:
            slow.append({"id": i, "description": description, "ms": duration_ms})

    total = len(TEST_CASES)
    accuracy = passed / total * 100

    print()
    print("=" * 70)
    print(f"  RESULT: {passed}/{total} correct — {accuracy:.1f}% accuracy")
    print(f"  Target: 95.0% (38/40)")
    print(f"  Status: {'PASS ✓' if accuracy >= 95 else 'FAIL ✗'}")

    if slow:
        print(f"\n  Slow checks (>{500}ms):")
        for s in slow:
            print(f"    #{s['id']}: {s['description']} — {s['ms']}ms")

    if failed:
        print(f"\n  Failed cases ({len(failed)}):")
        for f in failed:
            print(f"    #{f['id']}: {f['description']}")
            print(f"      expected: {f['expected']}")
            print(f"      got:      {f['got']}")
            print(f"      reason:   {f['reason'][:120]}")
            print()

    print("=" * 70)
    return accuracy >= 95


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)