# vps/test_vps.py
# Test suite for LINxAI VPS Manager.
#
# Run:
#   python3 vps/test_vps.py

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vps.manager import VPSManager


def run_tests():
    print("=" * 55)
    print("  LINxAI VPS Manager — Test Suite")
    print("=" * 55)
    print()

    passed = 0
    total = 0

    def check(description, condition):
        nonlocal passed, total
        total += 1
        status = "✓" if condition else "✗"
        print(f"  [{status}] {description}")
        if condition:
            passed += 1

    manager = VPSManager()

    # Test 1: config loads
    servers = manager.list_servers()

    check("Config loads successfully", isinstance(servers, list))
    check("At least one server configured", len(servers) >= 1)
    check("local-vm exists", any(s["name"] == "local-vm" for s in servers))

    # Test 2: SSH health check
    print()
    print("  Running SSH health check...")

    health = manager.health_check("local-vm")

    check("Health check returns dict", isinstance(health, dict))
    check("Health check succeeds", health["status"] == "success")
    check("Health check contains LINXAI_VPS_OK", "LINXAI_VPS_OK" in health["stdout"])
    check("Health check has duration", health["duration_ms"] >= 0)

    # Test 3: basic remote command
    print()
    print("  Running basic remote command...")

    result = manager.run_command("local-vm", "echo PHASE10_READY")

    check("Remote echo succeeds", result["status"] == "success")
    check("Remote echo output correct", "PHASE10_READY" in result["stdout"])
    check("Remote command exit code 0", result["exit_code"] == 0)

    # Test 4: system info command
    uname = manager.run_command("local-vm", "uname -a")

    check("uname command succeeds", uname["status"] == "success")
    check("uname output contains Linux", "Linux" in uname["stdout"])

    # Test 5: disk check helper
    disk = manager.check_disk("local-vm")

    check("Disk check succeeds", disk["status"] == "success")
    check("Disk output contains filesystem info", "Filesystem" in disk["stdout"])

    # Test 6: memory check helper
    memory = manager.check_memory("local-vm")

    check("Memory check succeeds", memory["status"] == "success")
    check("Memory output contains Mem", "Mem:" in memory["stdout"])

    # Test 7: dangerous command blocked
    dangerous = manager.run_command("local-vm", "rm -rf /")

    check("Dangerous command is blocked", dangerous["status"] == "blocked")
    check("Blocked command has reason", "Forbidden" in dangerous["stderr"])

    # Test 8: run_many works
    many = manager.run_many(["local-vm"], "echo MULTI_SERVER_OK")

    check("run_many returns list", isinstance(many, list))
    check("run_many returns one result", len(many) == 1)
    check("run_many command succeeds", many[0]["status"] == "success")
    check("run_many output correct", "MULTI_SERVER_OK" in many[0]["stdout"])

    manager.close_all()

    print()
    print("=" * 55)
    print(f"  RESULT: {passed}/{total} passed — {passed / total * 100:.0f}%")
    print(f"  Status: {'PASS ✓' if passed == total else 'PARTIAL'}")
    print("=" * 55)

    print()
    print("  Sample VPS command result:")
    print(f"  Server:   {result['server']}")
    print(f"  Status:   {result['status']}")
    print(f"  Output:   {result['stdout']}")
    print(f"  Duration: {result['duration_ms']}ms")

    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)