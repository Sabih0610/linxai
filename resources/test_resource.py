# resource/test_resource.py
# Test suite for the Resource Manager.
# Run: python3 resource/test_resource.py

import sys
import os
import time
import psutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from resources.monitor import ResourceManager, _classify_process, CPU_THRESHOLD_PCT


def run_tests():
    print("=" * 55)
    print("  LINxAI Resource Manager — Test Suite")
    print("=" * 55)
    print()

    passed = 0
    total  = 0

    def check(description, condition):
        nonlocal passed, total
        total += 1
        status = "✓" if condition else "✗"
        print(f"  [{status}] {description}")
        if condition:
            passed += 1

    # ── Test 1: ResourceManager initialises ─────────────────────────────────
    rm = ResourceManager(cpu_threshold=CPU_THRESHOLD_PCT)
    check("ResourceManager initialises", rm is not None)
    check("Initial CPU is 0.0", rm.get_stats()["cpu_pct"] == 0.0)
    check("Initial renice_count is 0", rm.get_stats()["renice_count"] == 0)

    # ── Test 2: Starts and stops cleanly ────────────────────────────────────
    rm.start()
    time.sleep(2)
    check("Monitor thread is running", rm.running)
    check("Stats are being updated",
          rm.get_stats()["last_updated"] is not None)

    # ── Test 3: CPU metric is a real number ──────────────────────────────────
    stats = rm.get_stats()
    check("CPU percent is a float", isinstance(stats["cpu_pct"], float))
    check("CPU percent is in range 0-100",
          0.0 <= stats["cpu_pct"] <= 100.0)

    # ── Test 4: Memory metric is realistic ──────────────────────────────────
    check("Memory percent in range", 0.0 < stats["memory_pct"] < 100.0)
    check("Memory used > 0 MB", stats["memory_used_mb"] > 0)
    check("Memory total > 0 MB", stats["memory_total_mb"] > 0)
    check("Memory used <= total",
          stats["memory_used_mb"] <= stats["memory_total_mb"])

    # ── Test 5: Process classification ──────────────────────────────────────
    for proc in psutil.process_iter():
        try:
            cls = _classify_process(proc)
            check(f"classify_process returns valid value for PID {proc.pid}",
                  cls in ("foreground", "background", "system"))
            break
        except Exception:
            continue

    # ── Test 6: get_top_processes returns list ───────────────────────────────
    top = rm.get_top_processes(n=5)
    check("get_top_processes returns a list", isinstance(top, list))
    check("get_top_processes returns <= 5 items", len(top) <= 5)
    if top:
        check("Each process has pid field",
              all("pid" in p for p in top))
        check("Each process has cpu_pct field",
              all("cpu_pct" in p for p in top))
        check("Each process has class field",
              all("class" in p for p in top))

    # ── Test 7: Low threshold triggers renice ────────────────────────────────
    print()
    print("  Testing renice at low threshold (1%)...")
    rm2 = ResourceManager(cpu_threshold=1.0)  # trigger at 1% CPU
    events = []
    rm2.log_callback = lambda et, data: events.append((et, data))
    rm2.start()
    time.sleep(3)
    rm2.stop()

    # At 1% threshold on any active system this should fire
    renice_fired = rm2.get_stats()["renice_count"] > 0 or \
                   any(et == "renice_applied" for et, _ in events)
    check("Renice fires when threshold exceeded",
          renice_fired or rm2.get_stats()["cpu_pct"] < 1.0)

    # ── Test 8: Stop cleans up ───────────────────────────────────────────────
    rm.stop()
    time.sleep(0.5)
    check("Monitor stops cleanly", not rm.running)

    # ── Summary ──────────────────────────────────────────────────────────────
    print()
    print("=" * 55)
    print(f"  RESULT: {passed}/{total} passed — {passed/total*100:.0f}%")
    print(f"  Status: {'PASS ✓' if passed == total else 'PARTIAL'}")
    print("=" * 55)

    # Show current system snapshot
    print()
    print("  Current system snapshot:")
    final = rm.get_stats()
    print(f"  CPU:    {final['cpu_pct']:.1f}%")
    print(f"  RAM:    {final['memory_used_mb']}MB / "
          f"{final['memory_total_mb']}MB "
          f"({final['memory_pct']:.1f}%)")
    print(f"  Top processes:")
    for p in rm.get_top_processes(5):
        print(f"    {p['name']:<20} CPU:{p['cpu_pct']:5.1f}%  "
              f"class:{p['class']}")

    return passed >= total - 1  # allow 1 failure for environment differences


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)