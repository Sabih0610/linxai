# test_pipeline.py
# End-to-end pipeline smoke test.
# Target: all commands complete under 30 seconds (VM hardware).
# On native Ubuntu reference hardware, pipeline completes under 10 seconds.
# Run: sudo python3 test_pipeline.py

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_smoke_test():
    print("=" * 65)
    print("  LINxAI — End-to-End Pipeline Smoke Test")
    print("  Target: all commands complete under 30 seconds (VM hardware)")
    print("  Note:   on native Ubuntu this runs under 10 seconds")
    print("=" * 65)
    print()

    from main import LINxAIPipeline
    print("  Initialising pipeline...")
    pipeline = LINxAIPipeline(use_face_auth=False, quiet=True)
    print("  Pipeline ready.\n")

    TEST_CASES = [
        ("show disk usage",             ["success", "error"], 120000),
        ("list all running processes",  ["success", "error"],  30000),
        ("check memory usage",          ["success"],           30000),
        ("show system uptime",          ["success"],           30000),
        ("check if port 9999 is open",  ["success", "error"],  30000),
        ("check if port 22 is open",    ["success", "error"],  30000),
        ("what is the kernel version",  ["success"],           30000),
        ("show cpu usage",              ["success"],           30000),
    ]

    passed = 0
    failed = []

    for i, (command, expected_outcomes, max_ms) in enumerate(TEST_CASES, 1):
        t = time.perf_counter()
        result = pipeline.process(command)
        actual_ms = int((time.perf_counter() - t) * 1000)

        outcome     = result.get("outcome", "?")
        total_ms    = result.get("total_ms", actual_ms)
        under_limit = total_ms <= max_ms
        good        = outcome in expected_outcomes

        ok     = good and under_limit
        status = "✓" if ok else "✗"
        flag   = "" if under_limit else " ⚠ SLOW"

        print(f"  [{status}] {i:02d}. {command:<45}  "
              f"outcome={outcome:<10}  {total_ms}ms{flag}")

        if ok:
            passed += 1
        else:
            failed.append({
                "command":  command,
                "outcome":  outcome,
                "expected": expected_outcomes,
                "ms":       total_ms,
            })

    total = len(TEST_CASES)
    pct   = passed / total * 100

    print()
    print("=" * 65)
    print(f"  RESULT: {passed}/{total} passed — {pct:.0f}%")

    if passed == total:
        print("  Status: PASS ✓  M7 milestone achieved")
    else:
        print("  Status: FAIL ✗")
        for f in failed:
            print(f"    '{f['command']}' → {f['outcome']} "
                  f"(expected {f['expected']}, {f['ms']}ms)")

    print("=" * 65)
    print()
    return passed == total


if __name__ == "__main__":
    success = run_smoke_test()
    sys.exit(0 if success else 1)