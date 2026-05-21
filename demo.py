# demo.py
# Automated jury demo — two scenarios showing the full pipeline.
# Run: sudo python3 demo.py

import sys
import os
import time
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

def green(t):  return _c("32", t)
def yellow(t): return _c("33", t)
def cyan(t):   return _c("36", t)
def red(t):    return _c("31", t)
def dim(t):    return _c("2",  t)
def bold(t):   return _c("1",  t)


def separator(title=""):
    line = "─" * 60
    if title:
        print(f"\n  {dim(line)}")
        print(f"  {bold(title)}")
        print(f"  {dim(line)}")
    else:
        print(f"\n  {dim(line)}")


def run_demo():
    print()
    print(bold("  ╔══════════════════════════════════════════════════╗"))
    print(bold("  ║          LINxAI — FYP-I Defense Demo            ║"))
    print(bold("  ║   Autonomous AI-Driven System Layer for Linux    ║"))
    print(bold("  ╚══════════════════════════════════════════════════╝"))
    print()
    print(dim("  Scenario 1: Happy path — command executes successfully"))
    print(dim("  Scenario 2: Conflict blocking — CIE prevents bad command"))
    print()
    time.sleep(2)

    from main import LINxAIPipeline
    pipeline = LINxAIPipeline(use_face_auth=False)

    # Scenario 1: Happy path
    separator("SCENARIO 1 — Port 80 is free, nginx restarts successfully")

    subprocess.run(["sudo", "systemctl", "stop", "apache2"],
                   capture_output=True)
    subprocess.run(["sudo", "systemctl", "stop", "nginx"],
                   capture_output=True)
    time.sleep(1)
    print(f"  {dim('Setup: port 80 is now free')}")

    user_input_1 = "restart nginx only if port 80 is free"
    print(f"\n  {bold('USER INPUT:')}  {cyan(user_input_1)}")
    time.sleep(1)

    result1 = pipeline.process(user_input_1)

    print()
    if result1["outcome"] == "success":
        print(f"  {green('SCENARIO 1 PASSED')} — nginx restarted successfully")
        print(f"  {dim('Pipeline completed in')} {result1['total_ms']}ms")
    else:
        print(f"  outcome: {result1['outcome']}")

    time.sleep(3)

    # Scenario 2: Conflict blocking
    separator("SCENARIO 2 — Port 80 occupied, nginx correctly blocked")

    print(f"  {dim('Setup: occupying port 80...')}")
    http_proc = None
    r = subprocess.run(["sudo", "systemctl", "start", "apache2"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        http_proc = subprocess.Popen(
            ["sudo", "python3", "-m", "http.server", "80"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)
    print(f"  {dim('Port 80 is now occupied')}")

    user_input_2 = "restart nginx only if port 80 is free"
    print(f"\n  {bold('USER INPUT:')}  {cyan(user_input_2)}")
    time.sleep(1)

    result2 = pipeline.process(user_input_2)

    print()
    if result2["outcome"] == "blocked":
        print(f"  {green('SCENARIO 2 PASSED')} — CIE correctly blocked the command")
        print(f"  {dim('Reason:')} "
              f"{result2['validation'].get('reason','')[:80]}")
        print()
        print(f"  {bold('This is the key differentiator.')}")
        print(f"  {dim('ShellGPT and Warp execute blindly. LINxAI prevented the error.')}")
    else:
        print(f"  outcome: {result2['outcome']}")

    if http_proc:
        http_proc.terminate()
    subprocess.run(["sudo", "systemctl", "stop", "apache2"],
                   capture_output=True)

    # Summary
    separator("Demo Complete — Audit Log Summary")
    records = pipeline.audit.query_session(last_n=20)
    print(f"\n  {len(records)} events recorded:\n")
    for r in records:
        ts = r["timestamp"][11:19]
        p = r.get("payload", {})
        detail = str(p.get("intent") or p.get("decision") or
                     p.get("status") or "")[:40]
        print(f"  {dim(ts)}  [{r['module']:<10}]  {r['event_type']}"
              f"  {dim(detail)}")

    print()
    stats = pipeline.audit.get_stats()
    print(f"  Total records: {stats['total_records']}")
    separator()
    print(f"\n  {green(bold('LINxAI demo complete.'))}\n")


if __name__ == "__main__":
    run_demo()