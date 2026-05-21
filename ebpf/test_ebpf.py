# ebpf/test_ebpf.py
import sys
import os
import time
import subprocess
import socket
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_test():
    print("=" * 55)
    print("  LINxAI eBPF Daemon — Integration Test")
    print("  Target: capture at least 1 event of each type")
    print("=" * 55)
    print()

    if os.geteuid() != 0:
        print("ERROR: Must run as root. Use: sudo python3 ebpf/test_ebpf.py")
        sys.exit(1)

    from ebpf.daemon import eBPFDaemon

    captured = []

    def on_event(record):
        captured.append(record)

    print("  Loading eBPF probes...")
    daemon = eBPFDaemon(
        log_path="/tmp/linxai_ebpf_test.jsonl",
        event_callback=on_event,
        filter_noise=False
    )

    # Start in background thread
    thread = daemon.start_async()
    
    # Wait longer to ensure polling loop is running
    print("  Waiting for polling loop to start...")
    time.sleep(4)
    print("  Probes loaded and polling. Generating test events...\n")

    # Trigger execve
    print("  [1/3] Triggering execve (launching 'ls')...")
    subprocess.run(["ls", "/tmp"], capture_output=True)
    time.sleep(1)

    # Trigger openat
    print("  [2/3] Triggering openat (reading /etc/hostname)...")
    with open("/etc/hostname", "r") as f:
        f.read()
    time.sleep(1)

    # Trigger connect — use Python socket directly, more reliable than curl
    print("  [3/3] Triggering connect (socket to 1.1.1.1:80)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('1.1.1.1', 80))
        s.close()
    except Exception:
        pass
    
    # Also try curl as backup
    subprocess.run(
        ["curl", "-s", "--max-time", "2", "http://1.1.1.1"],
        capture_output=True
    )
    time.sleep(2)

    daemon.stop()

    # Analyse
    print()
    print("=" * 55)
    print(f"  Events captured: {len(captured)}")
    print()

    types_seen = {r["event_type"] for r in captured}
    checks = [
        ("process_exec",    "execve probe"),
        ("file_open",       "openat probe"),
        ("network_connect", "connect probe"),
    ]

    passed = 0
    for event_type, label in checks:
        ok = event_type in types_seen
        status = "✓" if ok else "✗"
        print(f"  [{status}] {label} — {event_type}")
        if ok:
            sample = next(r for r in captured if r["event_type"] == event_type)
            p = sample["payload"]
            print(f"       sample: pid={p.get('pid')} "
                  f"process={p.get('process')} "
                  f"{p.get('filename', p.get('dest_ip', ''))}")
        print()

    stats = daemon.get_stats()
    print(f"  Total — execve:{stats['execve']} "
          f"connect:{stats['connect']} "
          f"openat:{stats['openat']}")
    print()
    print("=" * 55)
    print(f"  RESULT: {passed}/3 probes working" if passed < 3 else
          f"  RESULT: {sum(1 for _,l in checks if l.split()[0]+'_'+l.split()[1] in types_seen)}/3")
    
    passed = sum(1 for et, _ in checks if et in types_seen)
    print(f"  RESULT: {passed}/3 probes working")
    print(f"  Status: {'PASS ✓' if passed == 3 else 'FAIL ✗'}")
    print("=" * 55)
    return passed == 3


if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)