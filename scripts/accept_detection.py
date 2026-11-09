"""Real-kernel acceptance of network/attack-tool detection (requirements 38, 39).

Harmless fixtures on loopback only, run as the ordinary owner while the root BCC
sensor and the monitor are running:
  * reverse-shell shape: bash opens /dev/tcp to a local listener and sends one line
  * raw network tool: nc connects to the same listener (if nc is installed)
  * backdoor port: python connects to 127.0.0.1:31337 (refused; entry is observed)
  * attack tool: a do-nothing script named `nmap` in a private directory is executed
Each must yield a monitor incident with the expected rule. Benign controls (curl to
the listener, python connect to an ordinary port, a shell running `true`) must not.
    python3 -B scripts/accept_detection.py --out detection.json
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def listener():
    server = socket.socket()
    server.bind(("127.0.0.1", 0)); server.listen(8)
    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(2)
                try: conn.recv(64)
                except OSError: pass
    threading.Thread(target=serve, daemon=True).start()
    return server, server.getsockname()[1]


def incidents_since(store_path, started, slack=1.0):
    from operations.store import Store
    store = Store(store_path)
    try: rows = store.list("incident", 200)
    finally: store.close()
    return [r for r in rows if r.get("created", 0) >= started - slack]


def wait_for(store_path, started, match, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = [r for r in incidents_since(store_path, started) if match(r)]
        if found:
            return found[0]
        time.sleep(1)
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", default=str(Path.home() / ".linxai"))
    parser.add_argument("--out", default="detection.json")
    args = parser.parse_args(argv)
    if os.getuid() == 0:
        raise PermissionError("Run as the ordinary owner")
    store = Path(args.state) / "security.sqlite"
    server, port = listener()
    results, controls = [], []
    with tempfile.TemporaryDirectory(prefix="linxai-detect-", dir=Path.home()) as temp:
        tool = Path(temp) / "nmap"
        tool.write_text("#!/bin/sh\nexit 0\n"); tool.chmod(0o700)
        nc = shutil.which("nc")
        fixtures = [
            ("reverse_shell_bash_dev_tcp", "shell_network_connection",
             ["/bin/bash", "-c", f"exec 3<>/dev/tcp/127.0.0.1/{port}; echo linxai-fixture >&3; exec 3>&-"],
             lambda r: r["evidence"]["target"].get("port") == port and r["evidence"]["process"] == "bash"),
            ("raw_network_tool_nc", "shell_network_connection",
             [nc, "-z", "-w", "2", "127.0.0.1", str(port)] if nc else None,
             lambda r: r["evidence"]["target"].get("port") == port and r["evidence"]["process"].startswith("nc")),
            ("backdoor_port_31337", "unusual_connection_attempt",
             [sys.executable, "-c", "import socket\ntry: socket.create_connection(('127.0.0.1', 31337), 1)\nexcept OSError: pass"],
             lambda r: r["evidence"]["target"].get("port") == 31337),
            ("attack_tool_exec_nmap", "attack_tool_execution", [str(tool)],
             lambda r: r["evidence"]["target"].get("path") == str(tool)),
        ]
        for name, rule, argv_, match in fixtures:
            if argv_ is None:
                results.append({"fixture": name, "expected": rule, "status": "skipped (tool not installed)"}); continue
            started = time.time()
            subprocess.run(argv_, timeout=10, capture_output=True)
            found = wait_for(store, started, lambda r: r.get("rule") == rule and match(r))
            results.append({"fixture": name, "expected": rule, "detected": found is not None,
                            "latency_s": round(found["created"] - started, 2) if found else None,
                            "identity_quality": found["evidence"].get("identity_quality") if found else None})
            print(results[-1], flush=True)
        # Benign controls: none may raise one of the network/attack-tool rules. A quiet gap and
        # a zero-slack window keep the fixtures' own incidents out of this count.
        time.sleep(3)
        started = time.time()
        benign = [["/usr/bin/curl", "-s", "-m", "2", f"http://127.0.0.1:{port}/"],
                  [sys.executable, "-c", f"import socket; socket.create_connection(('127.0.0.1', {port}), 1).close()"],
                  ["/bin/bash", "-c", "true"], ["/usr/bin/ls", "/"]]
        for argv_ in benign:
            if Path(argv_[0]).exists():
                subprocess.run(argv_, timeout=10, capture_output=True)
                controls.append(argv_[0])
        time.sleep(15)
        rules = {"shell_network_connection", "unusual_connection_attempt", "attack_tool_execution"}
        false_alarms = [{"rule": r["rule"], "process": r["evidence"].get("process"), "target": r["evidence"].get("target")}
                        for r in incidents_since(store, started, slack=0.0) if r.get("rule") in rules]
    server.close()
    record = {"listener_port": port, "fixtures": results, "benign_controls": controls, "false_alarms": false_alarms}
    Path(args.out).write_text(json.dumps(record, indent=2) + "\n")
    ok = all(r.get("detected") for r in results if "detected" in r) and not false_alarms
    print("PASS" if ok else "FAIL", json.dumps({"false_alarms": false_alarms}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
