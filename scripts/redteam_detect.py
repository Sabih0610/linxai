"""Red-team detection run: common attacker techniques against the real monitor.

Run on the prepared target as the ORDINARY owner while the root sensor and the
monitor are running (incidents in ~/.linxai/security.sqlite):

    LINXAI_TEST_REDTEAM=1 python3 -B scripts/redteam_detect.py --out redteam-detect.json

Every technique is harmless and stays on loopback: "reverse shells" only connect to
a local listener and send one line; tools are do-nothing copies; credential reads are
refused by the kernel (the attempt is what is observed). Each case states what the
current rules are EXPECTED to do. A miss that the rules cannot see is reported as a
known gap, never as a pass, so the run measures coverage instead of confirming it.
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
from scripts.accept_detection import incidents_since   # noqa: E402  (same store reader)


def listen(family=socket.AF_INET, host="127.0.0.1", port=0):
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port)); server.listen(16)

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


def run(argv, timeout=8, **kw):
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)
    try:
        child.wait(timeout)
    except subprocess.TimeoutExpired:
        child.kill(); child.wait()
    return child.pid


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", default=str(Path.home() / ".linxai"))
    parser.add_argument("--out", default="redteam-detect.json")
    parser.add_argument("--wait", type=float, default=12.0, help="seconds to wait for an incident per case")
    args = parser.parse_args(argv)
    if os.environ.get("LINXAI_TEST_REDTEAM") != "1":
        print("PENDING: opt in with LINXAI_TEST_REDTEAM=1 on the prepared isolated target"); return 3
    if os.getuid() == 0:
        raise PermissionError("Run as the ordinary owner, like an attacker who gained a user shell")
    store = Path(args.state) / "security.sqlite"
    if not store.exists():
        print("FAIL: no monitor store; start the sensor and the monitor first"); return 2
    normal, port = listen()                              # an ordinary high port
    c2, c2_port = listen(port=4444)                      # a classic C2 / backdoor port
    v6, v6_port = listen(socket.AF_INET6, "::1")
    nc = os.path.realpath(shutil.which("nc") or "/usr/bin/nc")
    py = sys.executable
    connect = f"import socket;s=socket.create_connection(('127.0.0.1',{{}}),3);s.sendall(b'redteam\\n');s.close()"
    results = []
    with tempfile.TemporaryDirectory(prefix="redteam-", dir=Path.home()) as temp:
        home = Path(temp)
        for name in ("nmap", "scan-helper"):
            (home / name).write_text("#!/bin/sh\nexit 0\n"); (home / name).chmod(0o700)
        shutil.copy(nc, home / "kworker"); (home / "kworker").chmod(0o700)          # renamed netcat
        tmp_tool = Path(tempfile.mkdtemp(prefix="rt-", dir="/tmp")) / "updater"
        shutil.copy("/usr/bin/true", tmp_tool); tmp_tool.chmod(0o700)
        cases = [
            # (id, technique, expected rule or None for a known gap, argv)
            ("bash_dev_tcp_reverse_shell", "T1059.004 reverse shell via bash /dev/tcp", "shell_network_connection",
             ["/bin/bash", "-c", f"exec 3<>/dev/tcp/127.0.0.1/{port}; echo redteam >&3; exec 3>&-"]),
            ("netcat_reverse_shell", "T1059 netcat call-back", "shell_network_connection",
             [nc, "-w", "2", "127.0.0.1", str(port)]),
            ("python_reverse_shell", "T1059.006 python socket call-back on an ordinary port", None,
             [py, "-c", connect.format(port)]),
            ("perl_reverse_shell", "T1059 perl socket call-back on an ordinary port", None,
             ["/usr/bin/perl", "-MIO::Socket::INET", "-e", f"IO::Socket::INET->new('127.0.0.1:{port}') or exit 1"]),
            ("renamed_netcat", "T1036.003 masquerading: netcat copied as 'kworker'", None,
             [str(home / "kworker"), "-w", "2", "127.0.0.1", str(port)]),
            ("c2_backdoor_port", "T1571 connection to a classic backdoor port (4444)", "unusual_connection_attempt",
             [py, "-c", connect.format(c2_port)]),
            ("ipv6_reverse_shell", "reverse shell over IPv6 loopback", None,
             ["/bin/bash", "-c", f"exec 3<>/dev/tcp/::1/{v6_port}; echo redteam >&3; exec 3>&-"]),
            ("attack_tool_by_name", "T1046 scanner executed as 'nmap'", "attack_tool_execution", [str(home / "nmap")]),
            ("attack_tool_renamed", "T1036 same scanner renamed", None, [str(home / "scan-helper")]),
            ("exec_from_tmp", "T1204 payload executed from /tmp", "temporary_executable_attempt", [str(tmp_tool)]),
            ("read_etc_shadow", "T1003.008 credential dump attempt on /etc/shadow", "sensitive_file_attempt",
             ["/usr/bin/cat", "/etc/shadow"]),
            ("read_etc_gshadow", "T1003.008 credential dump attempt on /etc/gshadow", None, ["/usr/bin/cat", "/etc/gshadow"]),
            ("persistence_authorized_keys", "T1098.004 open ~/.ssh/authorized_keys for writing (no bytes written)", None,
             [py, "-c", "import os,pathlib;p=pathlib.Path.home()/'.ssh';p.mkdir(mode=0o700,exist_ok=True);open(p/'authorized_keys','a').close()"]),
            ("inbound_bind_shell", "T1059 bind shell listening on 4445 (inbound)", None,
             ["/bin/bash", "-c", f"timeout 5 {nc} -l 127.0.0.1 4445 & sleep 1; {py} -c \"{connect.format(4445)}\"; wait"]),
        ]
        controls = [("benign_curl", ["/usr/bin/curl", "-s", "-m", "2", f"http://127.0.0.1:{port}/"]),
                    ("benign_python_connect", [py, "-c", connect.format(port)]),
                    ("benign_ls", ["/usr/bin/ls", "/etc"])]
        for case_id, technique, expected, command in cases:
            started = time.time()
            pid = run(command)
            deadline, found = time.monotonic() + args.wait, []
            while time.monotonic() < deadline:
                found = [r for r in incidents_since(store, started) if r["evidence"].get("pid") == pid
                         or r["evidence"]["target"].get("port") in (port, c2_port, v6_port, 4445) and r["created"] >= started]
                if found and (expected is None or any(r["rule"] == expected for r in found)):
                    break
                time.sleep(0.5)
            rules = sorted({r["rule"] for r in found})
            if expected:
                verdict = "DETECTED" if expected in rules else "MISSED"
            else:
                verdict = "DETECTED (better than expected)" if rules else "GAP (not detected, as the rules predict)"
            latency = round(min((r["created"] for r in found), default=started) - started, 2) if found else None
            results.append({"id": case_id, "technique": technique, "expected_rule": expected, "rules": rules,
                            "verdict": verdict, "latency_s": latency})
            print(f"{verdict:42} {case_id:30} {rules}", flush=True)
            time.sleep(1.5)                                  # keep cases apart in time
        false_alarms = []
        for control_id, command in controls:
            started = time.time()
            pid = run(command)
            time.sleep(4)
            hits = [r["rule"] for r in incidents_since(store, started, slack=0) if r["evidence"].get("pid") == pid]
            false_alarms += [{"control": control_id, "rules": hits}] if hits else []
            print(("FALSE ALARM " if hits else "clean       ") + control_id, hits, flush=True)
        shutil.rmtree(tmp_tool.parent, ignore_errors=True)
    for server in (normal, c2, v6):
        server.close()
    summary = {"detected_expected": sum(r["verdict"] == "DETECTED" for r in results),
               "expected_detections": sum(bool(r["expected_rule"]) for r in results),
               "missed_expected": [r["id"] for r in results if r["verdict"] == "MISSED"],
               "known_gaps_confirmed": [r["id"] for r in results if r["verdict"].startswith("GAP")],
               "false_alarms": false_alarms}
    Path(args.out).write_text(json.dumps({"summary": summary, "cases": results}, indent=2) + "\n")
    print(json.dumps(summary, indent=1))
    return 0 if not summary["missed_expected"] and not false_alarms else 1


if __name__ == "__main__":
    raise SystemExit(main())
