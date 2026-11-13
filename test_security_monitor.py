"""Deterministic evidence/incident contracts; no BPF or service installation."""
import copy
import os
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from security.events import admit, detect, normalize
from security.monitor import Monitor
from security.sensor import Buffer, capture
from test_application import MemoryStore


def record(path="/etc/shadow", uid=1000, pid=123):
    return {"event_type": "file_open", "payload": {"filename": path, "uid": uid, "pid": pid,
            "process": "untrusted $(commands)", "start_ns": 123456, "monotonic_ns": 234567}}


class Source:
    trusted = False
    def __init__(self, buffer): self.buffer = buffer
    def poll(self, cursor, epoch): return self.buffer.poll(cursor, epoch)


class SecurityMonitorTests(unittest.TestCase):
    def setUp(self):
        self.buffer, self.store = Buffer("host", "boot", capacity=2), MemoryStore()
        self.monitor = Monitor(self.store, Source(self.buffer))

    def test_suspicious_event_to_durable_incident_without_model(self):
        event = self.buffer.publish(record())
        self.monitor.tick()
        incident = self.store.get("incident", event["id"])
        self.assertEqual(incident["rule"], "sensitive_file_attempt")
        self.assertEqual(incident["response"], "none")
        self.assertEqual(incident["evidence"]["source"], "simulated")
        self.assertIn("outcome unknown", incident["evidence"]["result"])
        self.monitor.tick()
        self.assertEqual(len(self.store.list("incident")), 1)

    def test_benign_near_matches_and_root_reads_not_suspicious(self):
        for value in (record("/etc/shadow.backup"), record("/home/user/shadow"), record(uid=0)):
            self.assertIsNone(detect(normalize(value, "host", "boot", source="simulated")))

    def test_reverse_shell_attack_tool_and_unusual_port_rules(self):
        def connect(process, port, protocol=6):
            return normalize({"event_type": "network_connect", "payload": {"dest_ip": "203.0.113.9", "dest_port": port,
                              "protocol": protocol, "uid": 1000, "pid": 7, "process": process}}, "h", "b", source="simulated")
        def exe(path):
            return normalize({"event_type": "process_exec", "payload": {"filename": path, "uid": 1000, "pid": 8,
                              "process": "bash"}}, "h", "b", source="simulated")
        self.assertEqual(detect(connect("bash", 443))["rule"], "shell_network_connection")
        self.assertEqual(detect(connect("nc", 8080))["rule"], "shell_network_connection")
        self.assertEqual(detect(connect("python3", 31337))["rule"], "unusual_connection_attempt")
        self.assertEqual(detect(exe("/usr/bin/nmap"))["rule"], "attack_tool_execution")
        # Benign near matches: ordinary clients, shells over UDP, look-alike names, normal ports.
        for event in (connect("curl", 443), connect("bash", 53, protocol=17), connect("bashful", 443),
                      connect("python3", 8443), exe("/usr/bin/nmapper"), exe("/usr/bin/ls")):
            self.assertIsNone(detect(event), event)

    def test_path_tricks_and_extra_credential_files_are_caught(self):
        # QA 13 Nov 2026: '/tmp//x', '/./etc/shadow', /etc/gshadow, sudoers.d and /var/tmp evaded the rules.
        def event(kind, path):
            return normalize({"event_type": kind, "payload": {"filename": path, "uid": 1000, "pid": 9, "process": "x"}},
                             "h", "b", source="simulated")
        for path in ("/etc//shadow", "/etc/./shadow", "/etc/gshadow", "/etc/sudoers.d/90-cloud", "/tmp/../etc/shadow"):
            self.assertEqual(detect(event("file_open", path))["rule"], "sensitive_file_attempt", path)
        for path in ("//tmp/x", "/./tmp/x", "/var/tmp/payload", "/dev/shm/./p"):
            self.assertEqual(detect(event("process_exec", path))["rule"], "temporary_executable_attempt", path)
        from security.events import admit
        self.assertTrue(admit({"event_type": "file_open", "payload": {"filename": "/etc//gshadow"}}))
        self.assertIsNone(detect(event("file_open", "/etc/sudoers.dist")))

    def _symlinks_ok(self):
        with tempfile.TemporaryDirectory() as d:
            try:
                os.symlink("socket:[1]", f"{d}/l"); return True
            except (OSError, NotImplementedError):
                return False

    def test_widened_rules_remote_shell_masquerade_persistence_ipv6(self):
        # Widened detection (13 Nov 2026), with a fake procfs: shells whose stdio (or whose
        # parent's stdio) is a TCP socket, renamed tool binaries, persistence writes, IPv6.
        if not self._symlinks_ok(): self.skipTest("symlinks unavailable on this host")
        from security.procfacts import ToolCatalog, facts
        with tempfile.TemporaryDirectory() as root:
            tools = os.path.join(root, "bin"); os.makedirs(tools)
            with open(f"{tools}/nc.openbsd", "wb") as f: f.write(b"\x7fELF fake netcat" * 64)
            with open(f"{tools}/bash", "wb") as f: f.write(b"\x7fELF fake bash" * 50)
            with open(f"{tools}/kworker", "wb") as f: f.write(b"\x7fELF fake netcat" * 64)     # renamed copy
            catalog = ToolCatalog(names=("nc",), which=lambda name: f"{tools}/nc.openbsd" if name == "nc" else None)
            def proc(pid, comm, ppid, start, stdio=None, tcp=(), exe=None):
                os.makedirs(f"{root}/{pid}/fd"); os.makedirs(f"{root}/{pid}/net")
                fields = ["S", str(ppid)] + ["0"] * 17 + [str(start)] + ["0"] * 10
                with open(f"{root}/{pid}/stat", "w") as f: f.write(f"{pid} ({comm}) " + " ".join(fields))
                with open(f"{root}/{pid}/status", "w") as f: f.write("Uid:\t1000\t1000\t1000\t1000\n")
                for fd in (0, 1, 2):
                    os.symlink(stdio or "/dev/pts/0", f"{root}/{pid}/fd/{fd}")
                with open(f"{root}/{pid}/net/tcp", "w") as f:
                    f.write("  sl  local rem st tx rx tr tm retr uid timeout inode\n")
                    for inode in tcp:      # real /proc/net/tcp layout: inode is the 10th column
                        f.write(f"   0: 0100007F:1F90 0100007F:115C 01 00000000:00000000 00:00000000 00000000  1000        0 {inode} 1\n")
                if exe: os.symlink(exe, f"{root}/{pid}/exe")
            proc(10, "python3", 1, 100, stdio="socket:[777]", tcp=("777",))          # python reverse shell: socket on stdio
            proc(11, "sh", 10, 110, stdio="socket:[777]", tcp=("777",))
            proc(12, "bash", 10, 120)                                              # pty.spawn child: pty stdio, parent on socket
            proc(13, "bash", 1, 130, stdio="socket:[888]")                         # sshd socketpair: AF_UNIX, not TCP
            proc(14, "kworker", 1, 140, exe=f"{tools}/kworker")
            proc(15, "nc", 1, 150, exe=f"{tools}/nc.openbsd")
            def ev(kind, pid, start, path=None, process=None):
                return {"kind": kind, "pid": pid, "start_ns": start * 10_000_000,
                        "target": {"path": path} if path else {"address": "127.0.0.1", "port": 8080}, "process": process}
            f = lambda e: facts(e, proc_root=root, tools=catalog, hz=100)
            self.assertEqual(f(ev("process_exec", 11, 110, "/bin/sh")), {"stdio_tcp": "self"})
            self.assertEqual(f(ev("process_exec", 12, 120, "/bin/bash")), {"stdio_tcp": "parent"})
            self.assertEqual(f(ev("process_exec", 13, 130, "/bin/bash")), {})                       # no FP for SSH sessions
            self.assertEqual(f(ev("process_exec", 11, 999, "/bin/sh")), {})                         # recycled PID: no facts
            self.assertEqual(f(ev("network_connect", 14, 140, process="kworker"))["tool_identity"], "nc")
            self.assertEqual(f(ev("network_connect", 15, 150, process="nc")), {})                    # the real nc is not masquerading
        def norm(kind, payload):
            return normalize({"event_type": kind, "payload": {"uid": 1000, "pid": 9, "process": "x", **payload}}, "h", "b", source="simulated")
        shell = norm("process_exec", {"filename": "/bin/sh"}); shell["facts"] = {"stdio_tcp": "self"}
        self.assertEqual((detect(shell)["rule"], detect(shell)["severity"]), ("remote_shell_socket_stdio", "critical"))
        renamed = norm("network_connect", {"dest_ip": "127.0.0.1", "dest_port": 8080, "protocol": 6}); renamed["facts"] = {"tool_identity": "nc"}
        self.assertEqual(detect(renamed)["rule"], "masqueraded_tool_connection")
        for path, flags in (("/home/u/.ssh/authorized_keys", 0o2101), (".bashrc", 0o1101), ("/etc/cron.d/x", 0o101),
                            ("/home/u/.config/systemd/user/evil.service", 0o101)):
            self.assertEqual(detect(norm("file_open", {"filename": path, "flags": flags}))["rule"], "persistence_write_attempt", path)
            self.assertTrue(admit({"event_type": "file_open", "payload": {"filename": path, "flags": flags, "uid": 1000}}), path)
        self.assertIsNone(detect(norm("file_open", {"filename": "/home/u/.bashrc", "flags": 0})))              # reading .bashrc
        self.assertFalse(admit({"event_type": "file_open", "payload": {"filename": "/home/u/.bashrc", "flags": 0, "uid": 1000}}))
        root_upgrade = normalize({"event_type": "file_open", "payload": {"uid": 0, "pid": 9, "filename": "/etc/systemd/system/x.service",
                                                                          "flags": 0o101}}, "h", "b", source="simulated")
        self.assertIsNone(detect(root_upgrade))                                                                # package upgrades
        v6 = norm("network_connect", {"dest_ip": "::1", "dest_port": 4444, "family": 10, "protocol": 6})
        self.assertEqual(detect(v6)["rule"], "unusual_connection_attempt")
        self.assertTrue(admit({"event_type": "network_connect", "payload": {"family": 10, "dest_port": 4444}}))
        mapped = norm("network_connect", {"dest_ip": "::ffff:203.0.113.9", "dest_port": 443, "family": 10, "process": "bash"})
        self.assertEqual(mapped["target"]["address"], "203.0.113.9")                                         # v4-mapped -> IPv4

    def test_lineage_walks_procfs_and_binds_first_hop_by_start_time(self):
        from security.lineage import lineage
        from operations.explain import explain_incident
        with tempfile.TemporaryDirectory() as root:
            def proc(pid, comm, ppid, start, uid):
                os.makedirs(f"{root}/{pid}")
                fields = ["S", str(ppid)] + ["0"] * 17 + [str(start)] + ["0"] * 10
                with open(f"{root}/{pid}/stat", "w") as f: f.write(f"{pid} ({comm}) " + " ".join(fields))
                with open(f"{root}/{pid}/status", "w") as f: f.write(f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
            proc(1, "systemd", 0, 1, 0); proc(50, "sshd", 1, 100, 0); proc(70, "bash", 50, 500, 1000)
            proc(90, "nc (evil) x", 70, 900, 1000)
            found = lineage({"pid": 90, "start_ns": 900 * 10_000_000}, proc_root=root, hz=100)
            self.assertEqual(found["identity"], "verified")
            self.assertEqual([h["comm"] for h in found["chain"]], ["nc (evil) x", "bash", "sshd", "systemd"])
            self.assertEqual(found["chain"][0]["uid"], 1000)
            recycled = lineage({"pid": 90, "start_ns": 5_000_000_000}, proc_root=root, hz=100)
            self.assertEqual(recycled["identity"], "unverified")
            self.assertEqual(lineage({"pid": 4242, "start_ns": 1}, proc_root=root, hz=100)["identity"], "exited")
            incident = {"rule": "shell_network_connection", "severity": "warning", "lineage": found,
                        "evidence": {"uid": 1000, "process": "nc", "target": {"address": "203.0.113.9", "port": 443}}}
            self.assertIn("nc (evil) x <- bash <- sshd <- systemd", " ".join(explain_incident(incident)))

    def test_monitor_attaches_lineage_and_survives_lineage_failure(self):
        calls = []
        def boom(event):
            calls.append(event["pid"]); raise OSError("gone")
        monitor = Monitor(self.store, Source(self.buffer), lineage=boom)
        event = self.buffer.publish(record())
        monitor.tick()
        incident = self.store.get("incident", event["id"])
        self.assertEqual(incident["lineage"], {"identity": "unavailable", "chain": []})
        self.assertEqual(calls, [123])
        # Untrusted (simulated) sources get no procfs lineage by default.
        self.assertIsNone(Monitor(self.store, Source(self.buffer)).lineage)

    def test_stable_subject_includes_host_boot_uid_pid_and_start(self):
        one = normalize(record(), "host", "boot", source="kernel")
        two = record()
        two["payload"]["start_ns"] += 1
        self.assertNotEqual(one["subject"], normalize(two, "host", "boot", source="kernel")["subject"])
        self.assertNotEqual(one["subject"], normalize(record(), "host", "other-boot", source="kernel")["subject"])
        incomplete = record()
        incomplete["payload"].pop("start_ns")
        event = normalize(incomplete, "host", "boot", source="kernel")
        self.assertIsNone(event["subject"])
        self.assertEqual(event["identity_quality"], "incomplete_or_simulated")

    def test_bounded_buffer_reports_loss_and_restart(self):
        for _ in range(5): self.buffer.publish(record())
        batch = self.buffer.poll(0, self.buffer.epoch)
        self.assertEqual(batch["gap"], 3)
        self.assertEqual(batch["health"]["buffer_evicted"], 3)
        self.assertEqual(len(batch["events"]), 2)
        self.monitor.tick()
        self.assertEqual(self.monitor.status["gaps"], 3)
        restarted = Buffer("host", "boot")
        self.assertTrue(restarted.poll(100, self.buffer.epoch)["reset"])

    def test_malformed_event_and_unavailable_source_are_explicit(self):
        for value in (record(uid=True), record(pid=0), record(path="\x00bad")):
            with self.assertRaises(ValueError): self.buffer.publish(value)
        self.assertEqual(self.buffer.status["invalid"], 3)
        with patch.object(self.monitor.source, "poll", side_effect=OSError("sensor absent")):
            self.assertEqual(self.monitor.tick()["state"], "unavailable")

    def test_detection_runs_while_model_is_blocked_and_ui_absent(self):
        entered, release = threading.Event(), threading.Event()
        def model(): entered.set(); release.wait(timeout=2)
        thread = threading.Thread(target=model)
        thread.start()
        entered.wait(timeout=1)
        try:
            self.buffer.publish(record())
            self.monitor.tick()
            self.assertEqual(self.monitor.status["incidents"], 1)
            self.assertTrue(thread.is_alive())
        finally:
            release.set()
            thread.join(timeout=2)

    def test_missing_bcc_marks_capture_unavailable_without_loading(self):
        with patch.dict("sys.modules", {"ebpf.daemon": None}):
            capture(self.buffer, threading.Event())
        self.assertEqual(self.buffer.status["state"], "unavailable")

    # Target run 2026-11-08: the idle VM produced ~140 events/s; the pipeline
    # handled ~75/s and dropped the rest. These pin the corrections.

    def test_admit_drops_unwatched_opens_and_non_ipv4_connects_only(self):
        connect = lambda **p: {"event_type": "network_connect", "payload": {"dest_ip": "0.0.0.0", "dest_port": 0, **p}}
        self.assertTrue(admit(record("/etc/shadow")))
        self.assertTrue(admit(record("/etc/sudoers")))
        self.assertFalse(admit(record("/usr/lib/x86_64-linux-gnu/libc.so.6")))
        self.assertFalse(admit(record("/etc/shadow.backup")))
        self.assertFalse(admit(connect(family=1)))                       # AF_UNIX
        self.assertTrue(admit(connect(family=10, dest_ip="2001:db8::1", dest_port=443)))   # IPv6 detected since 13 Nov 2026
        self.assertFalse(admit(connect(family=10, dest_port=0)))         # IPv6 without a real port stays noise
        self.assertTrue(admit(connect(family=2, dest_ip="10.0.2.2", dest_port=4444)))
        self.assertTrue(admit({"event_type": "process_exec", "payload": {"filename": "/usr/bin/true"}}))
        self.assertTrue(admit({"event_type": "file_open", "payload": None}))  # malformed reaches normalize as invalid

    def test_publish_many_persists_whole_batch_in_one_transaction(self):
        store = MemoryStore()
        buffer = Buffer("host", "boot", store, capacity=2048, source="kernel")
        records = [record(pid=1000 + n) for n in range(200)] + [record(pid=0)]
        events = buffer.publish_many(records)
        self.assertEqual(len(events), 200)
        self.assertEqual(store.batches, 1)
        self.assertEqual(buffer.status["invalid"], 1)
        self.assertEqual(len([k for k in store.rows if k[0] == "event"]), 200)

    def test_store_failure_still_delivers_events_and_reports_loss(self):
        store = MemoryStore()
        store.write_batch = lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
        buffer = Buffer("host", "boot", store, capacity=64, source="kernel")
        buffer.status["state"] = "ready"
        buffer.publish_many([record()])
        batch = buffer.poll(0, buffer.epoch)
        self.assertEqual(len(batch["events"]), 1)
        self.assertEqual(batch["health"]["store_errors"], 1)
        self.assertEqual(batch["health"]["state"], "degraded")

    def test_health_recovers_after_loss_window_and_staleness_clear(self):
        now = [100.0]
        buffer = Buffer("host", "boot", capacity=64, source="kernel", clock=lambda: now[0])
        buffer.status.update(state="ready", last_poll=100.0)
        self.assertEqual(buffer.poll(0, None)["health"]["state"], "ready")
        buffer.loss("queue_dropped", 5)
        self.assertEqual(buffer.poll(0, None)["health"]["state"], "degraded")
        now[0] = 104.0                                   # capture loop stalled > 3 s
        health = buffer.poll(0, None)["health"]
        self.assertTrue(health["capture_stale"])
        self.assertEqual(health["state"], "degraded")
        now[0], buffer.status["last_poll"] = 111.0, 111.0  # loop running again, loss older than window
        health = buffer.poll(0, None)["health"]
        self.assertEqual(health["state"], "ready")
        self.assertEqual(health["queue_dropped"], 5)       # cumulative counters are preserved
        buffer.status["state"] = "unavailable"
        self.assertEqual(buffer.poll(0, None)["health"]["state"], "unavailable")

    def test_monitor_drains_backlog_with_one_transaction_per_batch(self):
        buffer, store = Buffer("host", "boot", capacity=2048), MemoryStore()
        monitor = Monitor(store, Source(buffer))
        buffer.publish_many([record("/etc/shadow", pid=1 + n) for n in range(100)])
        monitor.drain()
        self.assertEqual(monitor.status["events"], 100)
        self.assertEqual(monitor.status["incidents"], 100)
        self.assertEqual(monitor.status["cursor"], buffer.sequence)
        self.assertEqual(store.batches, 4)                 # 32+32+32+4, not one write per event
        self.assertEqual(store.get("monitor", "status")["cursor"], buffer.sequence)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "getuid"), "real private Store requires Linux ownership checks")
    def test_real_store_write_batch_is_atomic_and_applies_retention(self):
        from operations.store import Store
        # Store refuses world-writable parents such as /tmp; use a private home dir.
        with tempfile.TemporaryDirectory(prefix=".linxai-store-batch-", dir=os.path.expanduser("~")) as temp:
            os.chmod(temp, 0o700)
            store = Store(os.path.join(temp, "state", "events.sqlite"))
            try:
                store.write_batch([("event", f"e{n}", {"n": n}, False, 5) for n in range(5)])
                store.write_batch([("event", "e5", {"n": 5}, False, 5)], prune={"event": 4})
                self.assertEqual(len(store.list("event", 100)), 5)
                with self.assertRaises(ValueError):            # second row exceeds admission limit
                    store.write_batch([("event", "e6", {"n": 6}, False, 6), ("event", "e7", {"n": 7}, False, 6)])
                self.assertIsNone(store.get("event", "e6"))     # whole batch rolled back
                with self.assertRaises(sqlite3.IntegrityError):  # duplicate key without replace
                    store.write_batch([("incident", "i1", {}, False, 9), ("event", "e5", {}, False, 9)])
                self.assertIsNone(store.get("incident", "i1"))
            finally:
                store.close()

    def test_monitor_does_not_advance_cursor_when_batch_write_fails(self):
        buffer, store = Buffer("host", "boot", capacity=64), MemoryStore()
        monitor = Monitor(store, Source(buffer))
        buffer.publish(record())
        original = store.write_batch
        store.write_batch = lambda *a, **k: (_ for _ in ()).throw(OSError("locked"))
        self.assertEqual(monitor.tick()["state"], "unavailable")
        self.assertEqual(monitor.status["cursor"], 0)
        store.write_batch = original
        monitor.tick()
        self.assertEqual(monitor.status["incidents"], 1)
        self.assertNotIn("error", monitor.status)
