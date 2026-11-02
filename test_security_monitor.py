"""Deterministic evidence/incident contracts; no BPF or service installation."""
import copy
import threading
import unittest
from unittest.mock import patch

from security.events import detect, normalize
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
