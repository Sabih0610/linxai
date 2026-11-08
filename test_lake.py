"""Medallion pipeline (bronze/silver/gold) and learned advisory baseline."""
import unittest
import unittest.mock

from security import lake as lakemod
from security.events import detect, normalize
from security.lake import Lake, feature_key, score
from security.monitor import Monitor
from security.sensor import Buffer
from test_application import MemoryStore


def event(path="/usr/bin/ls", uid=1000, kind="process_exec", source="kernel", **extra):
    payload = {"uid": uid, "pid": 400, "start_ns": 7, "monotonic_ns": 9, "process": "sh", **extra}
    if kind == "network_connect":
        payload.update(dest_ip=extra.get("dest_ip", "10.0.2.2"), dest_port=extra.get("dest_port", 22), protocol=6)
    else:
        payload["filename"] = path
    return normalize({"event_type": kind, "payload": payload}, "host", "boot", source=source)


class LakeTests(unittest.TestCase):
    def setUp(self):
        self.security, self.store = MemoryStore(), MemoryStore()
        self.lake = Lake(self.store, self.security, clock=lambda: 1000.0)

    def add(self, *events):
        for e in events: self.security.put("event", e["id"], e)

    def test_layers_are_populated_once_with_provenance(self):
        self.add(event(), event("/usr/bin/cat"))
        status = self.lake.run_cycle()
        self.assertEqual(status["last_cycle"]["bronze"], 2)
        self.assertEqual(status["last_cycle"]["silver"], 2)
        bronze = self.store.list("bronze")[0]
        self.assertEqual(len(bronze["sha256"]), 64)
        self.assertEqual(bronze["source"], "monitor.event")
        again = self.lake.run_cycle()
        self.assertEqual((again["last_cycle"]["bronze"], again["last_cycle"]["duplicates"]), (0, 2))
        self.assertEqual(self.lake.model()["trained_events"], 2)

    def test_invalid_rows_are_quarantined_not_trained(self):
        bad = event(); bad["uid"] = True
        self.add(bad, {"id": "x-1", "kind": "unknown"})
        status = self.lake.run_cycle()
        self.assertEqual(status["last_cycle"]["quarantine"], 2)
        self.assertEqual(self.lake.model()["trained_events"], 0)

    def test_simulated_incomplete_and_incident_evidence_are_excluded_from_training(self):
        simulated = event(source="simulated")
        incomplete = event(); incomplete["identity_quality"] = "incomplete_or_simulated"
        suspicious = event("/etc/shadow", kind="file_open")
        self.security.put("incident", suspicious["id"], detect(suspicious))
        self.add(simulated, incomplete, suspicious, event())
        self.lake.run_cycle()
        silver = {row["id"]: row for row in self.store.list("silver")}
        self.assertFalse(silver[simulated["id"]]["eligible"])
        self.assertFalse(silver[incomplete["id"]]["eligible"])
        self.assertTrue(silver[suspicious["id"]]["incident"])
        self.assertEqual(self.lake.model()["trained_events"], 1)

    def test_feature_keys_generalize_volatile_parts(self):
        self.assertEqual(feature_key(event("/tmp/tmp.Ab12/run")), "/tmp/*")
        self.assertEqual(feature_key(event("/usr/bin/ls")), "/usr/bin/ls")
        self.assertEqual(feature_key(event(kind="network_connect", dest_ip="10.0.2.2", dest_port=22)), "tcp/private/22")
        self.assertEqual(feature_key(event(kind="network_connect", dest_ip="8.8.8.8", dest_port=443)), "tcp/public/443")

    def test_baseline_scores_only_unseen_keys_after_enough_training(self):
        self.add(*[event("/usr/bin/ls") for _ in range(lakemod.READY_EVENTS - 1)])
        self.lake.run_cycle()
        self.assertIsNone(score(event("/usr/bin/nc"), self.lake.model()))           # not ready yet
        self.add(event("/usr/bin/ls"))
        self.lake.run_cycle()
        model = self.lake.model()
        anomaly = score(event("/usr/bin/nc"), model)
        self.assertEqual((anomaly["key"], anomaly["severity"]), ("/usr/bin/nc", "info"))
        self.assertGreaterEqual(anomaly["score_bits"], lakemod.ANOMALY_BITS)
        self.assertIsNone(score(event("/usr/bin/ls"), model))                        # known behaviour
        self.assertIsNone(score(event("/usr/bin/nc", uid=2000), model))              # other account: no baseline

    def test_key_and_account_growth_is_bounded(self):
        with unittest.mock.patch.object(lakemod, "MAX_KEYS", 3):
            self.add(*[event(f"/opt/tool{n}") for n in range(10)])
            self.lake.run_cycle()
        self.assertEqual(len(self.lake.model()["counts"]["1000"]["process_exec"]), 3)

    def test_monitor_records_advisory_anomalies_not_incidents(self):
        self.add(*[event("/usr/bin/ls") for _ in range(lakemod.READY_EVENTS)])
        self.lake.run_cycle()
        buffer, store = Buffer("host", "boot", capacity=64, source="kernel"), MemoryStore()
        class Trusted:
            trusted = True
            def poll(self, cursor, epoch): return buffer.poll(cursor, epoch)
        monitor = Monitor(store, Trusted(), baseline=self.lake.model())
        payload = {"uid": 1000, "pid": 401, "start_ns": 8, "monotonic_ns": 10, "process": "sh", "filename": "/usr/bin/nc"}
        buffer.publish({"event_type": "process_exec", "payload": payload})
        monitor.tick()
        self.assertEqual(len(store.list("anomaly")), 1)
        self.assertEqual(store.list("incident"), [])
        self.assertEqual(monitor.status["anomalies"], 1)


class NoveltyTests(unittest.TestCase):
    def test_varied_accounts_raise_fewer_novelty_alerts(self):
        stable = {"counts": {"1": {"process_exec": {"/usr/bin/ls": 300}}}}
        varied = {"counts": {"1": {"process_exec": {f"/opt/t{n}": 1 for n in range(300)}}}}
        probe = event("/usr/bin/nc", uid=1)
        self.assertIsNotNone(score(probe, stable))
        self.assertIsNone(score(probe, varied))


if __name__ == "__main__":
    unittest.main()
