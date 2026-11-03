"""Ordinary-user native process/storage contracts; no service or kernel mutation."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

from operations.store import Store
from operations.supervised import SupervisedLinuxAdapter


@unittest.skipUnless(sys.platform == "linux", "native Linux required")
class NativeRuntimeTests(unittest.TestCase):
    def setUp(self):
        if os.getuid() == 0:
            self.skipTest("ordinary Linux account required")
        self.system = SupervisedLinuxAdapter()
        self.temp = self.enterContext(tempfile.TemporaryDirectory(prefix=".linxai-runtime-", dir=Path.home()))

    def test_supervised_exact_argv_and_literal_stdin(self):
        argv = ("/usr/bin/python3", "-I", "-c", "import sys; print(sys.argv[1]); print(sys.stdin.read())", "a ; $(literal)")
        result = self.system._run("literal", argv, b"hello 'content'", 3)
        self.assertEqual(result.returncode, 0, result)
        self.assertFalse(result.error)
        self.assertIn("a ; $(literal)\nhello 'content'", result.stdout)

    def test_output_and_time_budgets(self):
        result = self.system._run("noisy", ("/usr/bin/python3", "-I", "-c", "print('x'*2000000)"), b"", 3)
        self.assertIn("Output limit", result.error)
        self.assertLessEqual(len(result.stdout), self.system.OUTPUT_LIMIT)
        result = self.system._run("slow", ("/usr/bin/python3", "-I", "-c", "import time;time.sleep(10)"), b"", 0.2)
        self.assertIn("deadline", result.error)
        self.assertTrue(result.started)

    def test_private_sqlite_persistence_duplicate_and_size_bounds(self):
        path = Path(self.temp) / "jobs.sqlite"
        store = Store(path)
        store.put("jobs", "first", {"state": "queued"}, replace=False)
        with self.assertRaises(Exception):
            store.put("jobs", "first", {"state": "other"}, replace=False)
        with self.assertRaises(ValueError):
            store.put("jobs", "huge", {"data": "x" * 200000})
        store.close()
        store = Store(path)
        self.assertEqual(store.get("jobs", "first")["state"], "queued")
        store.close()
        link = Path(self.temp) / "link.sqlite"
        link.symlink_to(path)
        with self.assertRaises(OSError): Store(link)

    def test_audit_rotation_is_bounded_and_shared_across_writers(self):
        import concurrent.futures
        import json
        from operations.audit import JsonlAudit
        path=Path(self.temp)/"audit.jsonl"
        writers=[JsonlAudit(path),JsonlAudit(path)]
        for writer in writers:writer.MAX_BYTES=1024
        def write(index):writers[index%2].append({"operation_id":str(index),"data":"x"*300})
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(write,range(40)))
        retained=[path]+[path.with_name(path.name+f".{i}") for i in range(1,4)]
        ids=[]
        for item in retained:
            self.assertLessEqual(item.stat().st_size,1024)
            ids.extend(json.loads(line)["operation_id"] for line in item.read_text().splitlines())
        self.assertEqual(len(ids),len(set(ids)))
        self.assertIn("39",ids)
        self.assertEqual(len(list(Path(self.temp).glob("audit.jsonl*"))),5)

    def test_audit_unsafe_archive_and_oversize_record_fail_before_append(self):
        from operations.audit import JsonlAudit
        path=Path(self.temp)/"audit.jsonl";writer=JsonlAudit(path)
        writer.append({"operation_id":"first"});original=path.read_bytes()
        outside=Path(self.temp)/"outside";outside.write_text("keep")
        path.with_name(path.name+".1").symlink_to(outside)
        with self.assertRaises(PermissionError):writer.append({"operation_id":"second"})
        self.assertEqual(path.read_bytes(),original);self.assertEqual(outside.read_text(),"keep")
        with self.assertRaises(ValueError):writer.append({"data":"x"*65536})
