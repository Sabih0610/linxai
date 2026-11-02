"""Native ordinary-user smoke tests; no service mutations, models or kernel hooks."""
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from operations import ActionRegistry
from operations.registry import normalize_service
from operations.audit import JsonlAudit
from operations.service import LocalPolicy, OperationService
from operations.system import LinuxSystemAdapter


@unittest.skipUnless(sys.platform == "linux", "native Linux required")
class LinuxIntegrationTests(unittest.TestCase):
    def setUp(self):
        if os.getuid() == 0 or os.geteuid() != os.getuid():
            self.skipTest("requires an existing ordinary user; do not weaken root rejection")
        self.adapter = LinuxSystemAdapter()
        self.identity = self.adapter.resolve_identity()
        try:
            self.adapter._directories(Path.home(), self.identity.uid)
        except OSError as exc:
            self.skipTest(f"safe native home directory unavailable: {exc}")
        # Shared /tmp is deliberately unsuitable for the production confinement policy.
        self.temp = self.enterContext(tempfile.TemporaryDirectory(prefix=".linxai-integration-", dir=Path.home()))
        self.workspace = Path(self.temp) / "workspace"
        self.workspace.mkdir(mode=0o700)
        ledger_dir = Path(self.temp) / "audit"
        ledger_dir.mkdir(mode=0o700)
        self.ledger = ledger_dir / "operations.jsonl"
        self.service = OperationService(ActionRegistry(str(self.workspace)), self.adapter,
                                        LocalPolicy(self.identity.uid), JsonlAudit(self.ledger))

    def run_action(self, action, params=None):
        return self.service.run({"action": action, "parameters": params or {}})

    def require_binary(self, name):
        if not Path(f"/usr/bin/{name}").exists():
            self.skipTest(f"required /usr/bin/{name} unavailable; no package installation in tests")

    def test_disk_usage(self):
        self.require_binary("df")
        result = self.run_action("disk.usage")
        self.assertEqual(result.status, "succeeded", result)

    def test_memory_usage(self):
        self.require_binary("free")
        result = self.run_action("memory.usage")
        self.assertEqual(result.status, "succeeded", result)

    def test_installed_console_launcher_as_ordinary_user(self):
        entry = Path(sys.executable).parent / "linxai"
        self.assertTrue(entry.is_file(), "Run locked setup before integration; installed console launcher missing")
        result = subprocess.run([str(entry), "memory.usage", "--audit-path", str(self.ledger)],
                                shell=False, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        observed = json.loads(result.stdout)
        self.assertEqual(observed["status"], "succeeded")
        self.assertTrue(observed["executed"] and observed["verified"])

    def test_listening_ports(self):
        self.require_binary("ss")
        result = self.run_action("ports.listen", {"protocol": "tcp"})
        self.assertEqual(result.status, "succeeded", result)

    def test_service_status_read_only(self):
        if not Path("/run/systemd/system").is_dir():
            self.skipTest("systemd is not running; a systemctl binary alone is insufficient")
        self.require_binary("systemctl")
        service = normalize_service(os.environ.get("LINXAI_TEST_SERVICE", "dbus"))
        available = subprocess.run(["/usr/bin/systemctl", "show", "--property=LoadState", "--value", "--", service],
                                   shell=False, capture_output=True, text=True, timeout=5)
        if available.returncode != 0 or available.stdout.strip() != "loaded":
            self.skipTest(f"read-only fixture unit {service} or its systemd bus is unavailable")
        result = self.run_action("service.status", {"service": service})
        self.assertEqual(result.status, "succeeded", result)

    def test_file_create_content_and_audit_correlation(self):
        self.require_binary("python3")
        result = self.run_action("file.create", {"path": "example.txt", "content": "native integration\n"})
        self.assertEqual(result.status, "succeeded", result)
        self.assertEqual((self.workspace / "example.txt").read_bytes(), b"native integration\n")
        records = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        self.assertEqual({r["operation_id"] for r in records}, {result.operation_id})
        for phase in ("validation", "execution", "verification", "result"):
            selected = [r for r in records if r["phase"] == phase]
            self.assertTrue(selected)
            self.assertEqual({r["fingerprint"] for r in selected}, {result.fingerprint})

    def test_directory_create(self):
        self.require_binary("python3")
        result = self.run_action("directory.create", {"path": "reports"})
        self.assertEqual(result.status, "succeeded", result)
        self.assertTrue((self.workspace / "reports").is_dir())

    def test_traversal_overwrite_and_symlink_rejected(self):
        existing = self.workspace / "keep.txt"
        existing.write_text("keep")
        outside = Path(self.temp) / "outside"
        outside.mkdir(mode=0o700)
        (self.workspace / "link").symlink_to(outside, target_is_directory=True)
        for path in ("../escape", "keep.txt", "link/escape"):
            result = self.run_action("file.create", {"path": path, "content": "replace"})
            self.assertIn(result.status, {"invalid_request", "validation_failed"}, result)
            self.assertFalse(result.executed)
        self.assertEqual(existing.read_text(), "keep")
        self.assertFalse((outside / "escape").exists())

    def test_altered_approval_and_admin_dispatch_are_denied(self):
        approved = self.service.prepare({"action": "file.create", "parameters": {"path": "safe.txt"}})
        changed = replace(approved.operation.prepared, stdin=b"altered")
        result = self.service.execute(replace(approved, operation=replace(approved.operation, prepared=changed)))
        self.assertEqual(result.status, "approval_invalid", result)
        self.assertFalse((self.workspace / "safe.txt").exists())
        result = self.run_action("service.restart", {"service": "dbus"})
        self.assertEqual(result.status, "authentication_authorization_required", result)
        self.assertFalse(result.executed)
