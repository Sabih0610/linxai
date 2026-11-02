"""Installer/launcher and unavailable-system regressions; no host mutations."""
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_dev_environment import load_script
from operations import ActionRegistry
from operations.service import Identity, LocalPolicy, OperationService
from operations.system import LinuxSystemAdapter


class MemoryAudit:
    def __init__(self):
        self.records = []

    def append(self, record):
        self.records.append(record)


class GateAOfflineTests(unittest.TestCase):
    def test_installer_refuses_root_and_setid_before_install(self):
        installer = load_script("install_app")
        for uid, euid, gid, egid in ((0, 0, 0, 0), (1000, 0, 1000, 1000), (1000, 1000, 1000, 0)):
            with self.subTest(ids=(uid, euid, gid, egid)), patch.object(installer.sys, "platform", "linux"), patch.object(installer.os, "getuid", return_value=uid, create=True), patch.object(installer.os, "geteuid", return_value=euid, create=True), patch.object(installer.os, "getgid", return_value=gid, create=True), patch.object(installer.os, "getegid", return_value=egid, create=True), patch.object(installer, "install") as install, patch("sys.stderr", io.StringIO()):
                self.assertEqual(installer.main([]), 2)
                install.assert_not_called()

    def test_existing_prefix_preserved_even_if_empty(self):
        installer = load_script("install_app")
        with tempfile.TemporaryDirectory() as temp, patch.object(installer, "safe_chain"), patch.object(installer.subprocess, "run") as run:
            prefix = Path(temp) / "unrelated"
            prefix.mkdir()
            keep = prefix / "keep.txt"
            keep.write_text("keep")
            with self.assertRaises(FileExistsError):
                installer.install(prefix)
            run.assert_not_called()
            self.assertEqual(keep.read_text(), "keep")

    def test_locked_noneditable_setup_verifies_isolated_import(self):
        setup = load_script("setup_dev")
        with tempfile.TemporaryDirectory() as temp, patch.object(setup.shutil, "which", return_value="uv"), patch.object(setup.subprocess, "check_output", return_value="uv 0.13.3\n"), patch.object(setup.subprocess, "run") as run, patch("sys.stdout", io.StringIO()):
            setup.main(["--venv", str(Path(temp) / "app"), "--no-editable"])
            self.assertIn("--locked", run.call_args_list[0].args[0])
            self.assertIn("--no-editable", run.call_args_list[0].args[0])
            self.assertIn("-I", run.call_args_list[1].args[0])

    def test_missing_tool_fails_validation_without_dispatch(self):
        adapter = LinuxSystemAdapter()
        identity = Identity(1000, 1000, "owner")
        with patch("operations.system.sys.platform", "linux"), patch.object(adapter, "resolve_identity", return_value=identity), patch.object(adapter, "_trusted_executable", side_effect=FileNotFoundError("required /usr/bin/df unavailable")), patch.object(adapter, "execute") as execute:
            audit = MemoryAudit()
            service = OperationService(ActionRegistry(), adapter, LocalPolicy(1000), audit)
            result = service.run({"action": "disk.usage", "parameters": {}})
            self.assertEqual(result.status, "validation_failed", result)
            self.assertFalse(result.executed)
            self.assertIn("trusted_executable", result.reason)
            self.assertTrue(any("/usr/bin/df unavailable" in r.get("details", {}).get("reason", "") for r in audit.records))
            execute.assert_not_called()

    def test_missing_service_fails_validation_without_dispatch(self):
        adapter = LinuxSystemAdapter()
        identity = Identity(1000, 1000, "owner")
        with patch("operations.system.sys.platform", "linux"), patch.object(adapter, "resolve_identity", return_value=identity), patch.object(adapter, "_trusted_executable", return_value="trusted"), patch.object(adapter, "_service_properties", return_value={"Id": "absent.service", "LoadState": "not-found"}), patch("operations.system.Path.is_dir", return_value=True), patch.object(adapter, "execute") as execute:
            result = OperationService(ActionRegistry(), adapter, LocalPolicy(1000), MemoryAudit()).run({"action": "service.status", "parameters": {"service": "absent"}})
            self.assertEqual(result.status, "validation_failed", result)
            self.assertFalse(result.executed)
            self.assertIn("service_exists", result.reason)
            execute.assert_not_called()

    def test_root_console_entry_refused_before_ledger_creation(self):
        from operations import cli
        with patch.object(cli.LinuxSystemAdapter, "resolve_identity", return_value=Identity(0, 0, "root")), patch.object(cli, "build_service") as build, patch("sys.stdout", io.StringIO()) as output:
            self.assertEqual(cli.main(["memory.usage"]), 2)
            build.assert_not_called()
            self.assertEqual(json.loads(output.getvalue())["status"], "identity_denied")

    @unittest.skipUnless(os.name == "posix", "native POSIX ownership/modes required")
    def test_managed_uninstall_refuses_unrelated_entries_and_altered_receipt(self):
        installer = load_script("install_app")
        with tempfile.TemporaryDirectory() as temp, patch.object(installer, "safe_chain"):
            prefix = Path(temp) / "app"
            prefix.mkdir(mode=0o700)
            receipt = prefix / installer.RECEIPT
            receipt.write_text(json.dumps({"schema": 1, "prefix": str(prefix), "uid": os.getuid()}))
            keep = prefix / "unrelated.txt"
            keep.write_text("keep")
            with self.assertRaisesRegex(ValueError, "Unrelated"):
                installer.uninstall(prefix)
            self.assertEqual(keep.read_text(), "keep")
            keep.unlink()
            receipt.write_text(json.dumps({"schema": 1, "prefix": "/wrong", "uid": os.getuid()}))
            with self.assertRaisesRegex(ValueError, "does not match"):
                installer.uninstall(prefix)
            receipt.unlink()
            receipt.symlink_to(Path(temp) / "outside")
            with self.assertRaisesRegex(ValueError, "Unsafe installation receipt"):
                installer.uninstall(prefix)

    @unittest.skipUnless(os.name == "posix", "shell argument forwarding requires POSIX")
    def test_launcher_forwards_exact_arguments_without_interpolation(self):
        if os.getuid() == 0:
            self.skipTest("launcher deliberately rejects root")
        installer = load_script("install_app")
        with tempfile.TemporaryDirectory(prefix="linxai argv ") as temp:
            # A deterministic executable stand-in reports argv; no app/service mutation.
            fake = Path(temp) / "python with spaces"
            fake.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
            fake.chmod(0o700)
            wrapper = Path(temp) / "linxai"
            wrapper.write_text(installer.launcher(fake))
            wrapper.chmod(0o700)
            args = ["file.create", "--parameters", json.dumps({"path": "a b.txt", "content": "$(touch NEVER); 'quoted'\nline"})]
            result = subprocess.run([str(wrapper), *args], shell=False, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "\n".join(["-I", "-B", "-m", "operations.cli", *args]) + "\n")

    def test_capability_probe_separates_presence_from_acceptance(self):
        probe = load_script("capabilities")
        data = probe.integration_capabilities()
        self.assertEqual(data["os_authentication"]["authorization"], "NOT TESTED; no broker installed by this probe")
        self.assertEqual(data["microphone"]["capture"], "NOT TESTED; devices are not opened")


if __name__ == "__main__":
    unittest.main()
