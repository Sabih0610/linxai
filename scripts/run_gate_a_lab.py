"""Isolated native Linux installation/launcher lab. Never provisions host features.

Exit 3 means incomplete evidence (skipped Linux checks), 1 means failure.
Requires a native Linux checkout, safe home, ordinary user and cached/online PyPI.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--check-root-rejection", action="store_true", help="Explicit lab opt-in: sudo -n only to prove the installed launcher rejects root")
    args = parser.parse_args(argv)
    from scripts.install_app import ordinary_user, safe_chain
    from tests.test_linux_integration import LinuxIntegrationTests
    ordinary_user()
    safe_chain(Path.home())
    report = {"schema": 1, "kind": "native Linux application installation; no kernel/hardware acceptance",
              "uid": os.getuid(), "install": "pending", "uninstall": "pending", "root_rejection": "pending; run explicit lab check",
              "operations_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT / "operations").glob("*.py"))}}
    try:
        with tempfile.TemporaryDirectory(prefix=".linxai-gate-a-", dir=Path.home()) as temp:
            prefix = Path(temp) / "app with spaces"
            command = [sys.executable, "-I", str(ROOT / "scripts/install_app.py"), "--prefix", str(prefix)]
            if args.offline:
                command.append("--offline")
            subprocess.run(command, check=True, timeout=660)
            report["install"] = json.loads((prefix / ".linxai-install.json").read_text())
            if args.check_root_rejection:
                root_check = subprocess.run(["/usr/bin/sudo", "-n", "--", str(prefix / "bin/linxai"), "memory.usage"],
                                            capture_output=True, text=True, timeout=10)
                if root_check.returncode != 2 or "ordinary user" not in root_check.stderr:
                    raise RuntimeError(f"Root rejection not demonstrated: exit={root_check.returncode} {root_check.stderr}")
                report["root_rejection"] = "passed; root refused before Python import"
            # Same tests as the direct backend group, now all requests use installed CLI.
            class InstalledTests(LinuxIntegrationTests):
                def run_action(self, action, params=None):
                    result = subprocess.run([str(prefix / "bin/linxai"), action, "--parameters", json.dumps(params or {}),
                                             "--workspace", str(self.service.registry.permitted_workspace), "--audit-path", str(self.ledger)],
                                            shell=False, capture_output=True, text=True, cwd=temp, timeout=20)
                    data = json.loads(result.stdout)
                    self.assertEqual(result.returncode, 0 if data["status"] == "succeeded" else 2, result.stderr)
                    from types import SimpleNamespace
                    return SimpleNamespace(**data)

                def test_installed_console_launcher_as_ordinary_user(self):
                    result = subprocess.run([str(prefix / "bin/linxai-ops"), "--help"],
                                            shell=False, capture_output=True, text=True, cwd=temp, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("--parameters", result.stdout)

            suite = unittest.defaultTestLoader.loadTestsFromTestCase(InstalledTests)
            result = unittest.TextTestRunner(verbosity=2).run(suite)
            report.update(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                          skipped=[{"test": str(test), "reason": reason} for test, reason in result.skipped])
            # Explicit managed removal; application audit fixtures are separate and retained
            # until TemporaryDirectory cleans up this lab's own disposable test files.
            subprocess.run([sys.executable, "-I", str(ROOT / "scripts/install_app.py"), "--prefix", str(prefix), "--uninstall"],
                           check=True, timeout=30)
            report["uninstall"] = "passed" if not prefix.exists() else "failed"
        incomplete = bool(result.skipped) or not report["root_rejection"].startswith("passed")
        report["status"] = "FAILED" if not result.wasSuccessful() else "PARTIAL" if incomplete else "APPLICATION LAB PASS"
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        return 1 if not result.wasSuccessful() else 3 if incomplete else 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        report.update(status="FAILED", error=str(exc))
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(f"Gate A lab failed: {exc}", file=sys.stderr)
        return 1



if __name__ == "__main__":
    raise SystemExit(main())
