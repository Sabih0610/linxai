"""Fast setup contract regressions; package/network/host operations mocked."""
import importlib.util
import io
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).parent


def load_script(name):
    spec = importlib.util.spec_from_file_location("linxai_dev_" + name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DevelopmentEnvironmentTests(unittest.TestCase):
    def test_default_setup_only_syncs_locked_app_and_prints_help(self):
        setup = load_script("setup_dev")
        with tempfile.TemporaryDirectory() as temp, patch.object(setup.shutil, "which", return_value="uv"), patch.object(setup.subprocess, "check_output", return_value="uv 0.13.3\n"), patch.object(setup.subprocess, "run") as run, patch("sys.stdout", io.StringIO()):
            self.assertEqual(setup.main(["--venv", str(Path(temp) / "app")]), 0)
            calls = run.call_args_list
            self.assertEqual(len(calls), 2)
            self.assertIn("--locked", calls[0].args[0])
            self.assertIn("test", calls[0].args[0])
            self.assertNotIn("--extra", calls[0].args[0])
            self.assertEqual(calls[1].args[0][-3:], ["-m", "operations.cli", "--help"])
            self.assertNotIn("ollama", str(calls))
            self.assertNotIn("apt-get", str(calls))
            self.assertEqual(calls[0].kwargs["env"]["UV_PYTHON_DOWNLOADS"], "never")

    def test_offline_and_explicit_extra_forwarded(self):
        setup = load_script("setup_dev")
        with tempfile.TemporaryDirectory() as temp, patch.object(setup.shutil, "which", return_value="uv"), patch.object(setup.subprocess, "check_output", return_value="uv 0.13.3\n"), patch.object(setup.subprocess, "run") as run, patch("sys.stdout", io.StringIO()):
            setup.main(["--venv", str(Path(temp) / "app"), "--offline", "--extra", "ai"])
            self.assertIn("--offline", run.call_args_list[0].args[0])
            self.assertIn("ai", run.call_args_list[0].args[0])

    def test_wrong_uv_version_and_source_as_environment_rejected(self):
        setup = load_script("setup_dev")
        with tempfile.TemporaryDirectory() as temp, patch.object(setup.shutil, "which", return_value="uv"), patch.object(setup.subprocess, "check_output", return_value="uv 0.1.0\n"), patch.object(setup.venv, "EnvBuilder"), patch.object(setup.subprocess, "run", return_value=Mock(returncode=1, stdout="")), patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                setup.main(["--venv", str(Path(temp) / "app")])
            with self.assertRaises(SystemExit):
                setup.main(["--venv", str(ROOT)])

    def test_manifest_separates_optional_features_and_uses_no_pypi_bcc(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text())
        extras = data["project"]["optional-dependencies"]
        self.assertTrue({"ai", "desktop", "sensor", "hardware", "voice", "remote"} <= set(extras))
        self.assertEqual(extras["sensor"], [])
        self.assertTrue(all("==" in entry for entry in data["project"]["dependencies"]))
        self.assertEqual(data["project"]["scripts"]["linxai"], "operations.cli:main")
        self.assertEqual(data["dependency-groups"]["test"], [])

    def test_lock_contains_pinned_application_and_optional_dependencies(self):
        data = tomllib.loads((ROOT / "uv.lock").read_text())
        names = {p["name"] for p in data["package"]}
        self.assertTrue({"linxai", "requests", "pyside6", "opencv-contrib-python", "pyyaml", "psutil"} <= names)
        self.assertNotIn("bcc", names)

    def test_test_runner_uses_explicit_groups_not_repository_wide_discovery(self):
        runner = load_script("test")
        self.assertTrue({"offline", "linux", "privileged", "desktop", "hardware", "model"} <= set(runner.GROUPS))
        names = str(runner.GROUPS)
        self.assertNotIn("attack_simulation", names)
        self.assertNotIn("install", names)

    def test_capability_report_does_not_infer_kernel_control(self):
        script = load_script("capabilities")
        self.assertIn("root/capabilities/config flags do not prove", (ROOT / "scripts/capabilities.py").read_text())
        result = script.kernel_flags()
        self.assertIsInstance(result, dict)
