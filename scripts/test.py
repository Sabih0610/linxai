"""Explicit safe test groups; never discover archived attack/install scenarios."""
import argparse
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
GROUPS = {
    "offline": ["test_safety_regressions", "test_action_registry", "test_operations_service", "test_dev_environment", "test_gate_a", "test_broker", "test_application", "test_security_monitor", "test_security_warnings", "test_resources", "test_lake", "test_followups", "test_explain", "test_conflicts", "test_workflow_graph", "test_iot", "test_netconf_features", "test_response_policy", "test_local_http", "test_workflows", "test_auth_voice", "test_candidate"],
    "linux": ["tests.test_linux_integration", "tests.test_native_runtime", "tests.test_native_agent", "tests.test_native_workflows"],
    "privileged": ["tests.test_opt_in.PrivilegedTests"],
    "desktop": ["tests.test_opt_in.DesktopTests", "tests.test_desktop"],
    "hardware": ["tests.test_opt_in.HardwareTests"],
    "model": ["tests.test_opt_in.RealModelTests"],
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("group", choices=[*GROUPS, "all"], nargs="?", default="offline")
    args = parser.parse_args(argv)
    modules = [m for group in GROUPS.values() for m in group] if args.group == "all" else GROUPS[args.group]
    suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(f"SUMMARY group={args.group} run={result.testsRun} skipped={len(result.skipped)} failures={len(result.failures)} errors={len(result.errors)}")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
