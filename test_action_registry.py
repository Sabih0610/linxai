"""Offline typed-registry contracts: never launch commands or touch live state."""
from dataclasses import FrozenInstanceError
import hashlib
import io
import sys
import types
import unittest
from unittest.mock import MagicMock, Mock, patch

from ai.fast_path import classify_fast
from operations import ACTIONS, ActionRegistry, InvalidParameters, Privilege, UnsupportedAction, adapt_plan
from operations._create_program import CREATE_PROGRAM


class OfflineRegistryTest(unittest.TestCase):
    def setUp(self):
        self.registry = ActionRegistry("/srv/linxai-work")
        for target in ("subprocess.run", "subprocess.Popen", "socket.create_connection",
                       "os.system", "os.open", "os.mkdir"):
            self.enterContext(patch(target, side_effect=AssertionError("Live operation forbidden in registry tests")))

    def names(self, prepared):
        return {check.identifier for check in prepared.mandatory_checks}


class RegistryContractTests(OfflineRegistryTest):
    def test_all_actions_have_bounded_complete_contracts(self):
        requests = {
            "disk.usage": {}, "memory.usage": {}, "ports.listen": {},
            "service.status": {"service": "nginx"},
            "service.start": {"service": "nginx"},
            "service.stop": {"service": "nginx"},
            "service.restart": {"service": "nginx"},
            "file.create": {"path": "notes.txt"},
            "directory.create": {"path": "reports"},
        }
        self.assertEqual(set(requests), set(ACTIONS))
        for identifier, parameters in requests.items():
            with self.subTest(identifier=identifier):
                prepared = self.registry.prepare(identifier, parameters)
                self.assertIsInstance(prepared.parameters, prepared.contract.parameter_type)
                self.assertGreater(prepared.contract.timeout_s, 0)
                self.assertLessEqual(prepared.contract.timeout_s, 30)
                self.assertFalse(prepared.contract.recovery_supported)
                self.assertFalse(prepared.execution_supported)
                self.assertIsInstance(prepared.argv, tuple)
                self.assertTrue(prepared.argv[0].startswith("/usr/bin/"))
                self.assertTrue(all(isinstance(arg, str) for arg in prepared.argv))
                self.assertTrue({"linux_runtime", "trusted_executable"} <= self.names(prepared))
                self.assertGreaterEqual(len(prepared.postconditions), 2)
                self.assertEqual(prepared.postconditions[0].identifier, "exit_code")

    def test_unknown_actions_and_unexpected_parameters_rejected(self):
        for identifier in (None, [], "shell", "service.reload", "package.install"):
            with self.subTest(identifier=identifier), self.assertRaises(UnsupportedAction):
                self.registry.prepare(identifier)
        for parameters in ([], "nginx", {"command": "id"}, {"path": "/"}):
            with self.subTest(parameters=parameters), self.assertRaises(InvalidParameters):
                self.registry.prepare("disk.usage", parameters)

    def test_prepared_data_and_catalog_are_immutable(self):
        original = {"service": "nginx"}
        prepared = self.registry.prepare("service.restart", original)
        original["service"] = "ssh"
        self.assertEqual(prepared.parameters.service, "nginx.service")
        for obj, name, value in ((prepared, "argv", ("sh",)),
                                 (prepared, "execution_supported", True),
                                 (prepared.parameters, "service", "ssh"),
                                 (prepared.contract, "privilege", Privilege.UNPRIVILEGED),
                                 (self.registry, "permitted_workspace", "/etc")):
            with self.subTest(name=name), self.assertRaises(FrozenInstanceError):
                setattr(obj, name, value)
        with self.assertRaises(TypeError):
            ACTIONS["shell"] = prepared.contract

    def test_resource_queries_preserve_sshfs_exclusion_without_a_shell(self):
        self.assertEqual(self.registry.prepare("disk.usage").argv,
                         ("/usr/bin/df", "-P", "-B1", "--exclude-type=fuse.sshfs"))
        self.assertEqual(self.registry.prepare("memory.usage").argv, ("/usr/bin/free", "--bytes"))


class ServiceTests(OfflineRegistryTest):
    def test_service_aliases_suffixes_and_instances(self):
        for value, expected in (("apache", "apache2.service"), ("httpd.service", "apache2.service"),
                                ("nginx.service", "nginx.service"), ("worker@tenant-1", "worker@tenant-1.service")):
            with self.subTest(value=value):
                prepared = self.registry.prepare("service.start", {"service": value})
                self.assertEqual(prepared.parameters.service, expected)
                self.assertEqual(prepared.argv, ("/usr/bin/systemctl", "--no-ask-password", "start", "--", expected))

    def test_malformed_or_broad_service_names_rejected(self):
        invalid = (None, 1, True, [], "", " nginx", "nginx ", "--all", "-Hhost",
                   "nginx;id", "nginx\nssh", "nginx ssh", "nginx*", "../nginx",
                   "/tmp/nginx", "nginx\x00", "foo\\x2eservice", "foo.socket",
                   "foo.target", "foo.service.service", "foo@", "foo@@bar", "..", "x" * 256)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(InvalidParameters):
                self.registry.prepare("service.restart", {"service": value})

    def test_omitted_model_checks_do_not_remove_mandatory_service_checks(self):
        for intent in ("service_status", "service_start", "service_stop", "service_restart"):
            for declared in ({}, {"pre_conditions": []}):
                with self.subTest(intent=intent, declared=declared):
                    prepared = adapt_plan({"intent": intent, "target": "nginx", **declared}, self.registry)
                    self.assertTrue({"systemd_available", "service_exists"} <= self.names(prepared))
                    if intent != "service_status":
                        self.assertIn("authenticated_authorization", self.names(prepared))
                        self.assertEqual(prepared.contract.privilege, Privilege.AUTHENTICATED_ADMIN)

    def test_privilege_claims_cannot_grant_permission_or_lower_requirements(self):
        expected = self.registry.prepare("service.restart", {"service": "nginx"})
        for claim in (False, True, "authorized", None, {"root": True}):
            with self.subTest(claim=claim):
                prepared = adapt_plan({"intent": "service_restart", "target": "nginx",
                                       "requires_sudo": claim, "risk_level": "low",
                                       "command": "sudo sh -c 'anything'", "rollback": "rm -rf /"}, self.registry)
                self.assertEqual(prepared, expected)
                self.assertFalse(prepared.execution_supported)
        for field in ("authenticated", "privilege", "execution_supported", "requires_sudo"):
            with self.subTest(field=field), self.assertRaises(InvalidParameters):
                self.registry.prepare("service.start", {"service": "nginx", field: True})
        with self.assertRaises(InvalidParameters):
            adapt_plan({"intent": "service_start", "target": "nginx", "authenticated": True}, self.registry)

    def test_model_cannot_elevate_a_read_only_action(self):
        prepared = adapt_plan({"intent": "memory_usage", "requires_sudo": True,
                               "risk_level": "high", "command": "sudo arbitrary"}, self.registry)
        self.assertEqual(prepared.contract.privilege, Privilege.UNPRIVILEGED)
        self.assertEqual(prepared.argv, ("/usr/bin/free", "--bytes"))

    def test_service_postconditions_require_actual_state(self):
        for action, expected in (("start", "active"), ("stop", "inactive"), ("restart", "active")):
            prepared = self.registry.prepare("service." + action, {"service": "nginx"})
            post = next(p for p in prepared.postconditions if p.identifier == "service_active_state")
            self.assertEqual(dict(post.arguments), {"service": "nginx.service", "state": expected})
        status = self.registry.prepare("service.status", {"service": "nginx"})
        self.assertIn("show", status.argv)
        self.assertIn("--no-pager", status.argv)
        self.assertNotIn("authenticated_authorization", self.names(status))

    def test_supported_conditional_fast_paths_keep_constraints(self):
        for phrase, expected in (("restart nginx only if port 80 is free", "tcp_port_free"),
                                 ("stop nginx if port 80 is occupied", "tcp_port_occupied")):
            prepared = adapt_plan(classify_fast(phrase), self.registry)
            self.assertIn(expected, self.names(prepared))
            self.assertIn("service_exists", self.names(prepared))
            condition = next(c for c in prepared.mandatory_checks if c.identifier == expected)
            self.assertEqual(dict(condition.arguments), {"port": 80})

    def test_listener_reconfiguration_is_not_silently_reduced(self):
        with self.assertRaisesRegex(InvalidParameters, "listener configuration"):
            adapt_plan(classify_fast("start nginx on port 5555"), self.registry)

    def test_unsupported_malformed_or_mismatched_conditions_rejected(self):
        invalid = (None, "service_exists", [None], [{}], [{"check": []}],
                   [{"check": "invented"}], [{"check": "service_exists", "service": "ssh"}],
                   [{"check": "service_exists", "service": "nginx", "skip": True}],
                   [{"check": "port_free", "port": "80;id"}],
                   [{"check": "port_free", "port": 80}, {"check": "port_free", "port": 81}],
                   [{"check": "port_free", "port": 80}, {"check": "port_occupied", "port": 80}])
        for conditions in invalid:
            with self.subTest(conditions=conditions), self.assertRaises(InvalidParameters):
                adapt_plan({"intent": "service_start", "target": "nginx", "pre_conditions": conditions}, self.registry)
        with self.assertRaises(InvalidParameters):
            self.registry.prepare("service.status", {"service": "nginx", "port_free": 80})


class PortTests(OfflineRegistryTest):
    def test_tcp_udp_and_port_filter_argument_arrays(self):
        for protocol, flag in (("tcp", "-t"), ("udp", "-u")):
            prepared = self.registry.prepare("ports.listen", {"port": 65535, "protocol": protocol})
            self.assertEqual(prepared.argv, ("/usr/bin/ss", "-H", "-l", "-n", flag, "sport = :65535"))
            self.assertEqual(prepared.contract.privilege, Privilege.UNPRIVILEGED)

    def test_malformed_ports_rejected_without_coercion(self):
        for value in (True, False, 0, -1, 65536, "80", "80;id", 80.0, [], {}):
            with self.subTest(value=value), self.assertRaises(InvalidParameters):
                self.registry.prepare("ports.listen", {"port": value})
        for value in (None, True, 0, 65536, "80;id", "-p", " 80", "1.2", []):
            with self.subTest(adapter=value), self.assertRaises(InvalidParameters):
                adapt_plan({"intent": "port_check", "port": value}, self.registry)

    def test_legacy_numeric_port_strings_are_normalized(self):
        prepared = adapt_plan({"intent": "port_check", "port": "0080", "target": "80"}, self.registry)
        self.assertEqual(prepared.parameters.port, 80)
        self.assertEqual(adapt_plan(classify_fast("check port 80"), self.registry).parameters.port, 80)

    def test_ambiguous_ports_and_protocols_rejected(self):
        for plan in ({"intent": "port_check", "port": 80, "target": "81"},
                     {"intent": "port_check", "command": "ss sport = :80"},
                     {"intent": "port_list", "target": "80"},
                     {"intent": "port_list", "protocol": "tcp;id"}):
            with self.subTest(plan=plan), self.assertRaises(InvalidParameters):
                adapt_plan(plan, self.registry)


class WorkspaceTests(OfflineRegistryTest):
    def test_workspace_is_explicit_absolute_backend_configuration(self):
        for action in ("file.create", "directory.create"):
            with self.subTest(action=action), self.assertRaises(InvalidParameters):
                ActionRegistry().prepare(action, {"path": "foo"})
        for workspace in ("/", "relative", "~/work", "C:\\work", "/srv/../etc", "/srv//work"):
            with self.subTest(workspace=workspace), self.assertRaises(InvalidParameters):
                ActionRegistry(workspace)
        with self.assertRaises(InvalidParameters):
            adapt_plan({"intent": "file_create", "target": "foo", "kind": "file",
                        "permitted_workspace": "/etc"}, self.registry)

    def test_paths_must_be_strictly_inside_workspace(self):
        invalid = (None, [], "", ".", "..", "../escape", "nested/../../escape", "/etc/passwd",
                   "/srv/linxai-work-other/x", "/srv/linxai-work", "/srv/linxai-work/../x",
                   "a//b", "a/./b", "a/", "~/x", "$HOME/x", "C:/x", "a\\b",
                   "a\x00b", "a\nb", "a;id", "$(id)", "a/*", "-option", "x" * 256,
                   "/".join(["a" * 255] * 16))
        for path in invalid:
            with self.subTest(path=str(path)[:100]), self.assertRaises(InvalidParameters):
                self.registry.prepare("file.create", {"path": path})

    def test_file_content_uses_stdin_and_is_never_code(self):
        content = "hello\n$(rm -rf /); 'quotes'\n"
        prepared = self.registry.prepare("file.create", {"path": "notes/read me.txt", "content": content})
        self.assertEqual(prepared.parameters.relative_path, "notes/read me.txt")
        self.assertEqual(prepared.stdin, content.encode())
        self.assertNotIn(content, prepared.argv)
        self.assertEqual(prepared.argv[:3], ("/usr/bin/python3", "-I", "-c"))
        self.assertEqual(prepared.argv[3], CREATE_PROGRAM)
        post = next(p for p in prepared.postconditions if p.identifier == "file_content_sha256")
        self.assertEqual(dict(post.arguments)["sha256"], hashlib.sha256(content.encode()).hexdigest())

    def test_file_safety_checks_cannot_be_omitted_by_model(self):
        prepared = adapt_plan({"intent": "file_create", "target": "readme.txt", "kind": "file",
                               "pre_conditions": [], "requires_sudo": True}, self.registry)
        self.assertTrue({"workspace_safe", "no_symlink_components", "parent_directory_writable",
                         "target_absent", "unprivileged_identity"} <= self.names(prepared))
        self.assertEqual(prepared.contract.privilege, Privilege.UNPRIVILEGED)

    def test_absolute_paths_normalize_and_locations_are_explicit(self):
        absolute = self.registry.prepare("file.create", {"path": "/srv/linxai-work/a.txt"})
        self.assertEqual(absolute.parameters.relative_path, "a.txt")
        for path, location in (("a.txt", "/srv/linxai-work"),
                               ("/srv/linxai-work/a.txt", "/srv/linxai-work")):
            self.assertEqual(adapt_plan({"intent": "file_create", "target": path,
                                        "location": location, "kind": "file"}, self.registry), absolute)
        nested = adapt_plan({"intent": "file_create", "target": "a.txt", "location": "reports",
                             "kind": "file"}, self.registry)
        self.assertEqual(nested.parameters.relative_path, "reports/a.txt")

    def test_create_kind_path_and_content_ambiguities_rejected(self):
        cases = ({"target": "a.txt"}, {"target": "a.txt", "kind": "unknown"},
                 {"target": "a.txt", "kind": "file", "file_create_kind": "directory"},
                 {"target": "a.txt", "path": "b.txt", "kind": "file"},
                 {"target": "/srv/linxai-work/a.txt", "location": "other", "kind": "file"},
                 {"target": "a", "kind": "directory", "content": "hello"},
                 {"target": "a", "kind": "file", "content": []},
                 {"target": "a", "kind": "file", "content": "é" * 32769},
                 {"target": "a", "kind": "file", "content": "\ud800"})
        for slots in cases:
            with self.subTest(slots=str(slots)[:100]), self.assertRaises(InvalidParameters):
                adapt_plan({"intent": "file_create", **slots}, self.registry)

    def test_fast_path_file_and_directory_plans_adapt_without_command_inference(self):
        for phrase, identifier in (("create file sample.txt", "file.create"),
                                   ("create directory reports", "directory.create")):
            prepared = adapt_plan(classify_fast(phrase), self.registry)
            self.assertEqual(prepared.contract.identifier, identifier)
        with self.assertRaises(InvalidParameters):
            adapt_plan({"intent": "file_create", "command": "touch guessed.txt", "kind": "file"}, self.registry)


class AdapterBoundaryTests(OfflineRegistryTest):
    def test_cached_plan_and_nested_conditions_are_not_mutated(self):
        import copy
        plan = classify_fast("restart nginx only if port 80 is free")
        original = copy.deepcopy(plan)
        prepared = adapt_plan(plan, self.registry)
        self.assertEqual(plan, original)
        plan["target"] = "ssh"
        plan["pre_conditions"].clear()
        self.assertEqual(prepared.parameters.service, "nginx.service")
        self.assertIn("tcp_port_free", self.names(prepared))

    def test_unsupported_intents_and_bad_plan_shapes_rejected(self):
        for plan in ({"intent": "package_install"}, {"intent": "service_reload"},
                     {"intent": "file_delete"}, {"intent": []}, {}):
            with self.subTest(plan=plan), self.assertRaises(UnsupportedAction):
                adapt_plan(plan, self.registry)
        for plan in (None, [], "plan", 1):
            with self.subTest(plan=plan), self.assertRaises(InvalidParameters):
                adapt_plan(plan, self.registry)

    def test_nonempty_unsupported_semantic_slots_are_not_dropped(self):
        for key, value in (("path", "/etc"), ("target", "custom"), ("query", "special"),
                           ("repo_url", "https://example.invalid"), ("content", "data")):
            with self.subTest(key=key), self.assertRaises(InvalidParameters):
                adapt_plan({"intent": "disk_usage", key: value}, self.registry)

    def test_arbitrary_command_metadata_is_ignored_not_parsed(self):
        expected = self.registry.prepare("disk.usage")
        for command in ("rm -rf /", "sudo reboot", None, [], {"execute": True}):
            with self.subTest(command=command):
                self.assertEqual(adapt_plan({"intent": "disk_usage", "command": command}, self.registry), expected)


class CreateProgramTests(OfflineRegistryTest):
    def program(self, kind="file", data=b"hello", euid=1000, platform="linux"):
        fake_os = types.SimpleNamespace(
            geteuid=lambda: euid, O_RDONLY=1, O_DIRECTORY=2, O_NOFOLLOW=4,
            O_CLOEXEC=8, O_WRONLY=16, O_CREAT=32, O_EXCL=64,
            open=Mock(side_effect=range(10, 30)), close=Mock(), mkdir=Mock(), fdopen=MagicMock())
        fake_sys = types.SimpleNamespace(platform=platform,
            argv=["-c", "/srv/linxai-work", "nested/new.txt", kind],
            stdin=types.SimpleNamespace(buffer=io.BytesIO(data)))
        with patch.dict(sys.modules, {"os": fake_os, "sys": fake_sys}):
            exec(compile(CREATE_PROGRAM, "<trusted-create-program>", "exec"), {})
        return fake_os

    def test_fixed_program_uses_nofollow_parents_and_exclusive_file_creation(self):
        fake_os = self.program()
        self.assertEqual([c.args[0] for c in fake_os.open.call_args_list],
                         ["/", "srv", "linxai-work", "nested", "new.txt"])
        for call in fake_os.open.call_args_list[:-1]:
            self.assertTrue(call.args[1] & fake_os.O_NOFOLLOW)
            self.assertTrue(call.args[1] & fake_os.O_DIRECTORY)
        final = fake_os.open.call_args_list[-1]
        self.assertTrue(final.args[1] & fake_os.O_EXCL)
        self.assertTrue(final.args[1] & fake_os.O_NOFOLLOW)
        self.assertEqual(final.args[2], 0o600)
        self.assertEqual(final.kwargs, {"dir_fd": 13})
        fake_os.fdopen.return_value.__enter__.return_value.write.assert_called_once_with(b"hello")
        self.assertEqual(fake_os.close.call_count, 4)

    def test_directory_creation_does_not_reuse_file_writer(self):
        fake_os = self.program(kind="directory", data=b"")
        fake_os.mkdir.assert_called_once_with("new.txt", 0o700, dir_fd=13)
        fake_os.fdopen.assert_not_called()

    def test_fixed_program_refuses_root_wrong_platform_and_oversized_content(self):
        for args in ({"euid": 0}, {"platform": "win32"}, {"data": b"x" * 65537},
                     {"kind": "directory", "data": b"text"}):
            with self.subTest(args=str(args)[:80]), self.assertRaises(SystemExit):
                self.program(**args)


if __name__ == "__main__":
    unittest.main()
