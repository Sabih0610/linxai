"""Broker contract tests. All service/auth effects are deterministic adapter doubles."""
from dataclasses import replace
import io
import json
from pathlib import Path
import socket
import struct
import sys
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from operations.broker import Broker, BrokerClient, BrokerService, BrokerSystem, Polkit
from operations import ipc
from operations.service import Identity, Execution, Observation, _Stop
from test_operations_service import MemoryAudit


class PeerDouble:
    pid, uid, gid, start = 1234, 1000, 1000, 987654
    def validate(self):
        return Identity(self.uid, self.uid, "owner")


class LedgerDouble:
    def __init__(self):
        self.rows = {}
    def put(self, kind, key, value, *, replace=True, limit=1000):
        if not replace and key in self.rows:
            raise ValueError("Replay")
        self.rows[key] = value


class SystemDouble:
    def __init__(self, peer):
        self.peer, self.authorized, self.calls = peer, None, []
        self.bad_check, self.bad_post, self.fail_execute, self.changed = False, False, False, False
    def resolve_identity(self):
        return self.peer.validate()
    def check(self, op_id, required, identity):
        return Observation(op_id, required, not self.bad_check, "observed", "changed" if self.changed else "initial")
    def execute(self, op_id, prepared, identity):
        self.calls.append((op_id, prepared))
        return Execution(op_id, prepared.argv, 1 if self.fail_execute else 0)
    def verify(self, op_id, required, prepared, execution, identity):
        return Observation(op_id, required, not self.bad_post, "observed")


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.peer, self.audit, self.store = PeerDouble(), MemoryAudit(), LedgerDouble()
        self.system = SystemDouble(self.peer)
        self.auth = Mock()
        self.auth.authorize.return_value = True
        self.broker = Broker(1000, ["linxai-lab"], self.store, self.audit,
                             system_factory=lambda peer: self.system, authorizer_factory=lambda system: self.auth)
        self.request = {"action": "service.restart", "parameters": {"service": "linxai-lab"}}
    def envelope(self):
        return {"version": 1, "request_id": str(uuid4()), "request": self.request}

    def test_authorized_exact_operation_and_correlation(self):
        env = self.envelope()
        result = self.broker.handle(self.peer, env)
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(result["operation_id"], env["request_id"])
        self.assertEqual(self.system.calls[0][1].argv, ("/usr/bin/systemctl", "--no-ask-password", "restart", "--", "linxai-lab.service"))
        phases = {r["phase"] for r in self.audit.records}
        self.assertTrue({"authorization", "validation", "execution", "verification", "result"} <= phases)
        bound = [r for r in self.audit.records if r["phase"] in {"validation", "execution", "verification"}]
        self.assertEqual({r["operation_id"] for r in bound}, {env["request_id"]})
        self.assertEqual({r["fingerprint"] for r in bound}, {result["fingerprint"]})
        self.assertEqual(self.auth.authorize.call_count, 1)

    def test_wrong_user_and_unconfigured_service_never_dispatch(self):
        self.broker.owner_uid = 1001
        self.assertEqual(self.broker.handle(self.peer, self.envelope())["status"], "broker_denied")
        self.broker.owner_uid = 1000
        self.request["parameters"]["service"] = "unconfigured"
        self.assertEqual(self.broker.handle(self.peer, self.envelope())["status"], "authorization_denied")
        self.assertFalse(self.system.calls)
        self.auth.authorize.assert_not_called()

    def test_denied_cancelled_and_unavailable_authentication(self):
        for status in ("authentication_authorization_required", "authentication_cancelled"):
            self.auth.authorize.side_effect = _Stop(status, "OS decision")
            self.assertEqual(self.broker.handle(self.peer, self.envelope())["status"], status)
        self.auth.authorize.side_effect = None
        self.auth.authorize.return_value = False
        self.assertEqual(self.broker.handle(self.peer, self.envelope())["status"], "authentication_authorization_required")
        self.assertFalse(self.system.calls)

    def test_replay_and_wire_authority_claims_denied(self):
        env = self.envelope()
        self.broker.handle(self.peer, env)
        self.assertEqual(self.broker.handle(self.peer, env)["status"], "broker_denied")
        for key in ("uid", "argv", "authenticated", "requires_sudo"):
            altered = self.envelope()
            altered[key] = True
            self.assertEqual(self.broker.handle(self.peer, altered)["status"], "broker_denied")
        self.assertEqual(len(self.system.calls), 1)

    def test_bad_checks_execution_postconditions_and_audit(self):
        for field, status in (("bad_check", "validation_failed"), ("fail_execute", "execution_failed"), ("bad_post", "verification_failed")):
            setattr(self.system, field, True)
            result = self.broker.handle(self.peer, self.envelope())
            self.assertEqual(result["status"], status, result)
            setattr(self.system, field, False)
        self.audit.fail_phase = "execution"
        before = len(self.system.calls)
        self.assertEqual(self.broker.handle(self.peer, self.envelope())["status"], "audit_failed")
        self.assertEqual(len(self.system.calls), before)

    def test_changed_target_state_and_expired_authorization_require_revalidation(self):
        service = BrokerService(str(uuid4()), self.request, self.peer, 1000, {"linxai-lab.service"}, self.system, self.auth, self.audit)
        approval = service.prepare(self.request)
        altered = replace(approval.operation.prepared, argv=("/usr/bin/false",))
        result = service.execute(replace(approval, operation=replace(approval.operation, prepared=altered)))
        self.assertEqual(result.status, "approval_invalid")
        approval = service.prepare(self.request)
        self.system.changed = True
        self.assertEqual(service.execute(approval).status, "state_changed")
        self.system.changed = False
        approval = service.prepare(self.request)
        service.grant = (service.grant[0], 0)
        self.assertEqual(service.execute(approval).status, "authorization_denied")
        self.assertFalse(self.system.calls)

    def test_polkit_uses_os_peer_triple_exact_details_and_no_password_io(self):
        runner = Mock()
        runner._run.return_value = Execution("op", (), 0)
        auth = Polkit(runner)
        service = BrokerService(str(uuid4()), self.request, self.peer, 1000, {"linxai-lab.service"}, self.system, auth, self.audit)
        approval = service.prepare(self.request)
        argv = runner._run.call_args.args[1]
        self.assertIn("1234,987654,1000", argv)
        self.assertIn(approval.operation.operation_id, argv)
        self.assertIn("linxai-lab.service", argv)
        self.assertEqual(runner._run.call_args.args[2:], (b"", 120))
        runner._run.return_value = Execution("op", (), 3)
        with self.assertRaises(_Stop) as denied:
            auth.authorize(self.peer, approval.operation)
        self.assertEqual(denied.exception.status, "authentication_cancelled")

    def test_persistence_failure_after_dispatch_preserves_side_effect_state(self):
        original = self.store.put
        count = 0
        def put(*args, **kwargs):
            nonlocal count
            count += 1
            if count == 2: raise OSError("disk full")
            return original(*args, **kwargs)
        self.store.put = put
        result = self.broker.handle(self.peer, self.envelope())
        self.assertEqual(result["status"], "broker_record_failed")
        self.assertTrue(result["executed"])
        self.assertTrue(result["verified"])
        self.assertFalse(result["audit_complete"])

    def test_broker_unavailable_explicit_and_never_local_fallback(self):
        result = BrokerClient("/nonexistent-linxai/broker.sock").run(self.request)
        self.assertEqual(result.status, "authentication_authorization_required")
        self.assertIsNone(result.executed)

    def test_oversized_duplicate_and_incomplete_frames(self):
        class Sock:
            def __init__(self, value): self.data = io.BytesIO(value)
            def recv(self, n): return self.data.read(n)
        for frame in (struct.pack("!I", ipc.MAX_FRAME + 1), struct.pack("!I", 8)+b"{}", struct.pack("!I", 13)+b'{"a":1,"a":2}'):
            with self.assertRaises(ValueError): ipc.receive(Sock(frame))

    @unittest.skipUnless(sys.platform == "linux", "real Linux peer credentials")
    def test_real_socket_peer_credentials(self):
        import os
        from operations.broker import Peer
        if os.getuid() == 0: self.skipTest("ordinary user required")
        left, right = socket.socketpair()
        with left, right:
            peer = Peer.read(left)
            self.assertEqual(peer.pid, os.getpid())
            self.assertEqual(peer.validate().uid, os.getuid())
