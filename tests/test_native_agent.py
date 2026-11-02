"""Native authenticated agent, actual operations and durable restart; no model/GUI."""
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest

from operations.agent import Agent, AgentClient, serve


@unittest.skipUnless(sys.platform == "linux", "native Linux required")
class NativeAgentTests(unittest.TestCase):
    def setUp(self):
        if os.getuid() == 0: self.skipTest("ordinary user required")
        self.temp = self.enterContext(tempfile.TemporaryDirectory(prefix=".linxai-agent-", dir=Path.home()))
        self.state = Path(self.temp) / "state"
        self.workspace = Path(self.temp) / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.agent = Agent(self.state, str(self.workspace))
        self.stop = threading.Event()
        self.thread = threading.Thread(target=serve, args=(self.agent, self.state / "agent.sock", self.stop), daemon=True)
        self.thread.start()
        for _ in range(100):
            if (self.state / "agent.sock").exists(): break
            time.sleep(0.01)
        self.client = AgentClient(self.state / "agent.sock")

    def tearDown(self):
        self.stop.set()
        self.thread.join(timeout=4)
        self.agent.store.close()

    def wait_result(self, key):
        for _ in range(100):
            row = self.client.call("job", id=key)
            if row["state"] in {"succeeded", "failed", "unknown", "review_required"}: return row
            time.sleep(0.02)
        self.fail("Job did not finish within native test bound")

    def test_real_read_survives_client_disconnect_and_reopen(self):
        preview = self.client.call("preview", text="show memory usage")
        self.assertEqual(preview["state"], "preview")
        self.client.call("confirm", id=preview["id"], digest=preview["digest"])
        # A new client observes the independently running agent's durable result.
        self.client = AgentClient(self.state / "agent.sock")
        result = self.wait_result(preview["id"])
        self.assertEqual(result["state"], "succeeded", result)
        self.assertTrue(result["result"]["verified"])
        self.assertTrue(self.client.call("jobs")["jobs"])
        with self.assertRaises(ValueError):
            self.client.call("confirm", id=preview["id"], digest=preview["digest"])

    def test_second_agent_cannot_unlink_socket_or_reconcile_running_jobs(self):
        other = Agent(self.state, str(self.workspace))
        try:
            with self.assertRaises(BlockingIOError):
                serve(other, self.state / "agent.sock", threading.Event())
            self.assertTrue((self.state / "agent.sock").is_socket())
            self.assertEqual(self.client.call("status")["uid"], os.getuid())
        finally:
            other.store.close()

    def test_client_authority_fields_and_wrong_identity_rejected(self):
        with self.assertRaises(PermissionError):
            self.agent.handle(self.agent.uid + 1, {"version": 1, "method": "jobs"})
        with self.assertRaises(ValueError):
            self.client.call("preview", text="memory usage", authenticated=True)
