"""Explicit Qt offscreen contract test; not physical desktop/hardware acceptance."""
import os
import time
import unittest


@unittest.skipUnless(os.environ.get("LINXAI_TEST_DESKTOP") == "1", "opt in for installed Qt desktop tests")
class DesktopTests(unittest.TestCase):
    def test_nonblocking_preview_and_confirm_with_deterministic_backend(self):
        from PySide6.QtWidgets import QApplication
        from ui.desktop import build_window
        class Backend:
            def __init__(self): self.confirmed = False
            def call(self, method, **fields):
                if method == "preview": return {"id": "preview-1", "digest": "exact", "state": "preview"}
                if method == "confirm": self.confirmed = True; return {"id": "preview-1"}
                if method == "jobs": return {"jobs": []}
                if method == "status": return {"uid": 1000, "workspace": "/lab"}
                if method == "security": return {"status": "test double; no actual sensor", "incidents": []}
        backend = Backend()
        app = QApplication.instance() or QApplication([])
        window = build_window(backend)
        window.input.setText("show memory usage")
        window.plan_button.click()
        deadline = time.monotonic() + 3
        while not window.confirm_button.isEnabled() and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        self.assertTrue(window.confirm_button.isEnabled())
        window.confirm_button.click()
        while not backend.confirmed and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        self.assertTrue(backend.confirmed)
        self.assertEqual(window.tabs.count(), 5)
        window.timer.stop()
        window.pool.waitForDone(3000)
        app.processEvents()
        window.close()
