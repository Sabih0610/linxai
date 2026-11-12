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

    def test_voice_reaches_preview_without_confirmation(self):
        from unittest.mock import Mock, patch
        from PySide6.QtWidgets import QApplication
        from ui.desktop import build_window
        backend=Mock()
        def response(method,**fields):
            if method=="jobs":return {"jobs":[]}
            if method=="preview":return {"id":"voice-job","digest":"bound"}
            return {}
        backend.call.side_effect=response
        app=QApplication.instance() or QApplication([])
        window=build_window(backend,"/existing/test-only-model")
        with patch("voice.client.listen",return_value="show memory usage"):
            window.voice_button.click()
            deadline=time.monotonic()+3
            while not window.confirm_button.isEnabled() and time.monotonic()<deadline:
                app.processEvents();time.sleep(0.01)
        self.assertEqual(window.input.text(),"show memory usage")
        self.assertTrue(window.confirm_button.isEnabled())
        self.assertFalse(any(call.args[0]=="confirm" for call in backend.call.call_args_list))
        window.timer.stop();window.pool.waitForDone(3000);app.processEvents();window.close()

    def test_device_profile_answer_cannot_be_confirmed(self):
        from unittest.mock import Mock
        from PySide6.QtWidgets import QApplication
        from ui.desktop import build_window
        backend=Mock()
        def response(method,**fields):
            if method=="jobs":return {"jobs":[]}
            if method=="preview":return {"answer":True,"device":"srl1","proven":["system.hostname"]}
            return {}
        backend.call.side_effect=response
        app=QApplication.instance() or QApplication([])
        window=build_window(backend)
        window.input.setText("what can srl1 do");window.plan_button.click()
        deadline=time.monotonic()+3
        while '"answer"' not in window.preview_text.toPlainText() and time.monotonic()<deadline:
            app.processEvents();time.sleep(0.01)
        self.assertIn('"proven"',window.preview_text.toPlainText())
        self.assertFalse(window.confirm_button.isEnabled())       # an answer is information, never a job
        self.assertIsNone(window.preview)
        window.confirm()                                           # even a direct call sends nothing
        window.pool.waitForDone(3000);app.processEvents()
        self.assertFalse(any(call.args[0]=="confirm" for call in backend.call.call_args_list))
        window.timer.stop();window.close()

    def test_changed_input_cannot_accept_stale_async_preview(self):
        import threading
        from unittest.mock import Mock
        from PySide6.QtWidgets import QApplication
        from ui.desktop import build_window
        entered,released=threading.Event(),threading.Event()
        backend=Mock()
        def response(method,**fields):
            if method=="jobs":return {"jobs":[]}
            if method=="preview":
                entered.set();released.wait(2)
                return {"id":"stale","digest":"old"}
            return {}
        backend.call.side_effect=response
        app=QApplication.instance() or QApplication([])
        window=build_window(backend)
        window.input.setText("show memory usage");window.plan_button.click()
        self.assertTrue(entered.wait(2))
        window.input.setText("restart another service");released.set()
        window.pool.waitForDone(3000);app.processEvents()
        self.assertFalse(window.confirm_button.isEnabled())
        self.assertIsNone(window.preview)
        window.timer.stop();window.close()
