"""Optional prerequisite/smoke tests. No automatic provisioning or model downloads."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import urllib.error
import urllib.request


@unittest.skipUnless(os.environ.get("LINXAI_TEST_PRIVILEGED") == "1", "opt in with LINXAI_TEST_PRIVILEGED=1 in a controlled Linux lab")
class PrivilegedTests(unittest.TestCase):
    def test_os_interpreter_bcc_import(self):
        if sys.platform != "linux":
            self.skipTest("Linux sensor OS required")
        binary = os.environ.get("LINXAI_BCC_PYTHON", "/usr/bin/python3")
        result = subprocess.run([binary, "-c", "import importlib.util; raise SystemExit(0 if importlib.util.find_spec('bcc') else 77)"], capture_output=True, timeout=10)
        if result.returncode == 77:
            self.skipTest("OS-supplied python3-bpfcc unavailable; never pip-install PyPI bcc")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_enforcement_acceptance_pending(self):
        self.skipTest("Pending approved dedicated-kernel enforcement scenario; UID 0 is not proof of usable hooks")


@unittest.skipUnless(os.environ.get("LINXAI_TEST_DESKTOP") == "1", "opt in with LINXAI_TEST_DESKTOP=1")
class DesktopTests(unittest.TestCase):
    def test_candidate_qt_toolkit(self):
        if not importlib.util.find_spec("PySide6"):
            self.skipTest("candidate desktop extra not installed; toolkit choice remains proposed")
        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            self.skipTest("no GUI display configured")
        result = subprocess.run([sys.executable, "-c", "from PySide6.QtWidgets import QApplication,QLabel; a=QApplication([]); label=QLabel('LINxAI'); assert label.text()=='LINxAI'"], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))


@unittest.skipUnless(os.environ.get("LINXAI_TEST_HARDWARE") == "1", "opt in with LINXAI_TEST_HARDWARE=1; may open camera")
class HardwareTests(unittest.TestCase):
    def test_camera_frame(self):
        if sys.platform != "linux" or not list(Path("/dev").glob("video*")):
            self.skipTest("no Linux camera device exposed")
        if not importlib.util.find_spec("cv2"):
            self.skipTest("hardware extra not installed")
        import cv2
        camera = cv2.VideoCapture(0)
        try:
            ok, frame = camera.read()
            self.assertTrue(ok and frame is not None, "camera frame unavailable")
        finally:
            camera.release()

    def test_voice_acceptance(self):
        model=os.environ.get("LINXAI_VOICE_MODEL")
        reference=os.environ.get("LINXAI_VOICE_REFERENCE")
        if not model or not reference:self.skipTest("Real microphone/WER requires LINXAI_VOICE_MODEL and LINXAI_VOICE_REFERENCE")
        if not importlib.util.find_spec("sounddevice") or not importlib.util.find_spec("faster_whisper"):self.skipTest("Explicit voice profile is not installed")
        from voice.client import listen
        from voice.pipeline import wer
        result=wer(reference,listen(model))
        self.assertLessEqual(result["wer"],0.15,json.dumps(result))


@unittest.skipUnless(os.environ.get("LINXAI_TEST_MODEL") == "1", "opt in with LINXAI_TEST_MODEL=1; uses existing loopback Ollama only")
class RealModelTests(unittest.TestCase):
    def test_existing_local_model_response(self):
        model = os.environ.get("LINXAI_TEST_MODEL_NAME", "qwen2.5:1.5b")
        try:
            with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=3) as stream:
                names = {entry["name"] for entry in json.load(stream).get("models", [])}
        except (OSError, urllib.error.URLError):
            self.skipTest("Ollama not available; do not start it during setup")
        if model not in names:
            self.skipTest(f"model {model} not installed; no downloads in tests")
        payload = json.dumps({"model": model, "stream": False, "messages": [{"role": "user", "content": "Reply only LINXAI_MODEL_READY"}], "options": {"temperature": 0, "num_predict": 32}}).encode()
        request = urllib.request.Request("http://127.0.0.1:11434/api/chat", data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=30) as stream:
            reply = json.load(stream)
        self.assertEqual(reply["message"]["content"].strip(), "LINXAI_MODEL_READY")
