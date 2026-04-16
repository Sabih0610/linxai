# executor/face_auth.py
# OpenCV-based face authentication server for LINxAI sudo operations.
#
# Architecture:
#   pam_linxai_face.so (C PAM module)
#       ↕ Unix domain socket (/tmp/linxai_pam.sock)
#   FaceAuthServer (this file, Python)
#       → OpenCV camera capture
#       → Haar cascade face detection
#       → Lucas-Kanade optical flow liveness detection
#       → LBPH face recognizer (enrolled face comparison)
#
# Liveness detection rationale:
#   A photograph has zero motion between frames.
#   A real face has micro-movements: blinking, breathing, slight head drift.
#   Lucas-Kanade tracks feature points across 5 frames.
#   If mean optical flow magnitude < LIVENESS_THRESHOLD → photo spoof → reject.
#
# Two modes:
#   server mode: runs as a daemon, handles PAM socket requests
#   enroll mode: captures and stores the authorised face template
#
# Run server: python3 executor/face_auth.py --server
# Enroll:     python3 executor/face_auth.py --enroll
# Test:       python3 executor/face_auth.py --test

import os
import sys
import cv2
import json
import time
import socket
import struct
import logging
import argparse
import threading
import numpy as np
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

SOCKET_PATH      = "/tmp/linxai_pam.sock"
FACE_DATA_DIR    = os.path.expanduser("~/.linxai/face")
TEMPLATE_PATH    = os.path.join(FACE_DATA_DIR, "face_template.yml")
CASCADE_PATH     = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"

NUM_FRAMES       = 5          # frames to capture per auth attempt
FRAME_DELAY_S    = 0.12       # seconds between frames (total ~600ms)
LIVENESS_THRESHOLD = 0.8      # minimum mean optical flow to pass liveness
AUTH_CONFIDENCE_THRESHOLD = 80.0  # LBPH confidence (lower = better match)
CAMERA_INDEX     = 0          # default camera device


# ── Face detector and recognizer ─────────────────────────────────────────────

class FaceAuthEngine:
    """
    Core face authentication logic.
    Handles enrollment, liveness detection, and identity verification.
    """

    def __init__(self):
        self.cascade = cv2.CascadeClassifier(CASCADE_PATH)
        if self.cascade.empty():
            raise RuntimeError(
                f"Haar cascade not found at {CASCADE_PATH}. "
                "Reinstall OpenCV: pip3 install opencv-python-headless"
            )
        self.recognizer = cv2.face.LBPHFaceRecognizer_create()
        self._template_loaded = False
        self._load_template()

    def _load_template(self):
        """Load stored face template if it exists."""
        if os.path.exists(TEMPLATE_PATH):
            try:
                self.recognizer.read(TEMPLATE_PATH)
                self._template_loaded = True
                logger.info("Face template loaded from disk.")
            except Exception as e:
                logger.warning(f"Could not load face template: {e}")

    def _detect_face(self, frame_gray: np.ndarray) -> Optional[np.ndarray]:
        """
        Detects the largest face in a grayscale frame.
        Returns cropped 100x100 face ROI or None if no face found.
        """
        faces = self.cascade.detectMultiScale(
            frame_gray,
            scaleFactor=1.1,
            minNeighbors=5,
            minSize=(60, 60),
            flags=cv2.CASCADE_SCALE_IMAGE
        )
        if len(faces) == 0:
            return None

        # Use largest detected face
        x, y, w, h = sorted(faces, key=lambda f: f[2] * f[3], reverse=True)[0]
        face_roi = frame_gray[y:y+h, x:x+w]
        return cv2.resize(face_roi, (100, 100))

    def _check_liveness(self, frames_gray: list) -> Tuple[bool, float]:
        """
        Liveness detection using Lucas-Kanade optical flow.

        Tracks Shi-Tomasi corner feature points across consecutive frames.
        A real face produces non-zero optical flow due to micro-movements.
        A static photograph produces near-zero flow.

        Args:
            frames_gray: list of consecutive grayscale frames

        Returns:
            (is_live, mean_flow_magnitude)
        """
        if len(frames_gray) < 2:
            return False, 0.0

        lk_params = dict(
            winSize=(15, 15),
            maxLevel=2,
            criteria=(cv2.TERM_CRITERIA_EPS | cv2.TERM_CRITERIA_COUNT, 10, 0.03)
        )

        # Detect feature points in first frame
        feature_params = dict(
            maxCorners=50,
            qualityLevel=0.3,
            minDistance=7,
            blockSize=7
        )

        p0 = cv2.goodFeaturesToTrack(frames_gray[0], mask=None, **feature_params)
        if p0 is None or len(p0) == 0:
            return False, 0.0

        flow_magnitudes = []

        for i in range(len(frames_gray) - 1):
            p1, st, err = cv2.calcOpticalFlowPyrLK(
                frames_gray[i], frames_gray[i+1], p0, None, **lk_params
            )
            if p1 is None:
                continue

            # Keep only successfully tracked points
            good_new = p1[st == 1]
            good_old = p0[st == 1]

            if len(good_new) == 0:
                continue

            # Calculate displacement magnitudes
            diffs = good_new - good_old
            magnitudes = np.sqrt(diffs[:, 0]**2 + diffs[:, 1]**2)
            flow_magnitudes.append(np.mean(magnitudes))

            # Use tracked points as new base
            p0 = good_new.reshape(-1, 1, 2)

        if not flow_magnitudes:
            return False, 0.0

        mean_flow = np.mean(flow_magnitudes)
        is_live = mean_flow >= LIVENESS_THRESHOLD

        logger.debug(
            f"Liveness: mean_flow={mean_flow:.3f}, "
            f"threshold={LIVENESS_THRESHOLD}, live={is_live}"
        )

        return is_live, float(mean_flow)

    def enroll(self, camera_index: int = CAMERA_INDEX) -> bool:
        """
        Captures the authorised user's face and saves a template.
        Must be run once before face auth can work.

        Returns True on successful enrollment.
        """
        os.makedirs(FACE_DATA_DIR, exist_ok=True)
        cap = cv2.VideoCapture(camera_index)

        if not cap.isOpened():
            logger.error(f"Cannot open camera {camera_index}")
            return False

        print("\n  Face enrollment for LINxAI")
        print("  ─────────────────────────────")
        print("  Look directly at the camera.")
        print("  Keep your face centred and still.")
        print("  Capturing 20 training frames...\n")

        face_samples = []
        labels = []
        frame_count = 0
        target = 20

        try:
            while frame_count < target:
                ret, frame = cap.read()
                if not ret:
                    break

                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                face = self._detect_face(gray)

                if face is not None:
                    face_samples.append(face)
                    labels.append(0)  # label 0 = authorised user
                    frame_count += 1
                    print(f"\r  Captured: {frame_count}/{target}  ", end="", flush=True)
                    time.sleep(0.15)
                else:
                    print(f"\r  No face detected — adjust position...  ", end="", flush=True)
                    time.sleep(0.1)

        finally:
            cap.release()

        if len(face_samples) < target:
            print(f"\n  Only captured {len(face_samples)} frames. Enrollment failed.")
            return False

        print(f"\n  Training face recognizer on {len(face_samples)} samples...")
        self.recognizer.train(face_samples, np.array(labels))
        self.recognizer.save(TEMPLATE_PATH)
        self._template_loaded = True

        print(f"  Face template saved to {TEMPLATE_PATH}")
        print("  Enrollment complete. Face authentication is ready.\n")
        return True

    def authenticate(self, camera_index: int = CAMERA_INDEX) -> Tuple[bool, str]:
        """
        Performs a full face authentication attempt.

        Steps:
          1. Capture NUM_FRAMES consecutive frames
          2. Detect face in each frame
          3. Run liveness detection (optical flow)
          4. Compare face against stored template (LBPH)

        Returns:
            (success: bool, reason: str)
        """
        if not self._template_loaded:
            return False, "No face template enrolled. Run: python3 executor/face_auth.py --enroll"

        cap = cv2.VideoCapture(camera_index)
        if not cap.isOpened():
            return False, f"Cannot open camera {camera_index}. Check camera connection."

        logger.info("Starting face authentication capture...")
        frames_gray = []
        faces_detected = []

        try:
            for i in range(NUM_FRAMES):
                ret, frame = cap.read()
                if not ret:
                    break

                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                frames_gray.append(gray)

                face = self._detect_face(gray)
                if face is not None:
                    faces_detected.append(face)

                time.sleep(FRAME_DELAY_S)
        finally:
            cap.release()

        # Must have detected face in majority of frames
        if len(faces_detected) < (NUM_FRAMES // 2 + 1):
            return False, (
                f"Face not detected in enough frames "
                f"({len(faces_detected)}/{NUM_FRAMES}). "
                f"Ensure your face is well-lit and centred."
            )

        # Liveness check
        is_live, flow_magnitude = self._check_liveness(frames_gray)
        if not is_live:
            logger.warning(
                f"Liveness check failed: flow={flow_magnitude:.3f} < "
                f"threshold={LIVENESS_THRESHOLD}"
            )
            return False, (
                f"Liveness check failed (flow={flow_magnitude:.2f}). "
                f"Please move slightly and try again."
            )

        # Identity verification using LBPH
        confidences = []
        for face in faces_detected:
            label, confidence = self.recognizer.predict(face)
            if label == 0:  # label 0 = authorised user
                confidences.append(confidence)

        if not confidences:
            return False, "Could not extract face features for comparison."

        mean_confidence = np.mean(confidences)
        logger.info(
            f"LBPH confidence: {mean_confidence:.1f} "
            f"(threshold: {AUTH_CONFIDENCE_THRESHOLD})"
        )

        # LBPH: lower confidence = better match
        if mean_confidence <= AUTH_CONFIDENCE_THRESHOLD:
            return True, (
                f"Authentication successful "
                f"(confidence={mean_confidence:.1f}, flow={flow_magnitude:.2f})"
            )

        return False, (
            f"Face not recognised (confidence={mean_confidence:.1f} > "
            f"threshold={AUTH_CONFIDENCE_THRESHOLD}). Access denied."
        )


# ── Unix socket server ────────────────────────────────────────────────────────

class FaceAuthServer:
    """
    Unix domain socket server that handles PAM authentication requests.

    The C PAM module connects to SOCKET_PATH, sends a JSON request,
    and waits for a JSON response. This server handles the request,
    runs face authentication, and sends the result back.

    Protocol:
        Request:  {"action": "authenticate", "user": "ubuntu"}
        Response: {"success": true, "reason": "Authentication successful ..."}
                  {"success": false, "reason": "Face not recognised ..."}
    """

    def __init__(self):
        self.engine = FaceAuthEngine()
        self.running = False

    def _handle_client(self, conn: socket.socket):
        """Handle one PAM authentication request."""
        try:
            # Read length-prefixed message
            raw_len = conn.recv(4)
            if not raw_len:
                return
            msg_len = struct.unpack(">I", raw_len)[0]
            data = conn.recv(msg_len).decode("utf-8")
            request = json.loads(data)

            action = request.get("action", "")
            logger.info(f"PAM request: action={action}, user={request.get('user', '?')}")

            if action == "authenticate":
                success, reason = self.engine.authenticate()
                response = {"success": success, "reason": reason}
                logger.info(f"Auth result: {'GRANTED' if success else 'DENIED'} — {reason}")
            else:
                response = {"success": False, "reason": f"Unknown action: {action}"}

            # Send length-prefixed response
            response_bytes = json.dumps(response).encode("utf-8")
            conn.sendall(struct.pack(">I", len(response_bytes)) + response_bytes)

        except Exception as e:
            logger.error(f"Error handling PAM request: {e}")
            try:
                response = {"success": False, "reason": str(e)}
                response_bytes = json.dumps(response).encode("utf-8")
                conn.sendall(struct.pack(">I", len(response_bytes)) + response_bytes)
            except Exception:
                pass
        finally:
            conn.close()

    def start(self):
        """Start the Unix socket server."""
        # Remove stale socket
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(SOCKET_PATH)
        os.chmod(SOCKET_PATH, 0o666)  # allow PAM module (root) to connect
        server.listen(5)
        server.settimeout(1.0)

        self.running = True
        logger.info(f"FaceAuthServer listening on {SOCKET_PATH}")
        print(f"[FaceAuth] Server running on {SOCKET_PATH}")
        print(f"[FaceAuth] Waiting for PAM authentication requests...")

        try:
            while self.running:
                try:
                    conn, _ = server.accept()
                    thread = threading.Thread(
                        target=self._handle_client,
                        args=(conn,),
                        daemon=True
                    )
                    thread.start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            print("\n[FaceAuth] Server stopping...")
        finally:
            server.close()
            if os.path.exists(SOCKET_PATH):
                os.unlink(SOCKET_PATH)
            logger.info("FaceAuthServer stopped.")

    def stop(self):
        self.running = False


# ── Programmatic client (used by ExecutionController) ────────────────────────

def request_face_auth(timeout_s: float = 10.0) -> Tuple[bool, str]:
    """
    Client function — sends an auth request to the FaceAuthServer.
    Called by ExecutionController when a command requires_sudo=True.

    Returns (success, reason).
    """
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout_s)
        sock.connect(SOCKET_PATH)

        request = json.dumps({
            "action": "authenticate",
            "user": os.environ.get("USER", "ubuntu")
        }).encode("utf-8")

        sock.sendall(struct.pack(">I", len(request)) + request)

        raw_len = sock.recv(4)
        msg_len = struct.unpack(">I", raw_len)[0]
        response = json.loads(sock.recv(msg_len).decode("utf-8"))
        sock.close()

        return response.get("success", False), response.get("reason", "No reason")

    except FileNotFoundError:
        return False, (
            "Face auth server not running. "
            "Start with: python3 executor/face_auth.py --server"
        )
    except socket.timeout:
        return False, "Face auth server did not respond within timeout."
    except Exception as e:
        return False, f"Face auth connection error: {e}"