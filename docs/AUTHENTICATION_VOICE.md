# Account-bound authentication and voice

Status: **IMPLEMENTED—LAB ACCEPTANCE PENDING**, with biometric assurance PARTIAL.
The ordinary desktop/model never receives passwords or grants privileges. Service
and response operations still traverse the original registry, service and broker.
The broker tries the protected face mechanism only for an already independently
allowed action. Every face failure/unavailability falls back to trusted polkit;
enrollment/revocation always requires polkit. No PAM files are changed.

`auth.face.enroll` and `auth.face.revoke` take **empty parameters**. OS peer UID,
configured root owner UID, exact operation ID and digest are backend derived.
Caller UID, image/template, password and authenticated booleans are rejected.
Mandatory checks include Linux, trusted executable, independent account scope
and bound authorization. Fixed argument arrays invoke the protected mechanism.
Successful exit alone is insufficient: protected enrollment state is inspected.
Recovery is unsupported; a failed/uncertain enrollment requires review.

The root face service has a protected socket and bounded workers/capture process.
Only root can request enrollment/authentication; the configured owner can inspect
status/challenges. Templates are per UID, root-owned 0600 and never stored in the
repository. A shared file lock excludes concurrent camera processes. Raw frames
remain in memory; only profile/provider hashes and results persist. Account,
nonce, exact operation, provider/template and short expiry bind each proof.
Attempts are throttled, nonce admission is durable and bounded. Re-enrollment or
revocation invalidates qualification. Wrong account/match/liveness/challenge,
stale proof or missing camera never grants permission.

Primary face authentication defaults **off** in `deployment/face.example.json`.
It additionally requires protected real-camera qualification, expiring after
24 hours and bound to the template, OpenCV version and capture/recognizer source.
The reused LBPH/optical-flow plus direction heuristic has **no demonstrated spoof
resistance**. Single labelled lab trials are preliminary evidence, not biometric
assurance or a production security certification. Keep primary disabled unless
the target's required assurance and repeated spoof trials have been accepted.
The password path remains usable when qualifications fail/expire.

The separate protected interpreter prerequisite declaration is `requirements/face-os.json`.
The ordinary Python environment's `hardware` extra is for development only.
Protected capture uses `/usr/bin/python3` and independently provisioned OS OpenCV
contrib/NumPy; it never imports an ordinary-user venv. Check explicitly on target:

```sh
/usr/bin/python3 -I -c 'import cv2,numpy; print(cv2.__version__); assert hasattr(cv2,"face")'
```

After protected bundle/config review in a disposable target lab, use the desktop
enrollment preview and trusted password prompt. The separately runnable suite is
`LINXAI_TEST_HARDWARE=1 /usr/bin/python3 -I -B scripts/accept_face.py` as a trusted
lab administrator. It forwards to the root-owned bootstrap, prompts for labelled
owner/wrong-person/photo/video presentations and camera removal, performs actual
captures and stores observations. It does not enable primary authentication or
install/change PAM. A fixture label is an operator observation, not proof supplied
by AI. Real enrollment, all spoof cases, account isolation and actual polkit
success/cancellation must still be run; none ran on this Windows/WSL host.

Voice is an ordinary-user input path. Start the desktop with `--voice-model` set
to an existing absolute local faster-whisper model directory. Explicitly install
the pinned `voice` profile (`scripts/setup_dev.py --extra desktop --extra voice`).
Routine startup neither downloads weights nor opens a microphone. Clicking Voice
captures at most 15 seconds of 16kHz PCM, uses VAD, rejects overflow/silence and
transcribes locally in a supervised 45-second subprocess. Only bounded text
enters the existing preview API; confirmation and all mandatory checks still
apply. Editing input invalidates late asynchronous previews/transcripts.

Opt-in actual microphone/WER command:

```sh
python -B scripts/accept_voice.py --help
LINXAI_TEST_HARDWARE=1 python -B scripts/accept_voice.py --model /absolute/local/model --reference 'restart nginx service'
```

Record equipment, language/accent, repeated technical-vocabulary corpus and actual
WER; the current runner reports observed edit distance and a 15% trial threshold.
No microphone or WER measurement was performed here. Deterministic tests cover
VAD framing/silence, bounded local-only decoding, WER arithmetic and voice-to-preview;
they are not hardware evidence.

Official API references used: [OpenCV LBPH](https://docs.opencv.org/4.13.0/df/d25/classcv_1_1face_1_1LBPHFaceRecognizer.html),
[sounddevice raw streams](https://python-sounddevice.readthedocs.io/en/0.5.3/api/raw-streams.html),
[faster-whisper](https://github.com/SYSTRAN/faster-whisper),
[polkit mechanism guidance](https://www.freedesktop.org/software/polkit/docs/latest/polkit-apps.html).
