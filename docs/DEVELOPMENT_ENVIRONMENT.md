# Reproducible application development environment

Updated 2 November 2026. This repository setup is lightweight and does not run
the inherited system installer. Final deployment is an ordinary-user Linux desktop
application with separately supervised privileged components. Cloud/WSL/hosted CI
are development environments, not proof of desktop, hardware or kernel acceptance.

## Install and start

Use CPython 3.11–3.13 with `venv`/`ensurepip` available. Ubuntu 24.04 with Python
3.12 is the Linux environment exercised during this handoff. Python 3.11/3.12 are
in the hosted CI matrix; 3.13 compatibility is declared but not validated here.

```sh
python3 scripts/setup_dev.py
.venv/bin/python -B scripts/test.py offline
.venv/bin/python -B scripts/test.py linux
.venv/bin/linxai --help
.venv/bin/linxai memory.usage
```

The console entry points `linxai` and `linxai-ops` deliberately call the existing
typed `operations.cli`; they do not initialize the legacy AI pipeline. Service
mutations continue to return `authentication_authorization_required`. Read
`OPERATIONS_SERVICE.md` for private audit-directory and workspace prerequisites.
The final command requires an ordinary Linux account and a safe writable audit
location; Windows and root contexts are not supported application execution.

Setup uses pinned uv 0.13.3, `pyproject.toml` and `uv.lock`. If a matching host uv
exists it is reused; otherwise pinned uv is bootstrapped inside the venv using
that interpreter's pip. Host Python/packages are never replaced. `uv sync --locked`
fails when the manifest and lock disagree. First setup needs PyPI package access;
after caches are populated, `python3 scripts/setup_dev.py --offline` checks reuse.
No automatic Python version downloads occur. Re-run setup after changing the lock.

For Windows, use `python scripts/setup_dev.py --venv .venv-windows` and
`.venv-windows\Scripts\python.exe -B scripts/test.py offline`. Windows checks do
not establish Linux acceptance. Never share one venv between Windows and Linux.

For WSL on a mounted Windows checkout, use a native Linux environment path if
DrvFS denies venv chmod/symlink operations:

```sh
python3 scripts/setup_dev.py --venv "$HOME/.cache/linxai-development/app-venv"
"$HOME/.cache/linxai-development/app-venv/bin/python" -B scripts/test.py linux
```

If editable-package metadata writes are also denied on the mounted checkout, put
the **checkout as well as the venv** on native Linux storage. After publication,
clone the handoff branch/commit there. Before publication this handoff used a
manifested snapshot of all selected tracked and untracked files, not stale HEAD.
Check its hashes before testing and never overwrite the selected source with it.

That selects a dedicated app environment; do not chmod/chown the Windows source
mount, edit `/etc/wsl.conf`, or weaken Git ownership checks as a workaround. This
handoff encountered that DrvFS limitation and used an ordinary user's native WSL
cache directory. Any partially created `.venv-linux` remains ignored and unneeded.

## Declared dependency profiles

| Profile | Locked Python inputs | Boundary |
| --- | --- | --- |
| Default application | PyYAML 6.0.3, psutil 7.1.3 | Typed operations themselves remain stdlib-only; these support inherited configuration/resources |
| Development | uv 0.13.3 | Isolated lock/sync tooling |
| Test | Python standard-library unittest; no extra PyPI test framework | Deterministic HTTP/model/process doubles and disposable files |
| `ai` | requests 2.32.5 and locked transitive dependencies | Local Ollama HTTP adapter; does not install/start Ollama or pull weights |
| `desktop` | PySide6 6.10.0 and locked Qt inputs | Candidate toolkit only; owner has not confirmed it as final framework |
| `remote` | Paramiko 4.0.0 and locked transitive inputs | Legacy remote module; routing/host-identity acceptance remain incomplete |
| `hardware` | numpy 2.2.6, opencv-contrib-python 4.12.0.88 | Face prototype; no enrollment/camera capture at install/start |
| `voice` | faster-whisper 1.2.1, webrtcvad-wheels 2.0.14, sounddevice 0.5.3 | Candidate dependencies; voice pipeline source still missing, no automatic weights/audio capture |
| `sensor` | No PyPI package; OS profile in `requirements/sensor-os.json` | BCC belongs to the sensor OS/interpreter, not the app venv |

Request extras explicitly, for example `python3 scripts/setup_dev.py --extra ai`.
Routine setup does not install desktop/hardware/voice/AI extras. All Python
transitive versions, sources and artifact hashes are in `uv.lock`; optional extras
were resolved, not all installed or accepted. No LangChain/LangGraph dependency is
added merely because older documents claim a workflow that is absent in source.

The sensor must use OS-compatible bindings, for example Ubuntu's `python3-bpfcc`
with `/usr/bin/python3`, plus BCC tools/headers appropriate to that actual kernel.
Do not `pip install bcc` or enable system-site-packages in the application venv.
Sensor provisioning/version capture is a separate, explicitly authorized lab task.
Matching kernel version strings, root UID, BTF or CONFIG_BPF flags do not prove
permission to attach hooks, working enforcement, or control of a dedicated kernel.

## Test groups and opt-ins

```sh
.venv/bin/python -B scripts/test.py offline
.venv/bin/python -B scripts/test.py linux
.venv/bin/python -B scripts/test.py all
```

`offline` lists only the 109 preserved regressions plus setup contracts. No broad
repository discovery imports historical install/attack tests. `linux` exercises
native df/free/ss, private audit/creation, confinement and approval denials as an
ordinary user; service status is read-only and skips without a running systemd.
Its temporary assets live under the existing user's safe home and are cleaned up.
Root execution skips these tests rather than bypassing the application's identity
policy or creating a privileged test account.

Optional groups remain skipped without a separate explicit environment flag:

```sh
LINXAI_TEST_PRIVILEGED=1 .venv/bin/python -B scripts/test.py privileged
LINXAI_TEST_DESKTOP=1 .venv/bin/python -B scripts/test.py desktop
LINXAI_TEST_HARDWARE=1 .venv/bin/python -B scripts/test.py hardware
LINXAI_TEST_MODEL=1 .venv/bin/python -B scripts/test.py model
```

Privileged currently tests the OS interpreter's BCC prerequisite and reports the
approved enforcement scenario as pending; it never installs/attaches a probe.
Desktop tests a candidate Qt runtime, not an implemented desktop workflow. Hardware
may open a camera only when explicitly opted in; voice/WER acceptance remains
pending. Real-model smoke uses an already installed loopback Ollama model only;
unavailable service/weights are skipped, never started/downloaded. Missing optional
capabilities are skipped with reasons. Present capabilities with incorrect behavior
fail tests; existing assertions are not weakened to make the environment pass.

## CI and capability evidence

`.github/workflows/linux.yml` runs locked setup, offline regressions and unprivileged
integration on ordinary Ubuntu 24.04 hosted runners for Python 3.11/3.12. It records
optional skips and uploads a passive capability report. The workflow is source
prepared here; a hosted result is not claimed until this branch is pushed and CI runs.

```sh
.venv/bin/python -B scripts/capabilities.py --output capabilities.json
```

This records OS/Python/tooling/identity, PID 1/systemd, configured GUI sockets,
camera nodes, kernel configuration/BTF/capability evidence, optional import presence,
Git revision/status and SHA-256 of all eight operations modules. It never loads
BPF, starts a model/service, opens a camera or changes host security settings.
See `CAPABILITY_REPORT_2026-11-02.md` for measured local results and remaining gaps.

## Legacy deployment boundary

Do not run `sudo bash install.sh`, `modules/install-*.sh` or the PAM installer as
Cloud setup. They mutate packages/services/authentication, use unpinned system pip
and still contain sudo launchers incompatible with ordinary-user app startup. The
new isolated console launcher is tested independently; repairing the old system
installer and independent sensor transport remains acceptance gate A work. No
routine setup may silently install a root GUI or claim observation is prevention.
