# Integrated candidate progress

Branch: codex/cloud-handoff-2026-11-02. Local commits only; no deployment or push.

- Completed implementation: A ordinary-user install; B bounded broker/OS-auth path;
  C natural-language preview, durable jobs, authenticated user agent and Qt client;
  D independent sensor transport, deterministic incidents and live Security state;
  E scoped response/policy/native-provider path with independent root enforcement.
- Actual automated results: latest Windows 162 run/3 skips; native WSL 186 run/8
  skips. Agent IPC and real unprivileged operations passed. B target auth is mocked.
- G implemented: protected face enrollment/provider, trusted password fallback, voice-to-preview; camera/spoof/WER acceptance pending.
- Current work: H integrated packaging, installed candidate verification and complete evidence matrix;
  F Python/dev-device/local remote-peer native workflows passed (4 tests).
  F broader recipes/resources and real vendor/SSH acceptance remain partial.
- Acceptance pending: A systemd/Cloud/new CI; B real polkit fixture; C physical
  desktop/auth/fresh install; D–H target kernel/device/model/load/owner tests.
- Continue without owner testing. Existing 1–72 requirements plus expanded scope
  remain in REQUIREMENTS_TRACEABILITY.md; no gate is PASS based only on mocks.

Checkpoint inputs: operations/{broker,agent,jobs,store,supervised}.py,
ai/local_planner.py, ui/desktop.py, deployment/, docs/{BROKER,APPLICATION}.md.
Commands: Windows .venv-windows\Scripts\python.exe -B scripts/test.py offline;
Linux .venv/bin/python -B scripts/test.py all; optional Qt with
QT_QPA_PLATFORM=offscreen LINXAI_TEST_DESKTOP=1 python -B -m unittest tests.test_desktop -v.
Next dependency: package the integrated source/trusted bundle; verify fresh ordinary-user
wheel and agent/desktop workflows. Inspect scripts/{install_app,package_trusted,run_gate_a_lab}.py,
then update full requirements matrix and explicit residual implementation gaps. Do not
report broader F recipes/predictive resources or biometric assurance as complete.
