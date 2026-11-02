# Integrated candidate progress

Branch: codex/cloud-handoff-2026-11-02. Local commits only; no deployment or push.

- Completed implementation: A ordinary-user install; B bounded broker/OS-auth path;
  C natural-language preview, durable jobs, authenticated user agent and Qt client;
  D independent sensor transport, deterministic incidents and live Security state;
  E scoped response/policy/native-provider path with independent root enforcement.
- Actual automated results: latest Windows 162 run/3 skips; native WSL 186 run/8
  skips. Agent IPC and real unprivileged operations passed. B target auth is mocked.
- Current work: G account-bound face provider/OS password fallback and voice;
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
Next dependency: extend the existing registry/broker with exact scoped response
actions; validate root-sourced evidence and owner limits before kernel policy mutation.
