# Integrated candidate progress

Branch: codex/cloud-handoff-2026-11-02. Local commits only; no deployment or push.

- Completed implementation: A ordinary-user install; B bounded broker/OS-auth path;
  C natural-language preview, durable jobs, authenticated user agent and Qt client.
- Actual automated results: latest Windows 144 run/3 skips; native WSL 168 run/8
  skips. Agent IPC and real unprivileged operations passed. B target auth is mocked.
- Current work: D independent kernel sensor, deterministic events/incidents and
  Security view; finish C offscreen Qt verification when isolated setup completes.
- Acceptance pending: A systemd/Cloud/new CI; B real polkit fixture; C physical
  desktop/auth/fresh install; D–H target kernel/device/model/load/owner tests.
- Continue without owner testing. Existing 1–72 requirements plus expanded scope
  remain in REQUIREMENTS_TRACEABILITY.md; no gate is PASS based only on mocks.

Checkpoint inputs: operations/{broker,agent,jobs,store,supervised}.py,
ai/local_planner.py, ui/desktop.py, deployment/, docs/{BROKER,APPLICATION}.md.
Commands: Windows .venv-windows\Scripts\python.exe -B scripts/test.py offline;
Linux .venv/bin/python -B scripts/test.py all; optional Qt with
QT_QPA_PLATFORM=offscreen LINXAI_TEST_DESKTOP=1 python -B -m unittest tests.test_desktop -v.
Next dependency: reuse ebpf/daemon.py/probes with independent protected deployment,
normalized stable identity, loss/readiness reporting and background incident storage.
