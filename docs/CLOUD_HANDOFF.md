# LINxAI self-contained development handoff

Prepared 2 November 2026. Selected working source was verified at
`E:\FYP\code 2\linxai`; preserve `E:\FYP\code` and its backup as historical
recovery sources. Development is continuing, not restarting or replacing the backend.

## Repository and reproducibility

Intended existing remote: `https://github.com/Sabih0610/linxai.git`.
Handoff branch: `codex/cloud-handoff-2026-11-02`. Load the handoff commit on that
branch, not the old `main` at `51e54c6888bddcfec07cd544acc295b3ce833e45`.
The exact final commit and remote publication result are in the local handoff
delivery; verify `git rev-parse HEAD` in every new task. A commit cannot embed its
own hash; the checked-out commit identifies these documents and all included source.

At inspection, main had seven modified tracked files and substantial untracked
registry/service/tests/docs. Those files are application inputs, not optional
scratch work. The handoff commit includes them together with dependency/setup/CI
inputs. Do not use the old SHA alone to claim that the current service is deployed.
No history rewrite, destructive reset or new public repository is required.

Required reproduction inputs are all checked-in Python/C/PAM/probe source,
`config/` examples, ordinary-user deployment scripts and historical unit templates (not provisioned by routine setup), the three original regression modules, new setup/integration tests,
`pyproject.toml`, `uv.lock`, `scripts/`, `.github/workflows/linux.yml`, `AGENTS.md`
and repository documentation. Source imports/runtime C probes are retained; empty
`voice/` is not a missing Git artifact—its runtime implementation has not been recovered.
Downloaded models, credentials/keys, biometric samples, runtime JSONL/SQLite data,
venvs, caches and unrelated chat/output files are intentionally not reproduction inputs.

## Read order for a new task

1. `AGENTS.md` and this document.
2. `ARCHITECTURE_REVIEW_2026-11-02.md`: the supplied architecture review preserved
   with only redundant EOF whitespace normalized, with findings, target architecture and acceptance gates.
3. `DEVELOPMENT_ENVIRONMENT.md`, `CLOUD_SETUP.md`, `CAPABILITY_REPORT_2026-11-02.md`.
4. `ACTION_CONTRACTS.md`, `OPERATIONS_SERVICE.md`, current implementation and
   verification records. Read the actual modules before editing them.
5. `REQUIREMENTS_INVENTORY.md` and `REQUIREMENTS_TRACEABILITY.md`; keep original IDs.

No previous chat, local skill, Windows folder or original temporary attachment is
needed to understand the agreed work. Use repository-relative paths from the new
checkout. Local capability evidence is not evidence of the new Cloud host.

## Agreed full scope and target

Deliver an ordinary-user **Linux desktop application** for Linux administration,
DevOps, network engineering and security/SOC work. Windows/Multipass/WSL are current
development arrangements, not the final desktop deployment target. Ubuntu 24.04 /
Python 3.12 is an exercised development combination; full supported distribution,
desktop, camera and kernel acceptance remains gate A. PySide6 is a proposed toolkit,
not a previously confirmed UI framework decision. Router/switch vendor/emulator
selection is still an owner input; do not claim an unsupported vendor adapter.

Retain text and voice goals, local Ollama reasoning, context/cache, deterministic
fast paths, typed plans/actions, live state validation, independent authentication/
authorization, operation approval, bounded execution, verified outcomes, recovery
where supported, resource management, remote Linux/VPS and supported network devices.
The desktop needs assistant, operations/tasks, assets, security and activity views.
The CLI remains a compatibility interface. The product does not call cloud AI by
default merely because development runs in Codex Cloud.

Background capture, deterministic detection, incident handling and installed
protection must continue while the UI is closed or the model is busy. Adaptive
protection means observe/recognize/reason/propose/authorize/respond/verify, then
validate and retain a scoped, versioned, expiring/revocable response policy for
matching recurrence. Validate benign near-matches before policy promotion.
Known policies may enforce at supported hooks without a model call. A novel threat
has a separate measured reasoning/containment delay; post-event signals do not
prove prevention of the triggering syscall. No universal first-operation prevention
or nanosecond-latency claim is accepted without corresponding evidence.

Keep model/UI unprivileged. Administrative work requires a narrow broker and trusted
OS authorization, then account-bound face enrollment/spoof checks with a password
fallback. A boolean, user-writable face socket, model risk label, cached plan or raw
shell command cannot authorize root. Incident/output/file/remote text is untrusted
evidence. One existing registry/service vocabulary remains the operation core.

The original 1–72 inventory remains required coverage, with added desktop/network/
adaptive-policy acceptance. The proposal's 28 November 2026 delivery target is
historical planning, not proof of completion or a new implementation guarantee.

## Current capability and gap matrix

| Area | Present source/behavior | Remaining acceptance gap |
| --- | --- | --- |
| Typed operation registry | Nine immutable contracts, validated parameters, server-defined privilege/checks/argv/timeouts/postconditions | Broader action coverage and trusted broker contracts |
| Shared service | Six unprivileged paths; OS identity/local policy; approval fingerprints/single-use expiry; exact argv shell=False; verification and correlated private ledger | Durable jobs, cancellation, crash reconciliation, authenticated IPC, restoration and native platform breadth |
| Administrative services | start/stop/restart return `authentication_authorization_required` | Password-backed broker, lab service authorization/verification; preserve hard block until then |
| CLI | Explicit `--operation` and standalone typed CLI call the service before model initialization | Legacy natural-language/interactive/setup/nginx/export/retry/remote paths remain separate and must be migrated |
| Local AI | Direct Ollama HTTP, prompts, schema validation, fast paths, cache/SQLite context | Held-out model/latency evaluation, lifecycle/configuration; no demonstrated LangGraph graph |
| DevOps/network/remote | Existing environment recipes, local network helpers and standalone Paramiko module | Typed jobs, host identity, idempotency, rollback; selected vendor lab adapter |
| Security/SOC | BCC execve/connect/openat source, lost-event counters and heuristic alerts | Independent collector owner/readiness/transport, incidents, tested background detection and enforcement |
| Adaptive prevention | Agreed architecture and acceptance requirements | AI response-policy store, safe promotion, authenticated deployment, recurrence enforcement, benign tests and revocation |
| Face/PAM/voice | Face/PAM prototype and installers; voice runtime absent | Trusted account-bound identity/liveness/fallback; actual voice capture/transcription/WER |
| Resource/audit | Legacy psutil/JSONL/SQLite; new correlated operation ledger | Stable process identity, measured benefit, retention/ownership, cross-module correlation and durable state |
| Desktop/packaging | Isolated safe typed CLI setup and optional candidate toolkit profile | Desktop app, legacy installer root mismatch, final install/upgrade/uninstall and service isolation |

Read `CAPABILITY_REPORT_2026-11-02.md` for current local measurements. Presence of
production adapter code is not a claim that every native action/platform passed.

## A–H acceptance roadmap

| Gate | Build or repair | Required completion evidence |
| --- | --- | --- |
| A Runnable Linux baseline | Selected source/revision, supported Python/BCC setup, installer/root mismatch, final desktop/camera/kernel feasibility | Source fingerprints on Linux; all six unprivileged smoke actions; root rejection and ordinary launcher; supported environment report |
| B Privileged operations | Authenticated broker, password-backed OS authorization, three bounded service mutations and exact-operation binding | Correct user succeeds on a lab service; denied/cancelled/wrong-user/replayed/altered requests never dispatch; correlated verification/audit |
| C First complete desktop workflow | Natural language through adapt_plan/service, durable jobs, thin application | Request -> preview/auth -> progress -> verified result; no shell fallback; status survives UI restart |
| D Independent security/SOC | Sensor ownership, background consumer, normalized events/incidents, readiness/errors and Security view | Controlled benign/suspicious workloads; no duplicate collector; visible loss/degradation; monitoring survives model load and app closure |
| E Adaptive prevention loop | Bounded AI response, verified containment, policy validation/persistence/installation/revocation | First lab incident verified; recurrence denied without model; benign near-match allowed; expiry/revocation and enforcement evidence |
| F DevOps and network breadth | Existing recipes as typed jobs, remote Linux, one selected router/switch platform | Safe repeatable setup; honest prerequisite failure; host identity; lab diff/apply/verify/recovery |
| G Face and voice | Bound enrollment/authentication, spoof testing, password fallback, missing voice source | Owner/wrong-user/photo/video/unavailable-camera cases; trusted fallback; measured technical-vocabulary WER |
| H Release and academic evidence | Integrated/load tests, packaging, measured performance, report/manual/demo/slides | Fresh-target installation/demo; requirement-to-test evidence; signed-off remaining limitations |

Gate A is only partially advanced by this setup. WSL/CI cannot certify final native
desktop, independent sensor or enforcement. De-risk camera/kernel feasibility early.
Keep the old numbered build sequence as historical planning; these lettered gates
are the current acceptance roadmap. Do not equate test-method count with 72 feature
acceptances or a completion percentage.

## Verification history and current evidence

Historical evidence: 1 November foundation suite 41 tests; registry slice 72; service
slice 109; 2 November architecture review 109 tests / 49 Python files parsed. Those
were Windows offline/mocked runs (including selected disposable-file checks), not
Linux integration or performance benchmarks. Older SRS/poster test counts and
“complete” labels remain historical in the inventory. They do not certify safety,
kernel prevention, hardware behavior or current all-module integration.

Current handoff runs and actual environment limitations are recorded separately in
`CAPABILITY_REPORT_2026-11-02.md` and appended to `VERIFICATION.md`. Run them afresh
in Cloud/CI; do not relabel historical reports as new tests. The historical Multipass
mount `E:\FYP\code -> /opt/linxai` and access-denial findings remain unresolved;
an accessible WSL checkout does not prove the Multipass guest has this revision.

## First Cloud task instructions

Verify repo/branch/SHA, inspect Git status and preserve all work. Run locked isolated
setup and the offline/native eligible tests. Inspect the new environment's UID,
service manager, GUI/devices and kernel evidence without host changes. Keep missing
capabilities skipped/pending. Do not use `install.sh` as routine setup. Do not start
or download Ollama/models, install PAM, enable services or load BPF as side effects.

Continue gate A: repair the inherited sudo launcher/root-rejection mismatch through
the ordinary-user packaging path, define independent sensor ownership/readiness and
authenticated event-ingestion contracts, and establish the selected lab/runtime.
Then implement gate B using the existing registry/service. Never build another
backend or wire the face prototype's success boolean directly to root execution.
Migrate one whole natural-language workflow before expanding UI or device breadth.

For each change define behavior/acceptance, reproduce the defect, implement one
coherent slice, test supported and negative cases, inspect the diff and update
requirement-linked evidence. No commit, setup script or local-root privilege is
proof that an application feature or acceptance gate is complete.


## Gate A continuation

Read INSTALLATION.md and GATE_A_BASELINE.md for the replaced ordinary-user installer, actual current evidence and pending systemd/Cloud acceptance. The original handoff results above remain historical. Continue the registry/service, not a second backend. New Gate A working changes must be committed/published explicitly before Cloud can load them; the checked-out SHA alone does not include uncommitted work.
