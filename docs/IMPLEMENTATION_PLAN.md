# Current execution status — integrated candidate (2 November 2026)

This section governs continued implementation; older entries below are historical.
Owner acceptance will occur after an integrated candidate exists. Unavailable
Gate A checks do not block independent B–H development. Continue autonomously with
focused local commits; do not publish/deploy or modify host security as a test side effect.

Track three independent dimensions for every area:
1. Implementation complete: production path and error handling exist end to end.
2. Automated verification complete: applicable deterministic/native tests actually ran.
3. Target-system/hardware acceptance pending: unrun real authentication, kernel,
   device, desktop, model or deployment tests remain explicit acceptance gaps.
A gate is PASS only with all required acceptance evidence; code plus mocks is not PASS.

| Gate | Implementation | Automated verification | Target acceptance |
| --- | --- | --- | --- |
| A | Typed app installation implemented | Windows 125 run/2 skips; WSL combined 142 run/7 skips (historical prior turn) | systemd success, Cloud/new CI pending; does not block B–H |
| B | Bounded service broker production path implemented | Windows contracts and WSL 155-test combined run passed (7 skips); final failure-case addition verified separately | Real polkit/service lab pending |
| C | Planner → preview → durable job → service/broker → result implemented; Qt client and guarded launchers | Windows 144/3 skips; WSL 168/8 skips; Qt offscreen workflow passed separately (1 test, 4.717 s) | Physical desktop, real OS-auth and installed target acceptance pending |
| D | Protected independent capture, normalized identity/loss, deterministic monitor/incidents and Security view implemented | Windows 151 run/3 skips; WSL 175 run/8 skips passed | Actual BCC compilation/capture/loss/lifecycle and target privilege hardening pending |
| E | Scoped response → broker → independent policy authority/native adapter → verified policy → recurrence/expiry/revoke implemented | Windows 162 run/3 skips; WSL 186 run/8 skips passed; all enforcement effects simulated | Actual BPF LSM qualification, response/recurrence/benign/revoke and OS auth acceptance pending |
| F | Planned: typed recipes, remote/device development adapter | Pending | Chosen platform/remote/device lab pending |
| G | Planned: account-bound face provider/fallback and voice | Pending | Biometric spoof/camera/microphone/WER pending |
| H | Planned: packaged integrated candidate and full evidence matrix | Pending | Fresh target, sustained load and owner acceptance pending |

Current checkpoint: preserve and commit Gate A; implement B using the existing
registry/OperationService, trusted peer identity and a root-owned deployment path.
Keep the full original 1–72 inventory and expanded desktop/network/adaptive scope.

# LINxAI implementation plan

Updated 1 November 2026 after the owner clarified the complete product scope.

## Product outcome

Deliver a Linux desktop application for Linux administration, network engineering,
DevOps and security operations. It accepts text/voice goals, inspects target state,
plans typed actions, authenticates privileged work, executes through shared policy,
verifies outcomes and displays correlated evidence. Background kernel monitoring
and installed protection policies continue when the UI or model is unavailable.

The owner explicitly confirmed adaptive protection: observe, recognize, reason,
respond, verify, store a scoped response policy and reuse it for matching incidents.
Known policies provide immediate enforcement at supported hooks. A novel threat
requiring model judgment has a separate measured reasoning/containment delay.
The system cannot guarantee prevention of a first harmful operation when no
applicable prior protection exists. Nanosecond timestamps are not detection latency.

The earlier 72-item feature inventory remains required reporting coverage. The desktop
application, network-device adapters and adaptive enforcement architecture expand
that inventory and require additional acceptance criteria.

## Repository and environment

- Working source: E:\FYP\code 2\linxai, starting at local main 51e54c6.
- Preserve E:\FYP\code and E:\FYP\backup\code for test/demo recovery.
- Intended runtime: Linux with Multipass used for the current development VM.
- Recorded VM: linxai-dev; historical mount E:\FYP\code -> /opt/linxai.
- The mount is not verified. Windows denied execution of Multipass even during
  an elevated read-only attempt on 1 November. Do not assume the latest folder is deployed.
- The final delivery date of 28 November 2026 is the original proposal target.

## Current capability map

| Capability | Reusable implementation | Remaining work |
|---|---|---|
| Local reasoning | Ollama/Qwen, prompts, fast paths, cache, SQLite context | Model evaluation, strict action semantics, configuration and lifecycle |
| Linux operations | CIE checks, deterministic builders, executor and output analysis | Typed registry, independent privilege policy, final-operation validation, safe recovery |
| DevOps | Repository installation, MERN/Python setup recipes and capability checks | Shared operation service, isolated environments, idempotency, real acceptance evidence |
| Kernel monitoring | execve/connect/openat probes, filtering and lost-event counts | Readiness, ownership, event identity/return status, actual-kernel testing, latency/loss measurement |
| Threat response | Optional hardcoded process termination, default disabled | Independent detector, incident correlation, AI action selection, scoped policy memory, enforcement and outcome verification |
| SOC workflows | Security alerts, JSONL records, explanations and some context feedback | Incident lifecycle, evidence collection, triage, operator controls and scoped response playbooks |
| Networking | Local ports, interfaces, firewall-oriented intents; generic SSH module | Explicit Linux network actions, inventory and vendor/device adapters, configuration diff/rollback/verification |
| VPS | Standalone Paramiko manager | Main routing, host identity verification, unified policy/configuration and output/deadline repair |
| Privileged identity | Face/OpenCV and PAM source; existing sudo handling | Dedicated privilege broker, account-bound enrollment, spoof testing, trusted password fallback |
| Desktop application | Terminal helpers only | Application shell, assistant/tasks/assets/security/activity screens and service transport |
| Voice | Installer and documentation | Recover or implement missing source, integrate input and measure microphone WER |
| Resources/audit | Renicing, metrics, JSONL and SQLite | Stable process identity, measured benefit, storage ownership/retention and shared operation IDs |

The current threat responder is not an AI response engine. Sending a signal after
an alert is not proof that the triggering file access or network operation was denied.

## Foundation fixes prepared and applied in this change

1. Unknown, malformed, failed and incomplete declared CIE checks block execution;
   checks that finish after the budget also block. Register port_range/process_count.
2. Validate generated/cached plan types, supported intents, bounded strings, ports
   and condition structure before downstream use; ignore malformed cached plans.
3. Preserve supported conditional service actions and port prerequisites; unsupported
   conditional requests decline rather than reusing a stale unconditional cached plan.
4. Prevent model-provided rollback strings from executing automatically; surface the
   need for validated state-based recovery. This intentionally changes prior behavior.
5. Reject absent/unknown validation outcomes at ordinary/retry CLI execution gates.
6. Replace POSIX preexec_fn process-group setup with start_new_session.
7. Repair one malformed JSON prompt example and add an offline regression suite.
8. Load public AI exports lazily so pure helpers do not require the HTTP/model stack.

These fixes do not establish a complete security boundary. Empty declared-check
lists can still approve; mandatory checks must move to the action registry. Shell
execution, guard bypasses, setup/nginx/export shortcuts and privileged UI behavior
remain unresolved. The validation budget detects overruns after a synchronous
check returns; it does not cancel a slow check in flight.

## Build sequence and acceptance gates

### 0 Verify the runnable baseline

Inspect the actual guest, OS/kernel, model and packages. Prove which revision is at
/opt/linxai, then align the mount/deployment deliberately. Record a baseline and
recover useful historical tests/demos without running their mutating scenarios.
Done when: exact environment/revision/mount and reproducible startup are recorded.

### 1 Establish the shared operations service

Extract operations from main.py. Add typed actions, server-selected privileges,
operation-derived checks, final-operation approval, trusted authentication, one
execution path, state-based recovery and operation IDs. Remove generic shell
execution from the trusted path for supported actions. Cover wrappers, critical
descendants, exports, setup, retries and rollback in negative tests.
Done when: rejected or unverifiable actions never start; successful operations have
verified postconditions and traceable recovery evidence. UI/model stay unprivileged.

### 2 Deliver the first desktop workflow

Proposed UI toolkit: PySide6, retaining Python backend modules. This is a
recommendation, not a previously confirmed framework choice. Build assistant,
task progress/approval and activity views against the operations service. Preserve
CLI compatibility. Use authenticated local IPC/service access and event streaming.
Done when: a service/file/environment task works through the app, including a
blocked condition and visible failure recovery. Closing the window does not stop monitoring.

### 3 Make monitoring and incident handling reliable

Choose one collector owner, publish readiness/errors, normalize events and correlate
process identity, lineage and return evidence. Add incident records, rule versions,
deduplication, benign exceptions and evidence views. Measure event loss, false alarms
and event-to-rule/event-to-alert delays independently of model latency.
Done when: controlled benign/suspicious workloads yield correct, nonduplicated
incidents; unavailable monitoring is reported; the detector remains responsive under model load.

### 4 Implement adaptive response and enforcement

Define typed response actions and owner-configured automatic-action limits. The AI
consumes bounded incident evidence and proposes a structured response; independent
policy checks validate it. Verify actual outcome before storing any reusable policy.
Policies carry conditions, asset scope, action, provenance, version, expiry and revocation.
Use appropriate supported enforcement hooks for denial rather than confusing a
post-event process signal with prevention. Keep persistent policy memory separate
from conversation history and command cache.
Done when: an unfamiliar lab incident gets a verified bounded response; a repeated
matching incident is blocked through an installed policy without waiting for the
model; a similar benign event does not trigger it; expiry/revocation works.

### 5 Add network and remote infrastructure workflows

Separate TCP/UDP ports, Linux interfaces and physical switch ports. Define a device
inventory and capability model. Start with Linux networking plus one lab router/switch
platform; add read state, preview changes, backup/diff, apply, connectivity verification
and supported rollback. Integrate remote Linux actions through the shared policy.
Done when: a lab change is verified end to end and a failed change recovers without
losing management access. Show precisely which platforms/actions are supported.

### 6 Complete identity, voice and DevOps coverage

Finish account-bound face enrollment and spoof testing, retain trusted password
authentication, and verify on hardware that exposes the required camera. Implement
the missing voice input and vocabulary tests. Complete environment/deployment
recipes and resource tuning with repeatability and measurement.
Done when: owner/other-user/spoof/fallback cases and required voice/DevOps workflows
have recorded acceptance results. Existing optional modules are not called complete by inference.

### 7 Validate and package the FYP

Run requirement-linked unit/integration/security scenarios and sustained-load tests.
Measure accuracy, false blocks, threat precision/recall, event loss, latency percentiles,
resource overhead and recurrence-policy effectiveness. Update SRS/SDS, 72-item status,
desktop/network/security additions, user manual, demo, slides and deployment package.
Done when: the supported scope can be installed and demonstrated on a fresh target
with reproducible evidence and explicitly documented limits.

## How to continue with Codex

Open this exact repository as the working project. Read AGENTS.md, this plan and
docs/VERIFICATION.md at the start of a milestone. Implement the next bounded milestone,
run its acceptance checks, inspect the diff and update the evidence before proceeding.
Use one milestone prompt at a time and retain durable scope/evidence in the repository.
Avoid parallel changes to the same execution or policy modules. No special model or
new chat is required by this plan. Do not change the product's local model just because
Codex is being used to implement it.

Suggested next task: establish the real VM baseline, then implement the typed action
registry and shared operation service. The desktop interface should consume that service.

Official workflow reference:
https://developers.openai.com/cookbook/examples/codex/iterating-development-workflows-with-codex

## Linux checks that remain unrun

- Multipass guest/mount inspection and selected-revision confirmation.
- Real nginx/service conditional success and conflict behavior.
- Ollama responses under normal, cold-start and unavailable conditions.
- BCC compilation, event correctness, readiness, loss and kernel enforcement support.
- Webcam/PAM/password authentication and remote SSH/network-device workflows.
- Full historical acceptance suite and sustained-load benchmarks.


## Typed registry slice implemented on 1 November 2026

The first bounded part of milestone 1 is implemented in `operations/`: nine typed
action contracts for disk/memory usage, TCP/UDP listening-port inspection, service
status/start/stop/restart and workspace file/directory creation. Each preparation
validates parameters, derives mandatory checks independently of model declarations,
selects server-owned privilege requirements, builds fixed argument arrays and
records timeouts, expected postconditions and unsupported recovery.

`adapt_plan` accepts the supported structured legacy plan slots, preserves bounded
conditional TCP constraints and existing service aliases, and rejects unsupported
actions/conditions/configuration requests. It ignores model commands, privilege
claims, risk labels and rollback strings. Workspace creation requires an explicit
backend-owned POSIX root. There is no raw-shell fallback and no new execution,
authentication or authorization path. All prepared actions report execution as
unsupported; declarations are not completed live system checks.

See `docs/ACTION_CONTRACTS.md` for the API, validation rules, check/postcondition
contracts, exclusive unprivileged creation program and migration boundaries.
The existing CLI/CIE/executor and uncommitted foundation fixes are preserved.
Milestone 1 is not complete: live check evaluation, final operation approval,
trusted authentication, controlled dispatch, verification, operation IDs and
state-based recovery remain. Milestone 0 guest identity/source/mount/startup is
still blocked as recorded in `docs/ENVIRONMENT_BASELINE.md`; no Linux integration
claim follows from this offline registry implementation.

Next bounded implementation task: add the fail-closed check/policy preparation
service around these contracts, with authenticated action/target authorization
and final-operation binding before introducing execution or migrating CLI paths.


## Shared operations lifecycle slice implemented on 1 November 2026

`operations/service.py` now consumes the existing action registry rather than
introducing a second action vocabulary. It validates typed requests, resolves OS
identity, applies an independent local UID/action policy, reconstructs final
operations, evaluates mandatory checks, issues expiring single-use approvals,
dispatches the exact bound argv, verifies postconditions and records correlated
results. UUID/fingerprint binding spans validation, execution, verification and
audit, with parameter/target/argv/stdin/check/configuration changes requiring
revalidation. State, identity, policy and expiry are checked again before dispatch.

Linux unprivileged adapters and a fail-reporting private JSONL ledger are in
`operations/system.py` and `operations/audit.py`. All administrative service
mutations return `authentication_authorization_required` until the trusted broker
exists. No client/model flag grants authority, and no raw-shell fallback exists.
The existing six unprivileged contracts have bounded shell=False dispatch and
postcondition handlers; failed checks or verification cannot produce success.
Recovery remains explicitly unsupported because no validated restoration contract
exists. Unconfirmed adapter side effects are reported as unknown, not as no action.

The first migrated CLI workflow is `python3 main.py --operation memory.usage`,
with typed parameter/configuration options and equivalent `python3 -m operations.cli`.
This branch precedes model/legacy pipeline initialization and never falls back to
it. Root/setuid main-app startup is now rejected. Existing natural-language
`--command`, interactive, setup/export/nginx, retry and remote workflows are not
migrated. Their useful source behavior and foundation fixes are preserved.

See `docs/OPERATIONS_SERVICE.md` for API, CLI, authorization, audit, recovery and
migration boundaries. Milestone 1 remains incomplete: privilege broker, authenticated
IPC, broader route migration, crash reconciliation and restoration are outstanding.
The Linux VM/source baseline gate remains unresolved; unit results do not verify
actual guest execution. No VM, mount, installed service, permission, PAM or package
changes were made during implementation/testing.

Next: verify the existing guest/source and supported unprivileged workflows in a
controlled Linux environment, then migrate one legacy request path through the
same service. Keep privileged dispatch blocked while designing the trusted broker.


## Cloud handoff and isolated development setup (2 November 2026)

Prepared the current source, including previously uncommitted registry/service,
foundation fixes, tests and records, on branch `codex/cloud-handoff-2026-11-02`.
`CLOUD_HANDOFF.md` is self-contained; the supplied architecture review is preserved
with only redundant EOF whitespace normalized; original inventory IDs 1–72 and FR source labels are retained with current
traceability. Gates A–H are the acceptance roadmap; old module-complete wording and
test counts remain historical. Final target is an ordinary-user Linux desktop.

Added pinned `pyproject.toml`/`uv.lock`, isolated setup, safe typed console launchers,
explicit offline/Linux/privileged/desktop/hardware/model test groups and ordinary-user
Linux CI. Optional profiles are separate and no routine setup starts Ollama, pulls
weights, opens devices or provisions BCC/PAM/services. Sensor OS/interpreter inputs
are declared separately. README/AGENTS entry points direct new tasks to current docs.

Fresh Windows and ordinary-user WSL evidence is in `CAPABILITY_REPORT_2026-11-02.md`.
Native tests advance the resource/file/port/launcher portion of gate A. The registry,
service, original regressions and useful legacy behavior are preserved. The old
system installer/root-launch mismatch, real systemd acceptance, sensor ownership/
transport, final desktop/hardware/kernel feasibility and trusted broker remain open.
Do not close gate A or implement a competing backend based on the new test count.

Next Cloud task: verify its actual commit/capabilities, run locked setup and eligible
tests, then finish remaining gate A deployment/sensor contracts before gate B.


## Gate A — reproducible ordinary-user application baseline (2 November 2026)

Status: IMPLEMENTED—LAB ACCEPTANCE PENDING. See INSTALLATION.md and
GATE_A_BASELINE.md for contracts, environment matrix, actual checks and pending
acceptance. Replaced the root/global-pip/model/PAM/service installer with an
ordinary-user, locked non-editable application install and guarded typed launchers.
Added safe managed removal, isolated-import verification, installed-wheel lab,
root/argv/missing-tool/service/ownership regressions and passive auth/audio/sensor
capabilities. Reused the registry, OperationService, mandatory checks and exact
approval binding; privileged actions remain broker-required and recovery unsupported.

Current Windows offline: 125 run, 123 passed, 2 POSIX skips. Native WSL offline:
125 passed. Backend and installed-wheel native groups each ran 11 tests: 10 passed,
service.status success skipped for absent systemd. Actual installed root launcher
and root installer both refused startup with exit 2. Neither Cloud nor the updated
hosted workflow was executed for this candidate. Historical 109/116/131 counts
above do not establish current full acceptance. Sensor unit templates are documented as
historical and are not installed; BCC stays on its OS interpreter.

Next concrete task: run the documented six-action installed lab on Ubuntu/systemd,
capture root refusal plus zero skips, then review/publish and run hosted/Cloud
checks where accessible. Gate B's trusted broker follows Gate A acceptance; do not
begin privileged dispatch on the basis of mocked or WSL-only evidence.


## Gate B implementation checkpoint — 2 November 2026

Implemented production broker transport, OS peer identity, root allowlist, polkit
exact-operation authorization, persistent replay admission, service/TCP checks,
verified state, private root audit, bounded supervision and protected packaging.
See BROKER.md. Default OperationService administrative refusal remains intact.
Original IDs 15–26, 29, 58–59 and 63–70 advance partially; no source IDs removed.
Windows broker contracts: 10 run, 9 passed/1 Linux peer skip; real Linux/native
checks follow. Real polkit/service acceptance remains pending without systemd.
This pending target acceptance does not block C–H independent implementation.
