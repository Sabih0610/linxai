# LINxAI architecture review and completion roadmap

Reviewed 2 November 2026, Asia/Karachi. Source: E:\FYP\code 2\linxai.
This is a read-only application review. No application source, VM, service, permission, package or network-device configuration was changed.

## 1 Architecture verdict

Keep and build on the new operations package. It is a useful foundation: the registry derives mandatory checks and privilege requirements, and the lifecycle service binds validation to the operation being executed.

The project is now a partially implemented application backend with nine typed actions, six unprivileged execution paths and three explicitly blocked administrative actions. It is not yet a fully integrated desktop operations/security application. The old natural-language pipeline and the new service coexist. Do not rewrite the project, and do not interpret the shared-service tests as completion of the legacy migration.

The owner confirmed during this review that the final application runs on a Linux desktop. Windows/Multipass remains the development setup. The router/switch lab platform has not been supplied; a vendor adapter cannot be considered an executable deliverable until its lab target is selected.

The next milestone should combine a runnable Linux baseline and deployment compatibility repair. Follow it with a trusted privilege broker and migration of one natural-language workflow into the existing service. De-risk actual kernel enforcement and camera access early, rather than discovering hardware/kernel incompatibility during final integration.

## 2 What was verified

| Check | Result and boundary |
|---|---|
| Current branch/HEAD | main at 51e54c6888bddcfec07cd544acc295b3ce833e45; substantial later work remains uncommitted/untracked |
| Foundation, registry and service suites | 109 tests passed in 0.651 seconds on the bundled Windows Python runtime |
| Python syntax | All 49 current source/test files parsed successfully |
| Diff whitespace | git diff --check passed; line-ending conversion warnings remain informational |
| Typed contracts | Nine identifiers, as listed below |
| Unprivileged policy | Six actions allowed for the current ordinary owner; three service mutations require the missing broker |
| Launcher compatibility probe | Simulated Linux root startup returned exit 2 before pipeline construction; installer source still launches main.py using sudo |
| Linux execution | Not verified in this review |
| Hardware, model and enforcement | No camera, microphone, model inference, BCC attachment, kernel prevention, router or remote-server acceptance test was run |

The test timings measure the offline suite. They do not measure threat latency or product execution speed. The suite uses mocks and selected temporary-file tests; native Linux ownership, locking, filesystem and service semantics are still unproven.

The previous baseline report records that Multipass execution was denied, its Windows service was stopped/disabled, and the historical source mount points to E:\FYP\code rather than the selected latest folder. Those are recorded baseline observations, not a newly verified guest state.

Nine contracts:

- disk.usage
- memory.usage
- ports.listen
- service.status
- service.start
- service.stop
- service.restart
- file.create
- directory.create

The six unprivileged actions have production adapter code and offline tests. service.start, service.stop and service.restart deliberately return authentication_authorization_required; that is correct current behavior until a trusted broker exists.

## 3 Findings and immediate corrections

### P1 Installed launcher and application disagree about privileges

The installer writes launchers that use sudo for the interactive and natural-language application. The new main entry point refuses root/setuid startup. Installing the current tree would therefore produce a launcher that the application rejects.

Evidence:

- E:\FYP\code 2\linxai\install.sh:200
- E:\FYP\code 2\linxai\install.sh:208
- E:\FYP\code 2\linxai\main.py:3207
- Read-only probe: main(["--command", "check memory"]) under mocked Linux UID/EUID 0 returned 2; no pipeline was created.

Fix the launchers and packaging to run the application as an ordinary user. Keep the root rejection. Administrative operations must reach a narrow broker, not a root GUI. Update supported command forwarding and add launcher-to-entry-point contract tests.

### P1 Supported application startup disconnects the existing security rules

The current in-process eBPF initialization and rule callback require EUID 0, but the supported main entry point now rejects root. An ordinary-user application therefore skips that branch. The separate root monitor writes events to its own configured/default log, but no authenticated transport connects it to the new operations service or an independent detection/rule consumer.

This does not prove that the standalone collector is stopped or that no kernel events can be logged. It establishes that the supported ordinary-user CLI does not run the old in-process rule/AI-context path.

Evidence:

- E:\FYP\code 2\linxai\main.py:158
- E:\FYP\code 2\linxai\main.py:292
- E:\FYP\code 2\linxai\main.py:307
- E:\FYP\code 2\linxai\main.py:3207
- E:\FYP\code 2\linxai\ebpf\daemon.py:371
- E:\FYP\code 2\linxai\systemd\linxai-ebpf.service

Move event ingestion and detection into a supervised background component. Give the sensor one owner, an explicit readiness/error protocol, a configured event destination and an authenticated consumer. The application subscribes to incidents instead of owning the collector. Do not re-enable root application startup as a workaround.

### P1 The old natural-language and administrative paths are not migrated

Only explicit --operation requests and the standalone typed CLI use OperationService. The existing adapt_plan bridge is not connected to ordinary AI requests in main.py. Setup steps, retry suggestions, nginx edits, output export and remote operations continue to use their older implementations.

Evidence:

- E:\FYP\code 2\linxai\main.py:3203
- E:\FYP\code 2\linxai\operations\plans.py:87
- E:\FYP\code 2\linxai\main.py:1898
- E:\FYP\code 2\linxai\main.py:2491
- E:\FYP\code 2\linxai\main.py:2708
- E:\FYP\code 2\linxai\main.py:2932

This is an explicit migration boundary, not evidence that the new service is bypassable. New guarantees simply do not cover those legacy entry points yet.

Migrate a complete request path: natural language -> structured plan -> typed request -> shared service -> independently authorized execution -> verified result. Enumerate unmigrated actions and reject them explicitly on the trusted new route. Do not claim the entire product is secured because --operation is secured.

### P1 No native Linux acceptance baseline yet

The current suite proves useful logic but cannot establish compatibility with actual df/free/ss/systemctl outputs, private paths, executable ownership, BCC bindings or authentication. The inherited install script performs broad unpinned system pip installation. There is no declared reproducible Python package/runtime setup in the current inventory.

Create a supported Linux/Python/dependency matrix and reproducible app environment. Keep BCC's interpreter/bindings compatible with the OS package that supplies them; sensor separation can avoid forcing the desktop application and BCC into one incompatible environment. Do not choose the production version solely because tests pass on Windows Python 3.12.

Close guest access, source revision and mount verification. If the existing development VM cannot be restored, choose a deliberately provisioned replacement with a preserved original and a recorded installation recipe. Do not repeatedly retry denied commands indefinitely.

### P2 Long-running jobs and durable state are not ready for broader automation

The new service is synchronous and process-local. Approval tokens disappear on restart. There is no durable job queue, cancellation protocol, operation reconciliation or restoration. The Linux subprocess adapter limits retained output after completion, while temporary output files can grow until timeout. Its current timeout behavior does not provide general descendant-process supervision.

Evidence:

- E:\FYP\code 2\linxai\operations\service.py:117
- E:\FYP\code 2\linxai\operations\system.py:29
- E:\FYP\code 2\linxai\operations\system.py:37
- E:\FYP\code 2\linxai\docs\OPERATIONS_SERVICE.md

These limits are documented honestly and are acceptable for the present bounded slice. They need resolution before expanding to package installation, deployment and incident remediation. Add bounded live output, job/process-group or cgroup supervision, action-specific cancellation and crash recovery. A crash after dispatch must produce an unknown/reconciling result, not an automatic retry that may duplicate side effects. Never claim universal exactly-once execution.

### P2 Existing authentication is a prototype, not the broker

The face server has a fixed permissive socket and does not establish a trusted account-bound authorization result for the exact requested operation. A UI/AI response or user-writable socket must not authorize root work. Implement password-backed OS authorization first; add face verification through a reviewed account-bound provider afterward.

Evidence:

- E:\FYP\code 2\linxai\executor\face_auth.py
- E:\FYP\code 2\linxai\executor\pam\pam_linxai_face.c

The new service's refusal to dispatch administrative actions is appropriate. Preserve it while building the broker. Do not connect the old face-server success boolean directly to administrative execution.

### P2 Delivery configuration and status documentation lag behind architecture

The root README/status documents describe earlier module completion, while appended implementation records contain newer partial-milestone evidence. Different log/configuration paths and launcher behavior still reflect the older application. Git HEAD excludes the current registry/service/test additions.

Create one current capability/acceptance matrix, retaining historical evidence separately. Review and checkpoint all required new files together when committing is authorized. A shared commit/release identifier must identify actual source, configuration and packaged artifacts; the current old HEAD does not identify the uncommitted working implementation.

## 4 Recommended target architecture

Use a modular Python application with a small number of processes separated by responsibility and privilege. Preserve the new operations contracts and avoid creating another action vocabulary. A distributed microservice platform is not needed for the current single-host FYP.

~~~mermaid
flowchart TD
    UI[Linux desktop application] --> IPC[Authenticated local API]
    IPC --> AG[Ordinary-user application agent]
    AG --> AI[Local Ollama reasoning]
    AI --> OP[Existing typed operations service]
    AG --> OP
    OP --> JOB[Ordinary-user job workers]
    OP --> BROKER[Privileged broker and OS authorization]
    BROKER --> SYS[Approved system operations]
    SENSOR[Privileged kernel sensor] --> DET[Background detection and incident engine]
    DET --> AI
    DET --> MEM[Validated response-policy store]
    MEM --> ENF[Installed kernel enforcement policies]
    ENF --> EVENTS[Enforcement evidence]
    EVENTS --> DET
    DET --> IPC
    OP --> AUDIT[Correlated operation and audit records]
~~~

### Desktop

The owner selected Linux desktop as the final target. PySide6 remains a proposed toolkit, not an already approved framework choice. Reuse Python services whichever UI toolkit is selected.

Implement assistant, operations, assets, security and activity views. Rendering, passwords and camera interaction must not grant execution authority. Long operations must not block the UI. Closing or crashing the window must leave monitoring and admitted background jobs under service supervision.

### Ordinary-user agent and operations service

The agent owns conversation/planning, operation state and UI events. The existing registry/service remains the operation core. Separate preview, authorization and dispatch. Carry operation/incident identifiers and authenticated principal identity across all boundaries.

The in-process Approval object is not an IPC credential. Define a versioned request/response protocol with bounded payloads and authenticated local peers before exposing service methods across processes.

### Privileged broker

Prefer a small Linux mechanism over authenticated local IPC with polkit-backed authorization. Resolve peer identity from the trusted transport. Accept typed action requests, never client-provided argv, shell strings, UID claims or an authenticated=true flag.

Rebuild and revalidate privileged operations inside the broker. Bind authorization to action, target, parameters, session and expiry. Administrative code, executable paths and installed policy files must be protected from ordinary-user modification. A user-writable development tree must not become a trusted root import path.

Start with allowlisted service actions in the isolated lab. Test cancellation, denied authentication, wrong user, replay, changed target and broker-unavailable cases. Use OS-native authentication prompts; keep passwords out of model context and application logs.

Polkit's documented pattern puts authorization in the privileged mechanism and treats its unprivileged caller as untrusted:
https://www.freedesktop.org/software/polkit/docs/latest/polkit-apps.html

### Monitoring and enforcement

Keep kernel capture, deterministic detection, buffering and installed enforcement independent of model latency. Use a normalized event schema with monotonic timestamps, host/boot identity, UID, stable process identity, lineage, executable identity, target and return evidence where applicable. Track lost events, queue pressure and degraded monitoring.

The initial release needs selected demonstrated prevention policies, not a claim to block every possible attack. Verify kernel configuration, supported hooks and enforcement availability before choosing the implementation. BPF LSM supports access-control hooks; post-event signals do not prove the original operation was prevented.

References:
https://docs.kernel.org/bpf/prog_lsm.html
https://tetragon.io/docs/concepts/enforcement/

### Adaptive AI response and memory

Define an incident lifecycle and a distinct response-policy lifecycle.

Incident: observed -> triaged -> response proposed -> authorized -> containment attempted -> outcome verified -> resolved or escalated.

Policy: candidate -> validated/tested -> eligible for automatic deployment -> active -> expired/revoked.

The AI proposes typed actions and scoped matching conditions. Independent policy checks enforce owner-configured automatic-action limits. Verified action success alone does not prove the incident was malicious or a rule is safe to generalize: include benign near-matches and false-positive checks before promotion.

Store provenance, evidence references, exact action/parameters, asset/subject scope, validation results, version, expiry, revocation and outcomes. Do not store a raw PID, process-name substring or unrestricted shell command as a universal reusable response. PID identity must include the relevant host/boot and process-start context.

Separate user conversation/cache data from authoritative enforcement policy. The privileged component must verify policy provenance and allowed scope rather than trusting a row written by the ordinary-user AI process. Include a reliable operator revoke/disable control.

Treat event text, file contents and remote command output as untrusted model input. Keep authorization outside the model. OWASP explicitly describes these action-integrity and memory-security boundaries:
https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html

### Audit and durable state

Use structured operation and incident records with explicit states, schema versions and correlation IDs. SQLite is sufficient for the local FYP's durable operational state if ownership, concurrency, migration and backup are defined. Privileged evidence must have a trustworthy writer and access boundary; the current user-owned private JSONL ledger is not tamper-proof against its own user.

Bound retention, redact credentials and sensitive content, report audit failures and reconcile operations after restart. Keep background queues bounded. Separate guaranteed admission/audit records from lower-priority UI progress that may be coalesced.

### Packaging and service isolation

Declare app dependencies and runtime versions, build an installable artifact and test clean install/uninstall/upgrade. Keep the GUI unprivileged. Give each long-running component only its required filesystem access and capabilities. Apply systemd hardening per component and verify it does not disable necessary BPF/authentication/device access.

Use supported directives for the chosen systemd version rather than copying the newest manual indiscriminately:
https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html

## 5 Completion roadmap

The stages below are acceptance gates. Offline work can continue around an environmental blocker, but a milestone with unrun Linux checks remains incomplete.

| Gate | Build or repair | Completion evidence |
|---|---|---|
| A Runnable Linux baseline | Resolve guest access, selected source/mount, supported Python/BCC setup, installer/root mismatch; confirm final desktop/camera/kernel feasibility | Selected working-tree fingerprints on Linux; six unprivileged action smoke tests; root app rejected; launcher works as ordinary user; documented supported environment |
| B Privileged operations | Authenticated broker, password-backed OS authorization, three bounded service mutations and exact-operation binding | Correct user succeeds on a lab service; denied/cancelled/wrong-user/replayed/altered requests never dispatch; correlated verification/audit |
| C First complete desktop workflow | Migrate natural-language read and service requests through adapt_plan/service; add durable jobs and a thin app | Request -> preview/auth -> progress -> verified result in app; no raw fallback; job status survives UI restart |
| D Independent security/SOC | Sensor ownership, background consumer, events/incidents, readiness/error handling and live Security view | Controlled benign/suspicious workloads; no duplicate collector; visible event loss/degradation; monitoring continues under model load and app closure |
| E Adaptive prevention loop | Bounded AI response, verified containment, policy validation, persistence, installation and revocation | First lab incident produces a verified response; matching recurrence denied without a model call; benign near-match allowed; expiry/revocation and enforcement evidence demonstrated |
| F DevOps and network breadth | Move existing recipes into typed jobs; integrate remote Linux; implement one selected router/switch platform | Repeated environment setup works safely; failed prerequisites stop honestly; remote identity verified; lab config diff/apply/verify/recovery succeeds |
| G Face and voice | Account-bound face enrollment/authentication, spoof testing, password fallback, missing voice input | Owner/wrong-user/photo/video/unavailable-camera cases recorded; failure preserves trusted fallback; technical-vocabulary WER measured |
| H Release and academic evidence | Integrated tests, sustained load, measured performance, packaging, report/manual/demo/slides | Fresh-target installation and repeatable demo; requirement-to-test evidence for every claimed feature; signed-off remaining limitations |

De-risk kernel enforcement and camera feasibility in gate A even though their complete implementation occurs later. Develop the thin UI once the service contract stabilizes; do not postpone every visible workflow until all backend modules are nominally complete.

The original proposal delivery target is 28 November 2026, 26 days after this review. Completing the entire expanded scope to a production standard by that date is high risk given the unresolved runtime and missing integrations. Preserve the full intended scope, prioritize the release's end-to-end acceptance scenarios, and report any scope or date tradeoff explicitly rather than silently dropping features or declaring unfinished work complete.

Suggested checkpoints, not guaranteed estimates:

- First checkpoint: close gate A and publish one reproducible Linux run report.
- Next checkpoint: one password-authorized lab service operation through the broker.
- Next checkpoint: the same task through the desktop, plus a live incident view.
- Next checkpoint: the full unfamiliar-incident -> response -> recurring-enforcement demonstration.
- Final checkpoint: network/DevOps/hardware evidence, integrated load test and fresh installation.

Do not expand vendor coverage before one device workflow is accepted. Vendor support and rollback/commit-confirm vary:
https://napalm.readthedocs.io/en/latest/support/index.html

Biometric spoofing, error rates and alternative authentication require dedicated evidence. NIST guidance informs the design but does not itself certify this local application:
https://pages.nist.gov/800-63-4/sp800-63b/authenticators/

## 6 Required engineering practices

1. Define the supported action and platform matrix before each milestone. Implementation presence is not acceptance.
2. Keep one operation vocabulary and route all product mutations through it. Inventory and close legacy escape paths.
3. Separate actor authentication, action authorization, operation approval and outcome verification.
4. Test the deployed artifact, launcher and services as well as Python functions.
5. Retain the 109 regression tests, add native Linux integration tests and distinguish mocks from real evidence.
6. Include crash, cancellation, tampered approval, stale state, wrong identity, audit failure, noisy sensor and model-unavailable cases.
7. Use bounded execution/output and action-specific recovery. Package-manager cancellation must not indiscriminately kill an unsafe critical section.
8. Pin runtime/dependency inputs and add a Linux CI job for ordinary tests. Privileged/kernel scenarios belong in an isolated controlled environment.
9. Maintain current capability status, requirements traceability and small architecture decision records. Preserve historical evidence separately.
10. Keep changes reviewable and checkpoint source/configuration/tests/docs together. The current untracked operations files are part of the application, not optional scratch files.

## 7 Release acceptance scenarios

The final demo should prove at least these coherent workflows:

- Natural-language resource/port/service inspection through the ordinary-user desktop.
- A conditional service operation with OS authentication and verified success.
- The same operation blocked by an independently introduced conflict.
- Workspace file creation with correct content and rejection of traversal/overwrite/symlink cases.
- A development environment created and verified; rerunning is safe and failed prerequisites stop correctly.
- One supported remote/server or router/switch operation with before/after state and failure recovery.
- A controlled suspicious incident with an AI-selected bounded response and retained evidence.
- A recurring matching incident denied by an installed policy without invoking the model.
- A similar benign event allowed, and a policy expired/revoked correctly.
- Monitoring remains alive while the UI closes or the model is unavailable.
- Password and face-authentication success/failure/fallback cases; voice input with measured errors.
- A crash/restart leaves operation status reconcilable and never invents success.

Measure planning/task accuracy, false blocks, first-incident reasoning/containment delay, recurring-policy enforcement/alert delay, false positives, dropped events, CPU/memory overhead and sustained availability. Record distributions and workload/environment details. Do not turn timestamp precision or unit-test duration into detection claims.

## 8 Next work order

Do not rerun the three earlier prompts from scratch. Preserve the registry, service and passing suites.

The next task should be: close the Linux runtime gate and repair deployment entry points. Inspect the current baseline; establish the selected source in an accessible Linux environment; correct the sudo launcher/root refusal mismatch while preserving ordinary-user startup; define the sensor's independent startup and event-ingestion contract; add native unprivileged smoke tests and launcher/service contract tests; document exact remaining broker/kernel/hardware gaps.

Then implement gate B. Use the existing OperationService and registry as the core; do not build a second backend beneath the desktop.

Router/switch vendor/emulator selection remains a pending owner input. It does not prevent the baseline, broker, desktop or monitoring work.
