# Requirement traceability without renumbering

The left column preserves the original inventory IDs 1–72. Historical descriptions/statuses and original PDF source labels are retained in REQUIREMENTS_INVENTORY.md. The checked-in simplified SRS.md has FR-01–12/NFR-01–07, a different namespace from the original PDF FR-01–36. Its broad references below are mappings, not replacements or claims that the PDF is present.

Gate IDs A–H refer to the architecture acceptance roadmap. Test evidence must identify an actual test/run and supported environment before changing a row to accepted. Current evidence is in CAPABILITY_REPORT_2026-11-02.md and VERIFICATION.md; none of these rows claims full acceptance.

| Original item | Feature | Gate | Current boundary | Simplified repo SRS mapping |
| --- | --- | --- | --- | --- |
| 1 | Natural Language Command-Line Interface | C | Legacy AI/context/fast paths and typed boundary present; complete natural-language migration pending | FR-01–03 |
| 2 | Offline AI Model Integration | C | Legacy AI/context/fast paths and typed boundary present; complete natural-language migration pending | FR-01–03 |
| 3 | Command Intent Classification | C | Legacy AI/context/fast paths and typed boundary present; complete natural-language migration pending | FR-01–03 |
| 4 | AI Prompt Engineering | C | Legacy AI/context/fast paths and typed boundary present; complete natural-language migration pending | FR-01–03 |
| 5 | LangGraph AI Workflow | C | LangGraph graph not established by source; do not infer it from dependencies | FR-01–03 |
| 6 | Structured JSON Execution Plans | C | Legacy AI/context/fast paths and typed boundary present; complete natural-language migration pending | FR-01–03 |
| 7 | SQLite Context Memory | C | Legacy AI/context/fast paths and typed boundary present; complete natural-language migration pending | FR-01–03 |
| 8 | Context-Aware Follow-Up Commands | C | Legacy AI/context/fast paths and typed boundary present; complete natural-language migration pending | FR-01–03 |
| 9 | Text Normalization | C | Legacy AI/context/fast paths and typed boundary present; complete natural-language migration pending | FR-01–03 |
| 10 | Microphone Audio Capture | G | Voice runtime missing; hardware/WER and pipeline integration pending | FR-11 |
| 11 | Voice Activity Detection (VAD) | G | Voice runtime missing; hardware/WER and pipeline integration pending | FR-11 |
| 12 | Offline Speech-to-Text | G | Voice runtime missing; hardware/WER and pipeline integration pending | FR-11 |
| 13 | Voice-to-AI Pipeline Integration | G | Voice runtime missing; hardware/WER and pipeline integration pending | FR-11 |
| 14 | Technical Vocabulary Recognition Testing | G | Voice runtime missing; hardware/WER and pipeline integration pending | FR-11 |
| 15 | Network Port Conflict Detection | A/B/C | CIE and action-derived checks present; native breadth/legacy migration incomplete | FR-04 |
| 16 | Service Status Validation | A/B/C | CIE and action-derived checks present; native breadth/legacy migration incomplete | FR-04 |
| 17 | Process and Resource State Validation | A/B/C | CIE and action-derived checks present; native breadth/legacy migration incomplete | FR-04 |
| 18 | File, User, and Permission Checks | A/B/C | CIE and action-derived checks present; native breadth/legacy migration incomplete | FR-04 |
| 19 | Firewall and Dependency Conflict Handling | A/B/C | CIE and action-derived checks present; native breadth/legacy migration incomplete | FR-04 |
| 20 | Approve / Block / Warn Decisions | A/B/C | CIE and action-derived checks present; native breadth/legacy migration incomplete | FR-04 |
| 21 | Automatic Conflict Resolution and Alternative Suggestions | A/B/C | CIE and action-derived checks present; native breadth/legacy migration incomplete | FR-04 |
| 22 | System Execution Controller | B/C/G | New bounded service tested; broker/legacy/authentication gaps remain | FR-05–06; NFR-03 |
| 23 | Command Timeout Handling | B/C/G | New bounded service tested; broker/legacy/authentication gaps remain | FR-05–06; NFR-03 |
| 24 | Destructive Command Protection | B/C/G | New bounded service tested; broker/legacy/authentication gaps remain | FR-05–06; NFR-03 |
| 25 | Structured Execution Results | B/C/G | New bounded service tested; broker/legacy/authentication gaps remain | FR-05–06; NFR-03 |
| 26 | Sudo Privilege Management | B/C/G | Administrative service dispatch deliberately blocked pending trusted broker | FR-05–06; NFR-03 |
| 27 | Facial Recognition Authentication | B/C/G | Face prototype only; account binding/spoof/password fallback acceptance pending | FR-05–06; NFR-03 |
| 28 | Face Liveness Detection | B/C/G | Liveness claim unverified | FR-05–06; NFR-03 |
| 29 | Custom PAM and Authentication Socket Integration | B/C/G | PAM/socket prototype is not trusted operation authorization | FR-05–06; NFR-03 |
| 30 | eBPF Monitoring Daemon | D/E | Monitoring source present; independent detection/adaptive policy/enforcement acceptance pending | FR-07; NFR-02–03 |
| 31 | Process Execution Monitoring (`execve`) | D/E | Monitoring source present; independent detection/adaptive policy/enforcement acceptance pending | FR-07; NFR-02–03 |
| 32 | Network Connection Monitoring (`connect`) | D/E | Monitoring source present; independent detection/adaptive policy/enforcement acceptance pending | FR-07; NFR-02–03 |
| 33 | File Access Monitoring (`openat`) | D/E | Monitoring source present; independent detection/adaptive policy/enforcement acceptance pending | FR-07; NFR-02–03 |
| 34 | BCC Probe Loading | D/E | Monitoring source present; independent detection/adaptive policy/enforcement acceptance pending | FR-07; NFR-02–03 |
| 35 | Kernel Event Buffering | D/E | Monitoring source present; independent detection/adaptive policy/enforcement acceptance pending | FR-07; NFR-02–03 |
| 36 | Suspicious Activity Detection | D/E | Monitoring source present; independent detection/adaptive policy/enforcement acceptance pending | FR-07; NFR-02–03 |
| 37 | Credential File Access Detection | D/E | Monitoring source present; independent detection/adaptive policy/enforcement acceptance pending | FR-07; NFR-02–03 |
| 38 | Suspicious Network and Exfiltration Detection | D/E | Monitoring source present; independent detection/adaptive policy/enforcement acceptance pending | FR-07; NFR-02–03 |
| 39 | Reverse Shell and Attack Tool Detection | D/E | Monitoring source present; independent detection/adaptive policy/enforcement acceptance pending | FR-07; NFR-02–03 |
| 40 | Kernel Security Alert Memory | D/E | Monitoring source present; independent detection/adaptive policy/enforcement acceptance pending | FR-07; NFR-02–03 |
| 41 | Security-Aware Future Command Warnings | D/E | Monitoring source present; independent detection/adaptive policy/enforcement acceptance pending | FR-07; NFR-02–03 |
| 42 | Security Event Causal Tracking | D/E | Monitoring source present; independent detection/adaptive policy/enforcement acceptance pending | FR-07; NFR-02–03 |
| 43 | Attack Simulation Module | D/E | Historical attack tests absent from latest tree; recover selectively, never routine discovery | FR-07; NFR-02–03 |
| 44 | Low-Overhead eBPF Monitoring | D/E | Overhead target unmeasured in current environment | FR-07; NFR-02–03 |
| 45 | Active Kernel Threat Interception | D/E | Kernel prevention/enforcement not demonstrated | FR-07; NFR-02–03 |
| 46 | CPU and Memory Monitoring | F/H | Resource prototype present; stable identity and measured benefit pending | FR-08 |
| 47 | Process Classification | F/H | Resource prototype present; stable identity and measured benefit pending | FR-08 |
| 48 | Automatic Process Priority Optimization | F/H | Resource prototype present; stable identity and measured benefit pending | FR-08 |
| 49 | Automatic Priority Restoration | F/H | Resource prototype present; stable identity and measured benefit pending | FR-08 |
| 50 | Predictive Resource Management | F/H | Reactive threshold code is not a predictive model | FR-08 |
| 51 | Resource Optimization Performance Validation | F/H | Resource prototype present; stable identity and measured benefit pending | FR-08 |
| 52 | Remote Server Configuration | F | Standalone remote source present; unified policy/host identity/device lab acceptance pending | FR-09 |
| 53 | SSH-Based Remote Authentication | F | Standalone remote source present; unified policy/host identity/device lab acceptance pending | FR-09 |
| 54 | Remote Command Execution | F | Standalone remote source present; unified policy/host identity/device lab acceptance pending | FR-09 |
| 55 | Remote Command Safety Guard | F | Standalone remote source present; unified policy/host identity/device lab acceptance pending | FR-09 |
| 56 | Remote Server Status Monitoring | F | Standalone remote source present; unified policy/host identity/device lab acceptance pending | FR-09 |
| 57 | Multi-Server Management Verification | F | Standalone remote source present; unified policy/host identity/device lab acceptance pending | FR-09 |
| 58 | Centralized JSON Lines Audit Logger | C/D/H | Operation ledger implemented; full cross-module incident/durable audit integration pending | FR-10; NFR-04 |
| 59 | Standardized Audit Records | C/D/H | Operation ledger implemented; full cross-module incident/durable audit integration pending | FR-10; NFR-04 |
| 60 | Cross-Module Audit Integration | C/D/H | Operation ledger implemented; full cross-module incident/durable audit integration pending | FR-10; NFR-04 |
| 61 | Command-Line Log Viewer | C/D/H | Operation ledger implemented; full cross-module incident/durable audit integration pending | FR-10; NFR-04 |
| 62 | AI Explain Mode | C/D/H | Operation ledger implemented; full cross-module incident/durable audit integration pending | FR-10; NFR-04 |
| 63 | Native Ubuntu Installer | A/C/D | Inherited system installer unsafe for routine setup; isolated typed launcher now supplied | FR-12; NFR-06–07 |
| 64 | Modular Component Installers | A/C/D | Reproducible dev setup added; legacy deployment/full application integration incomplete | FR-12; NFR-06–07 |
| 65 | Systemd Monitoring Service | A/C/D | Sensor source/unit file present; independent ownership/readiness/transport still pending | FR-12; NFR-06–07 |
| 66 | Configuration Management | A/C/D | Reproducible dev setup added; legacy deployment/full application integration incomplete | FR-12; NFR-06–07 |
| 67 | Module Status Interface | A/C/D | Reproducible dev setup added; legacy deployment/full application integration incomplete | FR-12; NFR-06–07 |
| 68 | Partial End-to-End Integration | A/C/D | Reproducible dev setup added; legacy deployment/full application integration incomplete | FR-12; NFR-06–07 |
| 69 | Full Eight-Module Integration | A/C/D | Full integration not complete | FR-12; NFR-06–07 |
| 70 | Native Linux Compatibility Testing | A/C/D | Ordinary-user WSL smoke evidence is separate from final desktop/hardware/platform acceptance | FR-12; NFR-06–07 |
| 71 | Comprehensive Testing and Stabilization | H | Offline test-method count is not requirement acceptance coverage | FR-12; NFR-05–06 |
| 72 | 24-Hour System Stress Testing | H | 24-hour/99-percent availability acceptance not demonstrated | FR-12; NFR-05–06 |


## Gate A evidence overlay — 2 November 2026

Status: IMPLEMENTED—LAB ACCEPTANCE PENDING. Original 1–72 identifiers and source
labels above are unchanged. See GATE_A_BASELINE.md, INSTALLATION.md and sanitized
docs/evidence/gate-a records. Cloud: none executed; current hosted CI: pending.
Native WSL: offline 125 passed; backend and installed lab each 10 passed/1 skipped;
actual root installer/launcher refused. Hardware/device/enforcement: none executed.

| Original IDs | Current evidence advance | Still pending |
| --- | --- | --- |
| 15–20 | Typed validation, real resource/port/filesystem checks and missing-manager denial | Full validation breadth, real systemd success/missing-unit checks, desktop migration |
| 22–25 | Preserved exact approved execution and bounded deadlines/results; isolated launcher forwarding | Trusted broker, all legacy paths, durable supervision/recovery |
| 58–59 | Native file operation ID/fingerprint correlation across checks/execution/verification/audit | Full cross-module durable audit/retention |
| 63–64, 66–68, 70 | Locked ordinary-user wheel install/remove, platform/dependency matrix, native installed CLI and safety negatives | Full six-action lab/Cloud evidence and final desktop integration |
| 65, 69 | Sensor packaging inspected; historical templates documented; OS interpreter separated | Independent secure sensor deployment, readiness/transport and full integration |

## Complete agreed scope beyond recovered inventory labels

These are scope descriptions, not invented original requirement IDs. Source IDs
not recoverable from the inventory/PDF remain **unknown**. Gates map the work;
no row claims acceptance merely because prototype source or a mock exists.

| Agreed scope | Gate / current evidence | Remaining acceptance |
| --- | --- | --- |
| Linux desktop natural-language administration | A/C; typed local backend and isolated installation tested | Desktop, AI-to-action workflow, durable jobs/API, complete legacy migration |
| Development environment provisioning and DevOps | F; existing prototypes only | Typed provisioning/deployment contracts, authorization, verification and isolated lab |
| Remote Linux operations | F; inherited SSH module retained | Trusted peer/host identity, shared service routing and multi-host lab |
| Router, switch and port management | F; local port inspection tested in A | Device-specific typed adapters, transport/policy and actual device lab |
| SOC workflows and independent monitoring/deterministic detection | D/F; inherited sensor/detection prototypes retained | Model/UI-independent supervision, transport, bounded queues/data and deterministic lab evidence |
| AI incident analysis, bounded response and verified containment | C/E; typed action constraints preserved | Incident boundary, broker/enforcement integration and real containment tests |
| Validated response-policy memory and owner-configured automatic response | E; auto-response remains disabled | Scoped/versioned/expiring policies, deterministic matching, independent owner limits, replay/expiry/containment tests |
| Trusted OS authorization outside model/UI | B; privileged actions explicitly blocked | Trusted broker/protocol, real OS auth, independent identity/policy and lab service operation |
| Account-bound face authentication with password fallback | B/G; prototype retained | Protected enrollment, trusted account binding, spoof/liveness testing and OS password fallback |
| Voice input | G; candidate dependencies separated | Runtime implementation, real microphone/VAD/offline recognition and measured language tests |
| Resources, audit, recovery and release quality | C/F/H; typed audit and refusal of unsupported restoration tested | Stable identity, measured resource benefit, validated state restoration, durable audit, long-run/load/release tests |

The project target remains a Linux desktop; standalone monitoring and enforcement
must continue without desktop/model. A passive capability probe proves neither
that independence nor kernel control. Test evidence for each future gate must
separate Cloud, native lab and hardware/device results with exact pending commands.


## Gate B implementation checkpoint — 2 November 2026

Implemented production broker transport, OS peer identity, root allowlist, polkit
exact-operation authorization, persistent replay admission, service/TCP checks,
verified state, private root audit, bounded supervision and protected packaging.
See BROKER.md. Default OperationService administrative refusal remains intact.
Original IDs 15–26, 29, 58–59 and 63–70 advance partially; no source IDs removed.
Windows broker contracts: 10 run, 9 passed/1 Linux peer skip; real Linux/native
checks follow. Real polkit/service acceptance remains pending without systemd.
This pending target acceptance does not block C–H independent implementation.


## Gate C workflow checkpoint — 2 November 2026

See APPLICATION.md. Existing fast paths/schema/adapt_plan now drive the agent and
desktop through preview/confirmation and durable jobs. Strict ordinary-user IPC,
exact target/digest binding, bounded admission/output, cancellation and unknown
crash recovery are implemented. Privileged work only uses the Gate B broker; no
raw-shell fallback is reachable from this installed route. Original requirements
1–9, 15–26, 58–62 and 63–70 advance partially. Other original IDs remain required.
Actual Windows suite: 144 run, 141 passed, 3 skipped (1.906 s). Native WSL: 168
run, 160 passed, 8 skipped (20.292 s), including real agent IPC/execution, client
reconnect, duplicate exclusion and private SQLite. Qt setup is separate/in progress;
a premature Qt run failed for absent PySide6 before install completion, not code.
Physical desktop, hardware, OS-auth and kernel evidence remain pending.


## Gate D monitoring checkpoint

See MONITORING.md. Independent sensor/monitor paths, protected packaging, bounded
transport/retention, normalized host/boot/start identity, deterministic incidents
and desktop Security state are implemented. Seven new contract tests pass; current
Windows offline: 151 run, 148 passed/3 skipped (2.064 s). Event/blocked-model tests
are simulations, not real BPF evidence. WSL lacks BCC/systemd; native capture,
actual loss/lifecycle and target privilege hardening remain pending. Original
30–44, 58–60, 65, 67–70 remain partially covered; item 45 prevention is Gate E.


## Gate E scoped response checkpoint

See RESPONSE_POLICIES.md. Existing registry/service/broker now support bounded
response installation/revocation, exact operation-ID payload binding, root evidence
and owner limits, independently qualified native BPF LSM adapter, verified
containment, root policy persistence, model-free recurrence, expiry and revocation.
Default auto-response remains disabled; root-configured automatic limits are
independently rechecked. All eight response tests use explicit simulated kernel/
auth/evidence adapters, with simulated origin retained. Three HTTP tests cover
fixed loopback, no redirects/proxies, body and absolute-deadline bounds. Windows
combined: 162 run, 159 passed/3 skips (1.511 s). No kernel hook was loaded.
C actual Qt offscreen workflow also passed separately: 1 test, 4.717 s, deterministic
backend; not physical desktop or real OS-auth evidence. Native E acceptance and
performance remain pending. IDs 36, 40–45, 58–60 plus expanded adaptive-policy
scope advance partially; original 1–72 inventory remains complete and unrenumbered.


## Gate F selected workflows checkpoint

See WORKFLOWS.md. The existing registry/service now covers Python environment/
project recipes, strict SSH typed peer and persistent development-device interface
inspect/diff/apply/verify/validated restoration. Reused VPS endpoint fields; no raw
recipe/shell fallback. Windows 166 run, 163 passed/3 skipped (1.537 s). Four real
isolated native workflow tests passed (25.851 s), including actual managed Python,
transactional development files and the remote peer protocol over local pipes.
This is not physical router or SSH-login evidence. Original 15–25, 52–62, 63–70
advance partially; Node/MERN/deployment breadth, resources and vendor/multi-host
acceptance remain pending and all original requirements remain present.


## Gate G authentication/voice checkpoint — 2 November 2026

See AUTHENTICATION_VOICE.md. Empty-parameter account enrollment/revocation actions
use the existing broker/registry and always require polkit. Protected face proofs
bind OS account, operation/digest, nonce, template/provider and expiry. Failure
falls back to trusted OS authentication; no UI/model credential flags are accepted.
Primary face defaults off pending actual camera/spoof qualification; heuristic
liveness is not demonstrated biometric assurance. Local-only bounded voice input
feeds ordinary preview/confirmation. Root camera interpreter remains separate.
Nine new deterministic tests plus existing suites: Windows 175 run/172 passed,
3 skips (1.621 s). Native WSL combined: 203 run/195 passed, 8 skips (42.452 s)
including actual ordinary-user agent/filesystem/process workflows. UI/provider
refinements after this run are verified in subsequent H evidence. Cloud/CI and
native OS-auth/kernel/hardware/model acceptance: none executed for this checkpoint.
Original 10–14, 26–29 and 58–70 advance partially; all 1–72 items remain required.
No face/PAM, physical camera/microphone, spoof assurance or WER success is claimed.
