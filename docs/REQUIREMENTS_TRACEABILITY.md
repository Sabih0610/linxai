# Requirement traceability without renumbering

The left column preserves the original inventory IDs 1–72. Historical descriptions/statuses and original PDF source labels are retained in REQUIREMENTS_INVENTORY.md. The checked-in simplified SRS.md has FR-01–12/NFR-01–07, a different namespace from the original PDF FR-01–36. Its broad references below are mappings, not replacements or claims that the PDF is present.

Current table updated on 9 November 2026: rows 3, 8, 19–21, 36–39, 41, 43, 44, 46–57, 61, 62, 70 and 72 consolidate the dated overlays below, which keep the detailed history. Every row separates implementation, automated evidence and remaining acceptance; none implies whole-requirement PASS. Gate IDs A–H refer to the architecture acceptance roadmap. Test evidence must identify an actual test/run and supported environment before changing a row to accepted. Current evidence is in CAPABILITY_REPORT_2026-11-02.md and VERIFICATION.md; none of these rows claims full acceptance.

| Original item | Feature | Gate | Current implementation | Automated evidence | Target / remaining acceptance | Simplified repo SRS mapping |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Natural Language Command-Line Interface | C | Implemented bounded text → validated typed preview | test_application; test_safety_regressions; native/installed agent | Broader multi-step/model language corpus | FR-01–03 |
| 2 | Offline AI Model Integration | C | Implemented: local-only bounded Ollama planning behind deterministic/fast paths; schema validation and typed adaptation; prompt-injection guard refuses state-changing proposals in quoted/translated/override text | eval_intents.py (qwen2.5:1.5b): 15/15 unsafe refused; injection set 10/10 safe (run 4 found 4 unsafe proposals → guard → run 5 10/10); test_workflow_graph | Larger models; third-party injection corpus | FR-01–03 |
| 3 | Command Intent Classification | C | Implemented: bounded text → planning graph → validated typed preview; account/credential and destructive-disk requests refused before the model | test_workflow_graph; `eval_intents.py` with qwen2.5:1.5b: 15/15 unsafe refused, 0 false actions; action accuracy 100 % tuning / 73.3 % held-out | Independent third-party corpus; larger models | FR-01–03 |
| 4 | AI Prompt Engineering | C | Implemented: local-only bounded Ollama planning behind deterministic/fast paths; schema validation and typed adaptation; prompt-injection guard refuses state-changing proposals in quoted/translated/override text | eval_intents.py (qwen2.5:1.5b): 15/15 unsafe refused; injection set 10/10 safe (run 4 found 4 unsafe proposals → guard → run 5 10/10); test_workflow_graph | Larger models; third-party injection corpus | FR-01–03 |
| 5 | LangGraph AI Workflow | C | Implemented: `ai/workflow.py` bounded planning state graph (normalize → deterministic → classify_fast → model → validate → adapt) on LangGraph `StateGraph` when installed, built-in runner otherwise | test_workflow_graph incl. `test_real_langgraph_matches_builtin_runner` — PASS on the VM with langgraph 1.2.20 (same requests and traces as the built-in runner) | LangGraph is optional (not in the locked dependency set) | FR-01–03 |
| 6 | Structured JSON Execution Plans | C | Implemented bounded text → validated typed preview | test_application; test_safety_regressions; native/installed agent | Broader multi-step/model language corpus | FR-01–03 |
| 7 | SQLite Context Memory | C | Implemented: private durable SQLite job history (five latest turns as context); follow-ups resolve against it | test_followups incl. 15-turn multi-dialogue corpus (model never reached); native agent | Migration of the legacy context store | FR-01–03 |
| 8 | Context-Aware Follow-Up Commands | C | Implemented: follow-ups ("restart it", "is it running", "do the same for X", "do it again") resolved against the latest typed job and re-previewed | test_followups | Longer multi-turn corpus | FR-01–03 |
| 9 | Text Normalization | C | Implemented bounded text → validated typed preview | test_application; test_safety_regressions; native/installed agent | Broader multi-step/model language corpus | FR-01–03 |
| 10 | Microphone Audio Capture | G | Implemented bounded local PCM/VAD/Whisper → preview; hardware acceptance pending | test_auth_voice; Qt voice-to-preview stand-in | Opt-in accept_voice.py with real mic, existing local model and vocabulary references/WER | FR-11 |
| 11 | Voice Activity Detection (VAD) | G | Implemented bounded local PCM/VAD/Whisper → preview; hardware acceptance pending | test_auth_voice; Qt voice-to-preview stand-in | Opt-in accept_voice.py with real mic, existing local model and vocabulary references/WER | FR-11 |
| 12 | Offline Speech-to-Text | G | Implemented bounded local PCM/VAD/Whisper → preview; hardware acceptance pending | test_auth_voice; Qt voice-to-preview stand-in | Opt-in accept_voice.py with real mic, existing local model and vocabulary references/WER | FR-11 |
| 13 | Voice-to-AI Pipeline Integration | G | Implemented bounded local PCM/VAD/Whisper → preview; hardware acceptance pending | test_auth_voice; Qt voice-to-preview stand-in | Opt-in accept_voice.py with real mic, existing local model and vocabulary references/WER | FR-11 |
| 14 | Technical Vocabulary Recognition Testing | G | Implemented bounded local PCM/VAD/Whisper → preview; hardware acceptance pending | test_auth_voice; Qt voice-to-preview stand-in | Opt-in accept_voice.py with real mic, existing local model and vocabulary references/WER | FR-11 |
| 15 | Network Port Conflict Detection | A/B/C | Implemented server-derived typed port checks | test_action_registry; test_broker; native ports | Actual conditional service/auth lab | FR-04 |
| 16 | Service Status Validation | A/B/C | Implemented systemd state checks and missing-manager denial | test_gate_a; native missing-manager check | service.status success skipped: WSL has no running systemd | FR-04 |
| 17 | Process and Resource State Validation | A/B/C | Implemented: typed state reads — processes (identity-bound), services (conflict analysis), ports, memory/disk, path metadata and user accounts; mandatory checks before every action | test_resources, test_conflicts, test_operations_service; native VM | — | FR-04 |
| 18 | File, User, and Permission Checks | A/B/C | Implemented: `path.inspect` (parent chain, owner, mode, symlink target, actor access, unsafe world-writable parents; never reads contents) and `user.lookup` (passwd/group facts, admin groups) | test_resources incl. native VM (`/etc/shadow` unreadable to the actor, private file 0o640 verified) | — | FR-04 |
| 19 | Firewall and Dependency Conflict Handling | A/B/C | Implemented: typed dependency/conflict analysis (Requires/BindsTo/Conflicts, masked or missing unit, occupied port, ufw enabled) | test_conflicts incl. real systemd on the VM | Firewall rule-level inspection needs root (broker) | FR-04 |
| 20 | Approve / Block / Warn Decisions | A/B/C | Implemented: approve / warn / block on every service preview; block refuses confirmation; unreadable systemd warns, never blocks | test_conflicts | — | FR-04 |
| 21 | Automatic Conflict Resolution and Alternative Suggestions | A/B/C | Implemented: typed alternatives (similar unit names, restart failed dependency, free ports); suggested, never auto-applied | test_conflicts; VM: `sshh.service` → `ssh.service` | Auto-application deliberately excluded (owner confirms) | FR-04 |
| 22 | System Execution Controller | B/C/G | Implemented exact approval/checks → supervised argv → verified correlated result | Foundation/registry/service/broker suites; native time/output/argv tests | Full legacy route migration and real privileged operation acceptance | FR-05–06; NFR-03 |
| 23 | Command Timeout Handling | B/C/G | Implemented exact approval/checks → supervised argv → verified correlated result | Foundation/registry/service/broker suites; native time/output/argv tests | Full legacy route migration and real privileged operation acceptance | FR-05–06; NFR-03 |
| 24 | Destructive Command Protection | B/C/G | Implemented exact approval/checks → supervised argv → verified correlated result | Foundation/registry/service/broker suites; native time/output/argv tests | Full legacy route migration and real privileged operation acceptance | FR-05–06; NFR-03 |
| 25 | Structured Execution Results | B/C/G | Implemented exact approval/checks → supervised argv → verified correlated result | Foundation/registry/service/broker suites; native time/output/argv tests | Full legacy route migration and real privileged operation acceptance | FR-05–06; NFR-03 |
| 26 | Sudo Privilege Management | B/C/G | Implemented protected peer-bound broker and polkit mechanism | test_broker; native SO_PEERCRED; real root-startup denial historical | accept_broker.py against explicitly prepared polkit/service fixture | FR-05–06; NFR-03 |
| 27 | Facial Recognition Authentication | B/C/G | PARTIAL: protected account template/proof; heuristic liveness unqualified, primary off | test_auth_voice doubles; no actual camera/spoof evidence | accept_face.py controlled repeated account/photo/video/missing-camera suite; assurance review | FR-05–06; NFR-03 |
| 28 | Face Liveness Detection | B/C/G | PARTIAL: protected account template/proof; heuristic liveness unqualified, primary off | test_auth_voice doubles; no actual camera/spoof evidence | accept_face.py controlled repeated account/photo/video/missing-camera suite; assurance review | FR-05–06; NFR-03 |
| 29 | Custom PAM and Authentication Socket Integration | B/C/G | PARTIAL: protected broker/face socket replaces UI trust; legacy custom PAM unmigrated | Strict protocol/account/operation tests; no PAM configuration changed | Original custom PAM criteria/source reconciliation; trusted target authentication acceptance | FR-05–06; NFR-03 |
| 30 | eBPF Monitoring Daemon | D/E | Implemented independently supervised protected capture path; native hooks unrun | test_security_monitor; normalized BCC source inspected | OS BCC/target-kernel compile/attach/capture and accept_monitor.py | FR-07; NFR-02–03 |
| 31 | Process Execution Monitoring (`execve`) | D/E | Implemented independently supervised protected capture path; native hooks unrun | test_security_monitor; normalized BCC source inspected | OS BCC/target-kernel compile/attach/capture and accept_monitor.py | FR-07; NFR-02–03 |
| 32 | Network Connection Monitoring (`connect`) | D/E | Implemented independently supervised protected capture path; native hooks unrun | test_security_monitor; normalized BCC source inspected | OS BCC/target-kernel compile/attach/capture and accept_monitor.py | FR-07; NFR-02–03 |
| 33 | File Access Monitoring (`openat`) | D/E | Implemented independently supervised protected capture path; native hooks unrun | test_security_monitor; normalized BCC source inspected | OS BCC/target-kernel compile/attach/capture and accept_monitor.py | FR-07; NFR-02–03 |
| 34 | BCC Probe Loading | D/E | Implemented independently supervised protected capture path; native hooks unrun | test_security_monitor; normalized BCC source inspected | OS BCC/target-kernel compile/attach/capture and accept_monitor.py | FR-07; NFR-02–03 |
| 35 | Kernel Event Buffering | D/E | Implemented independently supervised protected capture path; native hooks unrun | test_security_monitor; normalized BCC source inspected | OS BCC/target-kernel compile/attach/capture and accept_monitor.py | FR-07; NFR-02–03 |
| 36 | Suspicious Activity Detection | D/E | Implemented: deterministic model-free rules — sensitive file, temp/shm exec, attack-tool exec, shell/netcat outbound connection, backdoor ports | test_security_monitor; VM real kernel: Gate D incidents and `accept_detection.py` (4/4 fixtures ≤0.6 s, 0 false alarms in controls) | False-positive rate over long real workloads (24 h soak) | FR-07; NFR-02–03 |
| 37 | Credential File Access Detection | D/E | Implemented: non-root open of /etc/shadow or /etc/sudoers → `sensitive_file_attempt` | test_security_monitor; VM real-kernel incident (Gate D) and hourly soak probe | Open outcome not observed (entry only) | FR-07; NFR-02–03 |
| 38 | Suspicious Network and Exfiltration Detection | D/E | Implemented: outbound TCP to backdoor/C2 ports (1337, 4444, 5554, 6666, 6667, 9999, 12345, 31337) → `unusual_connection_attempt`; novel destinations scored by the lake baseline (advisory) | test_security_monitor; VM real kernel: port-31337 fixture detected in 0.26 s | Volume/content-based exfiltration (not attempted) | FR-07; NFR-02–03 |
| 39 | Reverse Shell and Attack Tool Detection | D/E | Implemented: shell or raw network tool (bash, sh, nc, socat, telnet …) opening an outbound TCP connection → `shell_network_connection`; known attack-tool execution → `attack_tool_execution` | test_security_monitor; VM real kernel: bash /dev/tcp and nc fixtures detected in 0.2–0.3 s, nmap-named exec detected, benign curl/python/bash controls silent | Evasion by renamed binaries or non-shell interpreters | FR-07; NFR-02–03 |
| 40 | Kernel Security Alert Memory | D/E | Implemented bounded incident/event private persistence | test_security_monitor; private Store native tests | Target continuous capture/loss/restart evidence | FR-07; NFR-02–03 |
| 41 | Security-Aware Future Command Warnings | D/E | Implemented: recent incidents (30 min, ≤5) attached to previews as advisory `security_warnings`, stronger for related/admin actions; never block or authorize | test_security_warnings | Desktop rendering | FR-07; NFR-02–03 |
| 42 | Security Event Causal Tracking | D/E | Implemented: kernel (pid, start, uid, boot) subject on every event; procfs ancestry (≤8 hops) attached to real-kernel incidents, first hop bound by start time (verified/unverified/exited) | test_security_monitor; VM: persistent reverse-shell fixture verified lineage bash ← python3 ← sshd ← … ← systemd | Short-lived processes (<≈0.3 s) exit before lineage is read; syscall return values not captured | FR-07; NFR-02–03 |
| 43 | Attack Simulation Module | D/E | Implemented: harmless explicit fixtures — monitor acceptance, hourly soak probe, network/attack-tool fixtures | VM real-kernel runs (Gate D; `detection-network.json`) | Response-policy fixtures need BPF LSM (Gate E) | FR-07; NFR-02–03 |
| 44 | Low-Overhead eBPF Monitoring | D/E | Measured | Sensor user-space CPU 0.93 % of one vCPU idle, 1.43 % under load; foreground timings with vs without sensor within ±5.5 % (noise) | In-kernel probe cost not separated | FR-07; NFR-02–03 |
| 45 | Active Kernel Threat Interception | D/E | Implemented: bounded IPv4 TCP BPF LSM provider with qualified, scoped, expiring, revocable policies; owner-only, `auto_enabled` off | test_response_policy; VM real kernel (BPF LSM active) `accept_policy.py` PASS: deny, uid/port/address/UDP near-matches allowed, revoke, expiry (`gate-e/`) | Recurrence case (named in the original acceptance) not part of `qualify`; automatic incident-triggered enforcement disabled by design; IPv6 | FR-07; NFR-02–03 |
| 46 | CPU and Memory Monitoring | F/H | Implemented: typed `process.list` (two-sample per-process CPU %, load, memory) plus memory/disk reads | test_resources; native VM | Desktop view | FR-08 |
| 47 | Process Classification | F/H | Implemented: structural classification (system / interactive / background by uid, kernel parent, tty) | test_resources; native VM | — | FR-08 |
| 48 | Automatic Process Priority Optimization | F/H | Implemented: `process.priority.lower` — owner-only, bound to (pid, start, uid), increase-only, all threads, verified | test_resources; native VM (0→7; stale identity and raising refused); `bench_resources.py` | Triggering is advisory (forecast recommends, owner confirms) | FR-08 |
| 49 | Automatic Priority Restoration | F/H | Implemented: `process.priority.restore` — admin through broker + polkit, decrease-only, floor nice 0 | VM console acceptance PASS (`restore-acceptance.json`) | — | FR-08 |
| 50 | Predictive Resource Management | F/H | Implemented: `resource.forecast` — least-squares slope + EWMA, pressure risks, background candidates (never applied) | test_resources; native VM | Accuracy over longer horizons | FR-08 |
| 51 | Resource Optimization Performance Validation | F/H | Measured: five per-CPU load scenarios before/after typed lowering | WSL2: CPU task −27–78 %, wake p95 −74–87 %; VM: CPU task −31–79 % (`bench/`) | Desktop/interactive workloads | FR-08 |
| 52 | Remote Server Configuration | F | Implemented: strict configured SSH typed peer (pinned key and known_hosts, BatchMode, no agent/forwarding, allowlisted actions, persistent replay refusal) | test_workflows; native peer; VM real-SSH acceptance PASS (`remote-acceptance.json`) | Physically separate hosts | FR-09 |
| 53 | SSH-Based Remote Authentication | F | Implemented: strict configured SSH typed peer (pinned key and known_hosts, BatchMode, no agent/forwarding, allowlisted actions, persistent replay refusal); key-only login, `restrict` authorized key | test_workflows; native peer; VM real-SSH acceptance PASS (`remote-acceptance.json`) | Physically separate hosts | FR-09 |
| 54 | Remote Command Execution | F | Implemented: strict configured SSH typed peer (pinned key and known_hosts, BatchMode, no agent/forwarding, allowlisted actions, persistent replay refusal) | test_workflows; native peer; VM real-SSH acceptance PASS (`remote-acceptance.json`) — memory, disk and service status verified on both peers | Physically separate hosts | FR-09 |
| 55 | Remote Command Safety Guard | F | Implemented: strict configured SSH typed peer (pinned key and known_hosts, BatchMode, no agent/forwarding, allowlisted actions, persistent replay refusal) | test_workflows; native peer; VM real-SSH acceptance PASS (`remote-acceptance.json`) — raw shell, nested remote and unknown asset refused before SSH; host-key mismatch fails closed; replay refused | — | FR-09 |
| 56 | Remote Server Status Monitoring | F | Implemented: strict configured SSH typed peer (pinned key and known_hosts, BatchMode, no agent/forwarding, allowlisted actions, persistent replay refusal) | test_workflows; native peer; VM real-SSH acceptance PASS (`remote-acceptance.json`) — remote `service.status` verified | Physically separate hosts | FR-09 |
| 57 | Multi-Server Management Verification | F | Implemented: multiple named assets, each pinned separately | VM: two assets (loopback and NAT address of the same VM) both verified | Two physically separate servers | FR-09 |
| 58 | Centralized JSON Lines Audit Logger | C/D/H | Implemented bounded private JSONL, durable IDs/fingerprints and generation rotation | Service/broker correlation; native concurrent rotation/symlink/fsync tests | Root deployment audit/durability/retention acceptance; user ledger not tamper-proof | FR-10; NFR-04 |
| 59 | Standardized Audit Records | C/D/H | Implemented bounded private JSONL, durable IDs/fingerprints and generation rotation | Service/broker correlation; native concurrent rotation/symlink/fsync tests | Root deployment audit/durability/retention acceptance; user ledger not tamper-proof | FR-10; NFR-04 |
| 60 | Cross-Module Audit Integration | C/D/H | Implemented: correlated jobs/audit/incidents/anomalies/policies; `logs`, `explain` and cross-module `timeline` (CLI `--timeline N`) | test_explain incl. native agent timeline; VM integrated acceptance | Desktop timeline view | FR-10; NFR-04 |
| 61 | Command-Line Log Viewer | C/D/H | Implemented: CLI `--logs N` and agent `logs` API (bounded audit tail) | test_explain; native VM agent | Desktop log view | FR-10; NFR-04 |
| 62 | AI Explain Mode | C/D/H | Implemented: deterministic explanations of jobs, incidents and anomalies from recorded facts (no model) | test_explain; native VM agent | Desktop explain button | FR-10; NFR-04 |
| 63 | Native Ubuntu Installer | A/C/D | Implemented locked ordinary-user app/profile install, guarded launchers, protected artifact separation | Fresh installed wheel/agent/project/Qt/uninstall; root denial historical | Target upgrade/service/desktop install acceptance | FR-12; NFR-06–07 |
| 64 | Modular Component Installers | A/C/D | Implemented locked ordinary-user app/profile install, guarded launchers, protected artifact separation | Fresh installed wheel/agent/project/Qt/uninstall; root denial historical | Target upgrade/service/desktop install acceptance | FR-12; NFR-06–07 |
| 65 | Systemd Monitoring Service | A/C/D | Implemented independent sensor/monitor/policy unit templates; not enabled here | Single-instance and daemon protocol/loss tests | Actual systemd lifecycle/reboot with UI/model stopped | FR-12; NFR-06–07 |
| 66 | Configuration Management | A/C/D | Implemented bounded private assets/state and explicit component health | Agent/security/storage/config contracts; native IPC | Target configuration/health and operational recovery procedures | FR-12; NFR-06–07 |
| 67 | Module Status Interface | A/C/D | Implemented bounded private assets/state and explicit component health | Agent/security/storage/config contracts; native IPC | Target configuration/health and operational recovery procedures | FR-12; NFR-06–07 |
| 68 | Partial End-to-End Integration | A/C/D | Implemented supported end-to-end ordinary-user workflows | Installed agent job/project, dev-device apply/verify/restore, native socket/process/files | Actual broker/kernel/hardware/remote integration | FR-12; NFR-06–07 |
| 69 | Full Eight-Module Integration | A/C/D | Implemented: AI, operations, context, conflicts, security monitor, warnings, explain/timeline, resources, DevOps recipe, medallion learning and kernel response policy integrated through typed services | `accept_integrated.py` on the VM: 13/13 steps PASS (`integrated-acceptance.json`) | Face/voice hardware paths (camera/microphone) not in the integrated run | FR-12; NFR-06–07 |
| 70 | Native Linux Compatibility Testing | A/C/D | PARTIAL: native Ubuntu 24.04.4 (VirtualBox VM) and WSL2 evidence | VM offline group 242/242; broker, sensor/monitor, restore, detection and SSH acceptance on the VM | Bare-metal desktop; other distributions | FR-12; NFR-06–07 |
| 71 | Comprehensive Testing and Stabilization | H | Implemented: automated offline, native, opt-in target acceptance suites; reviewable commits | Offline 251/251 on the VM (0 skipped) and 251 run / 13 Linux-only skipped on Windows; VM acceptance: broker, monitor, restore, detection, SSH, Gate E, integrated; 8.9 h soak | Two `linux`-group tests need the locked app install (setup_dev.py) on the VM; full 24 h soak | FR-12; NFR-05–06 |
| 72 | 24-Hour System Stress Testing | H | PARTIAL: `soak_integrated.py` (typed reads, sensor health, monitor freshness, RSS, hourly detection probe, host-pause accounting) | Integrated run stopped at 8.9 h by owner decision: 98.42 % available, all downtime inside an Ubuntu auto-update window (sensor restarted by the upgrade, recovered unaided); probes 9/9 (median 2.0 s); 8 h ops-only run 99.89 % | Full 24 h run (pause unattended-upgrades first); longer memory-trend evidence | FR-12; NFR-05–06 |


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

| Agreed scope | Current implementation / automated evidence | Target or remaining acceptance |
| --- | --- | --- |
| Linux desktop natural-language administration | C/G/H; typed agent preview/job/result and real Qt offscreen/installed workflow | Physical desktop, OS-auth and wider multi-step language corpus |
| Development environment provisioning and DevOps | F; actual typed Python project/interpreter, idempotency and edit preservation | Node/MERN/repository/deployment recipes remain partial; target workflows |
| Remote Linux operations | F; strict configured SSH path plus actual local peer/replay protocol | Real pinned-host SSH/account/multi-host acceptance |
| Router, switch and port management | F; local ports and development-device diff/apply/verify/validated restoration | Selected vendor interface/transport/commit-confirm and real device lab |
| SOC and independent monitoring/deterministic detection | D; independent sensor/monitor/health/incident paths, bounded simulated contracts | Actual kernel capture, lost events, outcomes/false positives/lifecycle |
| AI incident analysis, bounded response, verified containment | E; model-selected exact scope → independent broker/provider; simulated verification | Actual auth/containment and benign target suite |
| Validated response-policy memory and owner automatic response | E; independent scoped provenance/expiry/revoke/known-policy recurrence tests | Actual qualified kernel enforcement; owner automatic flag stays false by default |
| Trusted OS authorization outside AI/UI | B; root-owned peer/allowlist/polkit path, denied/replay/change tests | Prepared service/polkit lab; no privileged deployment occurred |
| Account-bound face with trusted password fallback | G; protected per-account proofs and fallback contract tests | Real camera/spoof/account assurance and original custom PAM reconciliation; primary off |
| Voice input | G; bounded local-only PCM/VAD/transcription → Qt preview, deterministic tests | Actual microphone/technical corpus/WER and equipment acceptance |
| Resources/audit/recovery/release | H; bounded audit and installed packaging; captured development-device restoration | Typed resource optimization/prediction, benchmarks and 24-hour full-system stress incomplete |


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


## Gate B target acceptance overlay — 8 November 2026

Prepared VirtualBox Ubuntu 24.04.4 console target; see VERIFICATION.md and
docs/evidence/vm-lab-2026-11-08/. Rows above are unchanged; this overlay records
the new evidence.

| Original IDs | New target evidence | Still pending |
| --- | --- | --- |
| 16, 20, 22, 25 | Real systemd start/restart/stop of an allowlisted fixture with fresh post-condition verification and correlated operation IDs/fingerprints | Wider service set, missing-unit and failing-unit cases on target |
| 26 | Real polkit `auth_admin` with OS password, one-shot per exact operation, bound to the client pid/start/uid; fail-closed denial when no agent is reachable | Deliberate cancel/wrong-password cases, desktop agent, root audit export |
| 65, 68 | Broker unit started under real systemd with root-owned verified bundle | Enable/reboot lifecycle; sensor/monitor/policy units |

## Gate D target run overlay — 8 November 2026

| Original IDs | New target evidence | Still pending |
| --- | --- | --- |
| 30–35, 42 | Real BCC compile/attach of execve/connect/openat on Ubuntu 24.04.4 kernel 6.8; events with kernel start-time identity; `kernel_lost=0` | Sensor throughput (≈75/s vs ≈140/s idle load), queue drops, non-IPv4 connect handling, recoverable health |
| 36–40 | None: no incident produced from real capture (monitor lag, event drops) | Fix pipeline throughput, then rerun accept_monitor.py |
| 44 | Sensor ≈29–37 % of one vCPU on the VM at idle load (observation, not a benchmark) | Proper baseline/monitored overhead measurement |

Gate D rerun (same day, after throughput fix): accept_monitor.py PASSED. IDs 30–35
and 42 now have real capture with kernel identity and zero sensor loss at idle
load; 36, 37 and 40 have one real incident each (`temporary_executable_attempt`,
`sensitive_file_attempt`) persisted by the independent monitor. 38/39, false-
positive measurement, latency variance, unit reboot lifecycle and 44 remain open.

## Development overlay — 8 November 2026 (uncommitted)

| Original IDs | New implementation | Automated evidence | Still pending |
| --- | --- | --- | --- |
| 41 | `security/warnings.py`: recent monitor incidents (30 min, ≤5) attached to every preview as `security_warnings`; stronger text for admin/related actions; advisory only — not in the digest, never blocks, authorizes or reaches the model | test_security_warnings (5) | Desktop rendering beyond raw preview JSON |
| 46, 47 | `process.list`: fixed `/proc` worker, two-sample per-process CPU %, load, memory; structural classification (system/interactive/background by uid, kernel parent, tty) instead of name substrings | test_resources; native VM run | Desktop view |
| 48 | `process.priority.lower`: unprivileged owner action bound to (pid, start_ticks, uid), increase-only, all threads, verified postcondition, prior nice captured | native VM: real child lowered 0→7, stale identity refused, raising refused | Measured benefit (51) |
| 49 | `process.priority.restore`: authenticated-admin broker action (`org.linxai.process.manage`), decrease-only, floor nice 0; offered as validated restoration after a verified lower | native VM: proposal captured, never dispatched locally | Real broker/polkit restore acceptance on the VM |
| 50 | `resource.forecast`: least-squares slope + EWMA over 5–40 samples, horizon 10–600 s, pressure risks, recommended background candidates (never applied) | test_resources (math, bounds); native VM forecast verified | Longer-horizon/learned model; accuracy measurement |

## Development overlay 2 — 8 November 2026

| Original IDs / scope | New implementation | Automated evidence | Still pending |
| --- | --- | --- | --- |
| 5 | `ai/workflow.py`: planning as an explicit bounded state graph (normalize → deterministic → classify_fast → model → validate → adapt); runs on LangGraph `StateGraph` when the optional package is installed, else the built-in runner; previews record engine and trace | test_workflow_graph (incl. adapter wiring against a StateGraph stand-in) | Execution on real LangGraph (package not in the locked environment) |
| 8 | `follow_up()`: "restart it", "is it running", "do the same for X", "do it again" against the user's latest typed job; revalidated and previewed like any request | test_followups | Longer multi-turn corpus |
| 19, 21 | `operations/conflicts.py`: Requires/BindsTo/Conflicts, masked/missing unit, occupied port and ufw-enabled findings; typed alternatives (similar units, restart failed dependency, free ports) | test_conflicts incl. real systemd on the VM (`sshh.service` → `ssh.service`) | Firewall rule inspection needs root (broker) |
| 20 | approve / warn / block decision on previews; block refuses confirmation; unreadable systemd warns | test_conflicts | — |
| 61, 62 | agent `logs`/`explain`, CLI `--logs N` / `--explain ID`; deterministic templates over job, audit, incident and anomaly facts | test_explain incl. native agent on the VM | Desktop explain button |
| Medallion data / learned model (new scope) | `security/lake.py`: bronze/silver/gold with provenance, quarantine, poisoning-aware training eligibility, Good-Turing novelty baseline, advisory anomalies; monitor refresh every 10 min | test_lake; VM: real capture, novel `/usr/bin/factor` flagged at 8.6 bits, no incident | False-positive rate on real workloads |

## Measurement overlay — 8 November 2026

| Original IDs | Measurement | Evidence | Still pending |
| --- | --- | --- | --- |
| 51 (with 48) | `scripts/bench_resources.py`: foreground CPU task and 5 ms wake-up p95 at idle, under background load, and after the real typed `process.priority.lower` to nice 19; load sized per pinned CPU. WSL2 (6.6 kernel, pinned to 2 CPUs): CPU-task time improved 27–78 % in all five scenarios, wake p95 improved 74–87 % in the four oversubscribed ones. VM (pinned to 1 vCPU): CPU-task time improved 31–79 %; wake p95 is dominated by hypervisor timer jitter (3.0 ms at idle) and is inconclusive there. Lowering verified in every case | `docs/evidence/vm-lab-2026-11-08/bench/` | Desktop/interactive workload measurement |
| 3 | `scripts/eval_intents.py` against the local `qwen2.5:1.5b` through the production planning graph (no execution). Final run: 47 positive and 15 negative requests; refusal of destructive / privilege / exfiltration / off-topic requests 15/15 with no false actions; action accuracy 100 % on the 32 tuning phrasings and 73.3 % (exact 66.7 %) on 15 held-out phrasings; model-route median latency 5.4 s after a 30 s cold load. Runs 1–2 found the model mapping "add user … to sudoers" to `service.start sudo.service` and "format the disk" to `disk.usage`; account/credential and destructive disk requests are now refused before the model | `docs/evidence/vm-lab-2026-11-08/intents/` (runs 1–3); test_workflow_graph | Independent (third-party written) corpus; larger model comparison |
| 44 | Sensor user-space CPU 0.93 % of one vCPU idle (180 s), 1.43 % under the pinned benchmark; foreground task times with vs without sensor within ±5.5 % (noise) | `bench/sensor-idle-vm.json`, `bench/bench-vm-1cpu-sensor.json` | In-kernel probe cost not separated; high exec-rate workloads |
| 49 | `scripts/accept_restore.py` on the VM console: lower 0→10 unprivileged, nice −5 refused before dispatch, restore to 0 through the root broker after polkit `auth_admin` — succeeded, verified, audit complete. PASS | `restore/restore-acceptance.json` | — |
| 72 | `scripts/soak_integrated.py`; 8 h ops-only run 99.89 % available; full integrated 24 h run started 9 Nov (first probe detected in 2.0 s) | `soak/` | Complete the 24 h run; the VM under VirtualBox-on-Hyper-V (NEM) loses guest time under sustained load (soft lockups observed at load ≈ 28) |
| DevOps recipes (Node) | `project.node`: typed unprivileged recipe writing a private ES-module Node project (package.json with `npm start`, `index.js` HTTP health server on 127.0.0.1, README, .gitignore) plus a managed marker; idempotent, never overwrites owner edits, downloads nothing; planner routes "create/scaffold a node/nodejs/express project/app in X" | test_workflows, test_action_registry; native VM test incl. `/usr/bin/node --check` of the generated file | MongoDB/React parts of MERN (need package downloads; deliberately out of scope) |

## Extension overlay — network devices over NETCONF, 9 November 2026

| Scope | Implementation | Evidence | Pending |
| --- | --- | --- | --- |
| Multi-vendor network device configuration (new scope; supersedes the development-file-only device platform for real devices) | `netconf` asset platform for `device.inspect`, `device.interface.set`, `device.interface.restore`: pinned SHA256 host key, key-only SSH, required candidate/confirmed-commit/validate/OpenConfig capabilities, revision-bound preview, lock-or-refuse, validate, 60 s confirmed commit, read-back, single-use 300 s restore; vendor-neutral OpenConfig (`operations/_netconf_program.py`, `docs/NETWORK_DEVICES.md`) | test_workflows (strict pinned assets); `accept_netconf.py` 11/11 on Nokia SR Linux v26.7.2 in a free WSL2 lab (`evidence/netconf-lab-2026-11-09/`) | Juniper (vJunos), Cisco (DevNet/CML-Free), Huawei (university hardware); IoT (MQTT/Modbus); agentless remote machines; device telemetry into incidents |
| IoT device control (new scope) | `iot.inspect`, `iot.point.set`, `iot.point.restore` for `modbus` and `mqtt` assets: allowlisted named points, literal topics, bounded/enumerated values, read-only kinds, revision over writable points, single-use transactions, device-confirmed writes (Modbus read-back; MQTT device state echo), CONNACK-verified MQTT auth, TLS required off-loopback, 300 s restore (`operations/iot_contracts.py`, `operations/_iot_program.py`, `docs/IOT.md`) | test_iot; `accept_iot.py` 19/19 against a Modbus PLC simulator and Mosquitto-authenticated MQTT devices in WSL2 (`evidence/iot-lab-2026-11-09/`) — found and fixed: unauthenticated MQTT session looked successful; drifting sensors broke the preview check | Real PLCs/MQTT devices; MQTT over TLS on a network; OPC UA/BACnet/Zigbee |
| Agentless remote Linux (new scope; extends 52–57) | `remote.operation` on `linux_agentless` assets: pinned SSH, fixed command templates (df, meminfo, ss, systemctl show/start/stop/restart), parsed JSON results, re-read verification (restart needs a new activation time), system changes only via target `sudo -n`, user-scope services (`docs/AGENTLESS.md`) | test_workflows; `accept_agentless.py` 9/9 on the VM via loopback and NAT addresses | Physically separate hosts; Windows (WinRM/OpenSSH) templates |
