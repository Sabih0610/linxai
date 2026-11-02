# Original numbered requirements inventory (historical)

Recovered 2 November 2026 from LINxAI-FYP-master-record.md, Appendix A.
Original item numbers 1–72, descriptions, source labels and historical statuses are preserved below.
These are not current completion claims. See CLOUD_HANDOFF.md and REQUIREMENTS_TRACEABILITY.md.
The original PDF requirements use different FR numbering from the simplified checked-in SRS.md; do not merge or renumber those namespaces.

## Appendix A All 72 features approved for report inclusion

The numbered list below preserves the 23 October inventory's feature descriptions, historical document-based statuses and source labels. **Its completed/in-progress labels are historical documentation claims. Read them with the reconciled status table in Section 8 and the unresolved work in Section 11.** In particular, voice, LangGraph, safety, VPS integration and performance claims require the qualifications already recorded above.

## A. User Interaction and AI Reasoning

1. **Natural Language Command-Line Interface** — Allows Linux commands to be entered in everyday English through the `linxai` terminal interface. **Completed.** Source: SRS §4.1; SDS §7.1.
2. **Offline AI Model Integration** — Uses Qwen2.5:1.5B through the locally hosted Ollama runtime to process commands without cloud APIs. **Completed.** Source: SRS §§2.5, 3.3; SDS §3.
3. **Command Intent Classification** — Identifies at least 30 Linux administration intent categories, including process, service, network, and file operations. **Completed** (47/50 tests, 94%). Source: Proposal, Objectives; SRS §4.1.
4. **AI Prompt Engineering** — Uses structured system prompts and prompt examples to guide command interpretation and planning. **Completed.** Source: Proposal, Phase 3; SDS §3.
5. **LangGraph AI Workflow** — Organizes intent classification, planning, validation handoff, and result handling through an agent workflow. **Completed** as part of the AI engine. Source: Proposal, AI Reasoning Stack; SDS §§3, 3.3.
6. **Structured JSON Execution Plans** — Produces machine-readable plans containing the intent, command, arguments, risk assessment, and explanation. **Completed.** Source: SRS §4.1; SDS §3.
7. **SQLite Context Memory** — Stores recent command history and context for subsequent interactions, with the SDS specifying five retained turns. **Completed.** Source: SRS §4.1; SDS §§3–4.
8. **Context-Aware Follow-Up Commands** — Enables subsequent commands to use previous conversation context. **Completed.** Source: SRS FR-04; Proposal, AI Reasoning Stack.
9. **Text Normalization** — Prepares and standardizes input text before AI processing. **Unclear** (shown in the architecture diagram, but implementation is not separately confirmed). Source: SDS, Fig. SDS-1.

## B. Voice Command Module

10. **Microphone Audio Capture** — Captures spoken Linux instructions through PyAudio. **In progress** (code complete; physical microphone testing pending). Source: SRS FR-05; SDS §3.
11. **Voice Activity Detection (VAD)** — Uses webrtcvad to identify speech and suppress unnecessary silence or noise. **In progress** (implemented in code, not fully hardware-verified). Source: SRS FR-06; SDS §3.
12. **Offline Speech-to-Text** — Uses Faster-Whisper to transcribe spoken commands without cloud processing. **In progress** (implemented in code). Source: SRS FR-07; SDS §3.
13. **Voice-to-AI Pipeline Integration** — Passes transcribed spoken instructions into the same command-processing pipeline used for typed commands. **In progress** (implementation described; native testing pending). Source: Proposal, Speech Processing; SDS §7.2.
14. **Technical Vocabulary Recognition Testing** — Targets a word error rate of 15% or lower on Linux technical vocabulary. **Planned** (final microphone-based testing remains pending). Source: Proposal, Objectives; SRS FR-08.

## C. Command Intelligence Engine (CIE)

15. **Network Port Conflict Detection** — Examines active ports using `/proc/net/tcp` before executing commands that require network ports. **Completed.** Source: SRS FR-09; SDS §3; Poster.
16. **Service Status Validation** — Uses `systemctl` to inspect services before service-management commands are executed. **Completed.** Source: SRS FR-10; SDS §3.
17. **Process and Resource State Validation** — Examines running processes and CPU/memory conditions before command execution. **Completed.** Source: SRS FR-11; SDS §3.
18. **File, User, and Permission Checks** — Examines file-related conditions, users, and permissions as part of pre-execution validation. **Completed** according to the documented CIE verification. Source: SDS §3; SRS §6.3.
19. **Firewall and Dependency Conflict Handling** — Checks firewall restrictions and service dependencies that may prevent a command from succeeding. **Unclear** (included in the proposal but not separately established by the implemented requirements). Source: Proposal, Objectives and Phase 5.
20. **Approve / Block / Warn Decisions** — Returns a validation decision with a reason before a command reaches the executor. **Completed** (40/40 CIE tests). Source: SRS FR-12; SDS §3.
21. **Automatic Conflict Resolution and Alternative Suggestions** — Attempts to suggest or select alternative actions when system-state conflicts are detected. **Unclear** (proposed and diagrammed, but the implemented tests principally document approve/block/warn behavior). Source: Proposal, Architectural Design; SDS, Fig. SDS-1.

## D. Safe Execution and Privilege Control

22. **System Execution Controller** — Executes commands only after approval from the Command Intelligence Engine. **Completed.** Source: SRS FR-13; SDS §3.
23. **Command Timeout Handling** — Terminates commands that exceed a defined execution timeout (30 seconds in the documented VM implementation). **Completed.** Source: SRS FR-14; SDS §9.
24. **Destructive Command Protection** — Blocks dangerous operations, including recursive root deletion, disk formatting, disk wiping, and fork bombs. **Completed.** Source: SRS FR-15; SDS §8.
25. **Structured Execution Results** — Captures standard output, error output, return code, duration, and execution status. **Completed** (21/22 execution tests passed). Source: SRS FR-16 and §6.3.
26. **Sudo Privilege Management** — Provides privilege handling for Linux administrative operations. **Unclear** (integration is documented, but operational privilege handling is not separately verified). Source: Proposal, Phase 6; SDS §3.
27. **Facial Recognition Authentication** — Uses OpenCV with Linux Pluggable Authentication Modules (PAM) to authenticate privileged users. **In progress** (module written; physical webcam testing pending). Source: Proposal, Face Authentication; SRS NFR-11; SDS §8.
28. **Face Liveness Detection** — Proposes optical-flow analysis across consecutive camera frames to distinguish live faces from photographs. **Unclear** (described in the proposal, but implementation and verification are not separately established). Source: Proposal, Face Authentication.
29. **Custom PAM and Authentication Socket Integration** — Connects a custom PAM authentication component to an OpenCV-based Python service over a Unix domain socket. **Unclear** (detailed in the original design but not explicitly verified). Source: Proposal, Face Authentication.

## E. eBPF Kernel Monitoring and Cybersecurity

30. **eBPF Monitoring Daemon** — Runs kernel-level monitoring probes to observe Linux activity. **Completed.** Source: SRS §4.5; SDS §3.
31. **Process Execution Monitoring (`execve`)** — Detects process launches and captures execution information. **Completed.** Source: SRS FR-17; SDS §3.
32. **Network Connection Monitoring (`connect`)** — Observes outbound network connection attempts. **Completed.** Source: SRS FR-18; SDS §3.
33. **File Access Monitoring (`openat`)** — Captures file-access events to identify potentially suspicious behavior. **Completed.** Source: SRS FR-19; SDS §3.
34. **BCC Probe Loading** — Uses the BPF Compiler Collection to compile and load kernel-monitoring programs. **Completed** as part of the implemented daemon. Source: Proposal, Kernel Monitoring and Security; SDS §3.
35. **Kernel Event Buffering** — Transfers kernel events into user space using perf buffers. **Completed.** Source: SRS FR-20; SDS §3.
36. **Suspicious Activity Detection** — Detects defined suspicious event patterns from process, file, and network activity. **Completed.** Source: SRS FR-33; SDS §8.
37. **Credential File Access Detection** — Identifies suspicious access to sensitive authentication-related files. **Completed** according to attack-simulation results. Source: SRS §§4.9, 6.3.
38. **Suspicious Network and Exfiltration Detection** — Detects defined unusual outbound connection and data-exfiltration patterns. **Completed** according to attack-simulation results. Source: SRS §§4.9, 6.3.
39. **Reverse Shell and Attack Tool Detection** — Recognizes defined reverse-shell patterns and suspicious command execution. **Completed** according to attack-simulation results. Source: SRS §§4.9, 6.3; Poster.
40. **Kernel Security Alert Memory** — Stores detected security events in the AI's SQLite context memory. **Completed.** Source: SRS FR-34; SDS §8.
41. **Security-Aware Future Command Warnings** — Uses recent kernel alerts to warn users when they submit subsequent commands. **Completed.** Source: SRS FR-35; SDS, Fig. SDS-2.
42. **Security Event Causal Tracking** — Retains evidence linking detected activities and system actions for auditing and investigation. **Completed.** Source: SRS FR-36.
43. **Attack Simulation Module** — Provides `linxai --attack-sim` to demonstrate security detection against defined attack scenarios. **Completed** (3/3 scenarios reported successful). Source: SRS §6.3; SDS §§7.1, 11.
44. **Low-Overhead eBPF Monitoring** — Targets continuous monitoring with CPU overhead of 2% or less. **Unclear** (the poster claims this performance, while the SRS says overhead validation must continue). Source: Proposal, Objectives; Poster; SRS NFR-04.
45. **Active Kernel Threat Interception** — Claims real-time interception of malicious activity rather than detection and logging alone. **Unclear** (the poster uses interception language, but the SRS establishes monitoring and detection, not a verified kernel-blocking mechanism). Source: Poster; SRS §4.5.

## F. Resource Management

46. **CPU and Memory Monitoring** — Samples CPU and memory usage at one-second intervals. **Completed.** Source: SRS FR-21; SDS §3.
47. **Process Classification** — Categorizes processes into foreground, background, and system classes. **Completed.** Source: SRS FR-22.
48. **Automatic Process Priority Optimization** — Adjusts background process priorities when CPU usage exceeds 80%. **Completed.** Source: SRS FR-23; SDS §3.
49. **Automatic Priority Restoration** — Restores adjusted process priorities when CPU load returns to a stable condition. **Completed.** Source: SRS FR-24.
50. **Predictive Resource Management** — Proposes predictive workload analysis beyond threshold-based process prioritization. **Unclear** (the implementation evidence establishes reactive, threshold-based renicing rather than a separately verified predictive model). Source: Proposal, Features of Project and Objectives.
51. **Resource Optimization Performance Validation** — Measures improvements in foreground responsiveness across five load scenarios. **Unclear** (testing is planned in the proposal, without corresponding recorded results in the SRS). Source: Proposal, Objectives and Phase 9.

## G. Remote VPS Management

52. **Remote Server Configuration** — Stores server hostnames, ports, usernames, and authentication settings in YAML configuration files. **Completed.** Source: SRS FR-25; SDS §4.
53. **SSH-Based Remote Authentication** — Uses Paramiko and SSH keys to establish secure server connections. **Completed.** Source: SRS FR-26; SDS §3.
54. **Remote Command Execution** — Executes commands on remote Ubuntu servers and returns structured results. **Completed.** Source: SRS FR-27.
55. **Remote Command Safety Guard** — Applies destructive-command restrictions to remote operations. **Completed.** Source: SRS FR-28; SDS §8.
56. **Remote Server Status Monitoring** — Proposes observing the operational status of remotely managed servers. **Unclear** (monitoring is described in the proposal, while implemented requirements explicitly establish remote command execution). Source: Proposal, Features of Project.
57. **Multi-Server Management Verification** — Targets administration of at least two VPS targets and execution of ten commands within defined response limits. **Unclear** (the VPS module is marked implemented, but these specific acceptance-test results are not provided). Source: Proposal, Objectives and Phase 10.

## H. Logging, Auditing, and Explainability

58. **Centralized JSON Lines Audit Logger** — Records important system activity in `/var/log/linxai/audit.jsonl`. **Completed.** Source: SRS FR-29; SDS §4.
59. **Standardized Audit Records** — Stores timestamps, session identifiers, host information, module names, event types, severity, and payloads. **Completed.** Source: SRS FR-30; SDS §4.1.
60. **Cross-Module Audit Integration** — Collects AI, validation, execution, kernel, resource, and remote administration events in a unified audit system. **Completed.** Source: SRS §§2.2, 6.3; SDS §§3, 9.
61. **Command-Line Log Viewer** — Displays audit summaries, recent records, module-specific events, and continuously followed logs. **Completed.** Source: SRS FR-31; SDS §7.3.
62. **AI Explain Mode** — Explains recent system events in ordinary English when the user requests an explanation. **Completed.** Source: SRS FR-32; SDS §3; Poster.

## I. Deployment, Configuration, and Integration

63. **Native Ubuntu Installer** — Installs LINxAI as a system-wide Linux application through `sudo bash install.sh`. **Completed.** Source: SRS §6.1; SDS §§3, 10.
64. **Modular Component Installers** — Provides installation support for optional voice, VPS, and security modules. **Completed** according to the SDS. Source: SDS §§3, 10.
65. **Systemd Monitoring Service** — Configures the eBPF daemon as a Linux system service to support background and startup monitoring. **Completed** according to the SDS. Source: SRS §6.1; SDS §10.
66. **Configuration Management** — Uses YAML files for system settings, module enablement, and server configurations. **Completed** as a documented storage component. Source: SRS §§2.4, 6.1; SDS §4.
67. **Module Status Interface** — Provides `linxai --status` to display core, eBPF, voice, VPS, and logging readiness. **Unclear** (the interface is specified, but separate implementation verification is not recorded). Source: SRS §3.1; SDS §7.1.
68. **Partial End-to-End Integration** — Connects the AI engine, CIE, execution controller, and logger into a working command-processing pipeline. **Completed** (8/8 integration tests). Source: SRS §6.3; SDS §11.
69. **Full Eight-Module Integration** — Integrates all principal functional modules into one verified system, including voice and security feedback. **Planned** in FYP-II; completion is not established by the supplied documents. Source: Proposal, Phase 13.
70. **Native Linux Compatibility Testing** — Validates hardware-dependent features and system operation on native Ubuntu, with Debian compatibility also proposed. **In progress** (Multipass verification documented; further platform and hardware testing required). Source: Proposal, Development and Test Environment; SRS NFR-15.
71. **Comprehensive Testing and Stabilization** — Completes at least 100 test cases, end-to-end integration tests, and final bug fixing. **Planned** for FYP-II. Source: Proposal, Phase 14; SRS Appendix C.
72. **24-Hour System Stress Testing** — Validates continuous system operation and the proposed 99% availability target. **Planned** for FYP-II. Source: Proposal, Objectives and Phase 14; SRS Appendix C.
