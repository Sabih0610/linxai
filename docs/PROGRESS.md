# Integrated candidate progress — 3 November 2026

Branch codex/cloud-handoff-2026-11-02. Preserve all existing work. Local commits only;
no push, merge or operational deployment. No waiting for intermediate owner testing.

Completed supported paths: A ordinary-user install; B authenticated bounded broker;
C NL preview/durable jobs/agent/Qt; D independent capture/detection/incidents; E scoped
root-authorized response/policy/qualification path; F Python/strict SSH peer/development
device workflow; G protected face/password fallback and local voice-to-preview;
H clean-source packaging, exact-wheel verifier and installed candidate runner. F breadth, G biometric
assurance and H full release remain PARTIAL; implementation is not acceptance.

Current automated results: Windows 186 run/183 pass/3 skips; WSL 220 run/210 pass/
10 skips; Qt offscreen 3 pass; fresh installed candidate seven steps passed; short
10-second read/audit soak 11 verified operations/0 failures. Two fixed-code builds
were byte-identical; the exact 0cb5a90 wheel passed all five Linux artifact steps. Cloud/hosted new CI,
real root authentication/kernel/SSH/vendor/camera/microphone/model and 24-hour tests
have NOT run. See VERIFICATION.md and current source hashes in native evidence.

Integrity follow-up completed: resolved target/contract digest at confirmation and
dispatch; execution-factory scope check; restart preview expiry; readonly schema
reopen and unknown-version refusal; bounded remote nesting. Old timeout failures
are retained; harness observation derives from existing lifecycle deadlines.

Remaining implementation: typed Node/MERN/repository/deployment recipes; stable
process identity and independently authorized priority capture/restoration;
predictive resources and benchmarks; firewall/dependency alternatives; nuanced
follow-ups/LangGraph source criteria; incident-aware future warnings; full legacy
migration. All original requirements 1–72 plus expanded scope remain in the matrix.

Next concrete continuation:
1. Read RELEASE_CANDIDATE.md and current matrix; inspect operations/{workflow_contracts,
   _workflow_program,workflows,registry,service,broker,jobs}.py and resources/monitor.py.
2. Finish one additional typed DevOps recipe with idempotency/partial failure/edit
   preservation before breadth. No model command becomes executable. Then resource
   actions must use host/boot/UID/PID/start identity and captured prior state; do not
   reuse the old name-substring automatic renicer as a trust boundary.
3. Windows: .venv-windows\Scripts\python.exe -B scripts/test.py offline.
   Native: .venv/bin/python -B scripts/run_candidate.py --offline --desktop --report
   candidate-acceptance.json (exit 3 is pending target acceptance, not failure).
4. Review/commit source/tests/docs, package with scripts/package_candidate.py from a
   clean committed tree. Publish or target-deploy only when explicitly requested.
   Prepared target acceptance runners are accept_broker.py, accept_monitor.py,
   accept_policy.py, accept_face.py and accept_voice.py. Do independent coding while
   target hardware is unavailable; never convert simulations into acceptance claims.

Current tested code checkpoint: 0cb5a907a38639d3adc516dfc20b7c3149a23a28.
The final evidence-only commit preserves those application/protected bytes. See
artifact-0cb5a90.json and reproducible-0cb5a90.json. Remote branch was read at
33fc8a9; local implementation is not on GitHub until deliberately published.

Update 8 November 2026: Gate B broker target acceptance PASSED on the VirtualBox
Ubuntu 24.04.4 VM (`LINxAI`, console session, real polkit + systemd); evidence in
docs/evidence/vm-lab-2026-11-08/. WSL now runs systemd but cannot satisfy the
shipped `allow_active` polkit policy (no logind seat). Next target runs on the same
VM: accept_monitor.py (BCC + BTF present), then accept_policy.py after adding `bpf`
to the kernel `lsm=` list. Build trusted bundles with core.autocrlf=false.
Gate D target run (same day): real BCC capture attached with kernel identity, but
accept_monitor.py FAILED because the sensor degraded under idle load (per-event
fsync'd SQLite on the capture thread, unfiltered openat, AF_UNIX connect events
rejected, monitor ≤64 events/s, sticky health). See
docs/evidence/vm-lab-2026-11-08/monitor/README.md. Fix those, then rerun.
Gate D rerun PASSED after the uncommitted throughput fix (store.write_batch,
sensor publish_many/admit/recoverable health, draining monitor); evidence and
patch in docs/evidence/vm-lab-2026-11-08/monitor/. Next: Gate E accept_policy.py
(kernel has CONFIG_BPF_LSM=y; `bpf` must be added to the `lsm=` boot list).
Development (uncommitted): requirement 41 preview warnings; 46–50 process.list,
process.priority.lower/restore (broker, org.linxai.process.manage), resource.forecast.
Offline 209/0 failures on Windows and on the VM (no skips there). Pending: deploy the
new policy action and run a polkit-approved process restore on the VM.

Update 9 November 2026: the items above were committed and accepted on the VM (process
restore, Gate E BPF LSM qualification, real-kernel reverse-shell/attack-tool/backdoor-port
detection, 8.9 h integrated soak, end-to-end acceptance 13/13). New platforms: NETCONF
network devices (SR Linux accepted 11/11; Cisco IOS XR validated without commit), IoT
(MQTT, Modbus/TCP), agentless Linux and Windows targets (Windows 8/8 on the owner's PC).

Update 10 November 2026 (branch codex/cloud-handoff-2026-11-02, see NETWORK_DEVICES.md
and DISCOVERY.md):
- Typed OpenConfig and native SR Linux configuration features (hostname to EVPN-VXLAN and
  QoS) with confirmed commit, read-back, restore and whole-config identity checks; all-or-
  nothing coordinated batches across devices.
- Vendor knowledge base from public YANG data (1,306 Cisco/Juniper/Huawei platform
  releases) and read-only device discovery to a gold capability profile (bronze/silver/gold).
  Profiles for two SR Linux switches and the Cisco IOS XR 25.3.1 sandbox router.
- Chat requests naming a network device are answered or planned from its gold profile only.
  Live srl1 chat-to-change-to-restore 6/6.
- Small local model optimisation: on a 32-request two-vendor blind set, qwen2.5:1.5b went
  from 26/32 to 30/32 with 0 wrong proposals; qwen2.5:0.5b scores 29/32 with 0 wrong.
- Offline suite 280 tests, 0 failures on Windows and Linux.
Pending: account-based sandboxes (private Cisco reservation for commit/restore, Juniper
vLabs, Arista cEOS), SSH CLI discovery, LoRA fine-tune, merge of the branch into main.
