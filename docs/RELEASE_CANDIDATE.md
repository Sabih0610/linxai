# Integrated development candidate and continuation

Current status: **PARTIAL**. B–G now have integrated production paths for their
bounded supported workflows. H supplies reproducible packaging and installed
acceptance tooling. This is a development candidate, not an accepted full-scope
release. No gate is PASS solely from mocks, WSL or source presence.

The complete Linux desktop outcome remains natural-language administration,
provisioning/DevOps, remote Linux operations, router/switch/port management, SOC,
independent deterministic monitoring, AI-proposed bounded containment, validated
recurring enforcement, account-bound face/password authentication and voice.
Original inventory items **1–72** remain in REQUIREMENTS_TRACEABILITY.md with
current evidence and remaining gaps. REQUIREMENTS_INVENTORY.md preserves original
descriptions/source labels; unavailable original PDFs and unknown identifiers have
not been reconstructed. The architecture review is a historical starting point.

## Components and supported workflow

The ordinary-user CLI and Qt desktop use the authenticated user agent and existing
OperationService/registry. Twenty typed actions cover the original disk/memory,
ports/services/files/directories, scoped TCP response/revocation, Python project
provisioning, strict typed SSH peers, development-device transactions/restoration
and protected face enrollment/revocation. Model commands/privilege flags confer
no authority. Unsupported plans fail explicitly. Administrative work requires
the independent root broker and polkit or a qualified protected face proof.

The protected sensor, ordinary deterministic monitor, protected kernel policy
authority and protected face mechanism are separately supervised templates.
Monitoring/policy logic does not depend on desktop/model lifecycle. Root code is
packaged separately, verified before imports and never loaded from user-owned
source/venvs. Neither app installation nor startup enables any privileged service,
PAM module, BPF hook, camera/microphone or model. See BROKER.md, MONITORING.md,
RESPONSE_POLICIES.md and AUTHENTICATION_VOICE.md for their lab procedures.

The independent root owner configuration bounds response UID/target/duration and
automatic reuse. Automatic response defaults off until target qualification.
Known active policies do not need AI to match/enforce; novel incidents can only
be contained after analysis/authorization. No universal or first-event prevention
claim is made. Storage/queues/process output/retries are bounded. Audit generations
rotate under a shared private writer lock; four 8 MiB generations are retained.
Replays/capacity exhaustion fail closed. Recovery requires captured prior state
and an independently validated new restoration operation; uncertain jobs are not
replayed automatically.

## Install and use as an ordinary Linux account

Use native Linux storage and CPython 3.11–3.13; 3.12 is the actual local lab runtime.
Keep BCC and protected camera bindings in their OS interpreter. Root/container
capabilities do not establish a dedicated usable kernel or device.

```sh
python3 scripts/setup_dev.py
.venv/bin/python -B scripts/test.py offline
.venv/bin/python -B scripts/test.py linux
sh install.sh --desktop
# Optional only: sh install.sh --desktop --voice
mkdir -m 700 "$HOME/linxai-workspace"
"$HOME/.local/share/linxai/bin/linxai-agent" --workspace "$HOME/linxai-workspace"
# In another ordinary-user terminal:
"$HOME/.local/share/linxai/bin/linxai-desktop"
# Optional existing local speech weights:
# linxai-desktop --voice-model /absolute/existing/whisper-model
```

Describe `show memory usage`, `show listening ports`, `create a python project in
demo` or a supported explicit file request. Preview, inspect mandatory checks and
confirm. Inspect Operations/Activity for IDs, progress, failures and reconciliation.
The Assets view supports configured development-device diff/apply/verify/restore;
Security shows independent monitor health/incidents/policies and response previews.
Face enrollment/revocation use the Security preview buttons and OS password prompt.
Unavailable monitoring/broker/model/hardware is displayed as unavailable, never
assumed successful. A frozen preview binds the full registry-prepared target/parameters/checks; queued
work and the execution service are checked again, and restart expires previews. Editing input
invalidates asynchronous results. Voice creates a preview and never confirms it.

`linxai --ask 'show memory usage'`, `--confirm ID --digest DIGEST` and `--jobs`
provide the same agent workflow. Direct typed read/create CLI requests use the
service; direct administrative CLI requests retain explicit broker-required
refusal. Use the agent preview workflow for administrative dispatch.

The optional Ollama loopback endpoint is contacted only on a planning request
that needs it. No model is warmed/downloaded by setup/startup. Existing aliases
and deterministic plans work with no model. Configure assets in private 0600
`~/.linxai/assets.json` before starting the agent; see WORKFLOWS.md. SSH requires
verified known-hosts, a private key and an ordinary remote typed peer installation.
The development-file adapter is not a vendor compatibility claim.

Installation refuses an existing prefix. For upgrades, stage a new dedicated
`--prefix`, verify it, then deliberately switch your launcher/user-unit path.
Keep old install/data until reconciled; do not overwrite running state. Managed
uninstall (`sh uninstall.sh --prefix ...`) removes only the dedicated install and
preserves configuration/audit. New wheel builds use a temporary clean source tree
and preserve historical checkout build output, preventing stale `build/lib` reuse.
User systemd/desktop templates are in deployment/; configure/enable them only on a
prepared target. This development task has not installed operational services.

## Automated candidate and artifact commands

```sh
# Cache initial setup first; --offline forbids package downloads.
.venv/bin/python -B scripts/run_candidate.py --offline --desktop --report candidate-acceptance.json
# Exit 3 = implemented ordinary-user checks passed, target acceptance still pending.
QT_QPA_PLATFORM=offscreen LINXAI_TEST_DESKTOP=1 .venv/bin/python -B -m unittest tests.test_desktop -v
.venv/bin/python -B scripts/soak.py --seconds 30 --report soak-report.json
# After reviewing and committing all source/tests/docs:
.venv/bin/python -B scripts/package_candidate.py --offline --output dist/candidate-COMMIT
.venv/bin/python -B scripts/verify_candidate.py dist/candidate-COMMIT --desktop --report artifact-acceptance.json
```

The candidate runner performs actual isolated installed-wheel imports, a
natural-language agent job, real Python project creation, optional installed Qt
offscreen window, CLI memory read and managed uninstall. Tests never mutate real
services. Reports distinguish each executed step. A short read/audit soak is not
the required 24-hour full-system stress test. For that lab, run all accepted
components with representative measured loads and benign/adversarial fixtures for
24 hours, record loss/backpressure/memory/availability/latencies and retain bounded
evidence. `soak.py --seconds 86400` supplies only the operations/audit workload.

Packaging requires a clean committed Git tree, rejects symlink/generated/sensitive
source members and builds from canonical committed bytes in fresh temporary
storage. Artifacts are an application wheel, `source.tar`, separate protected
`trusted-components.tar` and a SHA256 manifest with repository/branch/commit and
every source hash. The verifier checks every artifact hash, wheel package bytes and protected component
bytes against the committed source archive, then installs the exact hashed wheel in
a disposable ordinary-user prefix and runs the real agent/project workflow. This
prevents passing source tests from masking a stale or mismatched packaged registry.
The source archive includes lockfile, tests, user/service
templates and documentation. Dependencies remain locked in uv.lock; weights,
credentials, environments and biometric material are excluded. Artifact generation
does not install, publish, sign, merge or enable anything. Verify hashes before
reviewed lab extraction; this is not a signed supply-chain attestation.

Linux CI runs ordinary checks and packaging on hosted Ubuntu. New CI/Cloud results
remain pending until the owner publishes the local commits and runs an accessible
environment. No Cloud execution is inferred from WSL or historical CI results.

## Remaining implementation and target acceptance

| Area | Implementation still partial | Exact next evidence |
| --- | --- | --- |
| AI/planning | LangGraph graph is not established; nuanced follow-ups/model evaluation remain | Deterministic multi-step/follow-up contracts, existing real-model opt-in, compare original unknown source requirements |
| CIE/DevOps | Firewall/dependency alternatives, Node/MERN/repository/deployment recipes not migrated; unsupported actions are rejected | Add typed recipes to operations/workflow_contracts.py and fixed workers; idempotency/edit/failure/native tests |
| Resources | Legacy reactive monitor/renicing remains outside installed trusted operations; prediction/benefit unimplemented/unmeasured | Stable host/boot/PID/start identity contracts, prior priority capture, independently authorized bounded mutations/restoration, five-load lab |
| Kernel/SOC | Limited heuristics, entry-attempt evidence; broader outcomes/correlation/incident-aware future warnings partial | `LINXAI_TEST_KERNEL=1 python -B scripts/accept_monitor.py`; actual overload/lifecycle/benign suite on target |
| Adaptive response | Only scoped IPv4 TCP enforcement; native LSM qualification unrun | Protected `accept_policy.py` lab, real first-response/near-match/recurrence/revoke/expiry with desktop/model stopped |
| Auth | Root deployment/polkit unrun; camera heuristic unproven; legacy custom PAM still unmigrated | `LINXAI_TEST_BROKER_LAB=1 python -B scripts/accept_broker.py`; controlled `accept_face.py` and repeated spoof/account tests; keep primary off |
| Remote/devices | Typed SSH production path, only local peer pipes tested; no selected vendor | Real pinned-host SSH/multi-host lab; select platform and add adapter/commit-confirm acceptance through same contract |
| Voice/desktop | Bounded paths implemented; physical display/input/audio/camera accuracy not measured | Opt-in desktop/hardware groups, `accept_voice.py` with local model/known reference; corpus and equipment report |
| Release | Original full eight-module breadth, 24-hour load, target fresh install/upgrade and owner acceptance incomplete | Current matrix plus dedicated full target runner/procedures; no PASS until all required criteria have evidence |

Legacy main.py, ExecutionController setup/export/retry shortcuts, old VPS raw
commands, automatic renicing and PAM installers remain unmigrated compatibility
source, outside the supported installed agent/desktop route. They must not be
reintroduced as a fallback. Historical README instructions are preserved separately
under docs/history/README_PRE_CANDIDATE.md and are not current startup guidance.

Continuation starts with the remaining typed provisioning/resource workflows
above, not another architecture. Reuse registry.py/service.py/broker.py/jobs.py,
preserve exact-operation binding and original tests, and rerun installed candidate
acceptance after any change. Current local commits are not automatically on GitHub.
