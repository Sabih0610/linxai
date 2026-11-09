# LINxAI verification record

## Foundation regression suite

Run from the repository root with Python 3.11 or later:

```text
python3 -m unittest test_safety_regressions -v
```

The suite uses the standard library. Model HTTP calls are replaced with test doubles;
real subprocess creation and network connection helpers are forbidden during tests.
It does not install dependencies, start services, change configuration or signal processes.
It validates plan shape, cache handling, check failure/deadline behavior, conditional
request routing, retry gating and disabled automatic generated rollback.

The first foundation batch passed 41 test methods on Windows against staged changes
and untouched source dependencies. Some methods cover multiple malformed cases or
request variants through subtests. This is not 41 real Linux integration scenarios.
The final installed-source run is recorded in the accompanying delivery evidence.

Installed-source verification on 1 November: all 41 test methods passed in
0.283 seconds using the bundled Windows Python runtime. All 39 Python source/test
files parsed successfully. Lightweight public imports remained available without
the HTTP client installed. Git diff whitespace checking passed after normalization.
These times describe offline checks, not model or threat-detection performance.

The documented model prompt examples are also parsed as JSON and validated. This
found and repaired a quotation error in the example for querying port 80.

## Intentional behavior changes

- An unknown/unavailable/failed required check now blocks instead of approving or warning.
- Incomplete/over-budget validation blocks, including an overrun on the final check.
- Unsupported conditional requests decline before cache/model use, so a stale plain
  port query cannot replace a conditional service operation.
- A generated rollback is retained as a suggestion but is not automatically executed.
  Failed operations report that state-based recovery needs implementation.
- A missing/unknown CLI validation decision is blocked.

## Limits

Schema validity is not authorization. Action-derived checks and privilege policy are
still required. The current synchronous check budget does not interrupt a running OS
query. Generic shell execution and alternate operation paths remain audit findings.
Automatic threat response remains disabled by default. There is no implemented
AI response-policy memory or demonstrated kernel prevention in this batch.

Windows denied execution of E:\FYP\multipass\bin\multipass.exe during the read-only
baseline attempt. The VM mount/revision, Linux integrations and hardware tests remain
unverified; no permissions or VM settings were changed to work around this.


## Typed action registry regression evidence (1 November 2026)

The preserved foundation suite was rerun before the registry change: **41 tests
passed in 0.484s**. Then the selected working source was tested with:

```powershell
Set-Location -LiteralPath 'E:\FYP\code 2\linxai'
& 'C:\Users\sabih\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest test_safety_regressions test_action_registry -v
```

On bundled Windows CPython 3.12.14, **71 tests passed in 0.467s** (41 unchanged
foundation tests plus 30 new registry tests), exit code 0. No dependency failure
occurred. This runtime still does not have `requests`; these suites require no
real model HTTP client. Python 3.11+ is required for the existing test suite's
`unittest.TestCase.enterContext`.

New offline coverage includes all action contracts; immutable normalized data;
mandatory checks despite omitted/empty model preconditions; independent privilege
requirements despite model claims; explicit rejection of malformed service names,
ports, paths and ambiguous/unsupported slots; preservation of supported conditional
fast-path plans; workspace configuration and containment; no command parsing or
shell fallback; separate content stdin; and fixed creation-program descriptor,
exclusive/no-follow flags and root refusal using mocked OS calls.

The new tests forbid live subprocess launches, network connections, `os.system`,
`os.open` and `os.mkdir`. Creation-program tests inject fake OS/stdin modules;
they do not create actual files or change services. Production registry preparation
performs no live checks or execution. Check identifiers are required contracts for
the future service, not a report that the Linux checks passed. The old CLI remains
on its legacy execution path.

No VM, service, mount, permission, PAM, package or model changes were made. Linux
command compatibility, actual BCC/model availability, real service postconditions,
filesystem symlink/rename races and authentication/authorization remain unverified.
Review `docs/ACTION_CONTRACTS.md` before connecting any execution path.


Final review reproduced a path-length defect with one targeted failing test:
a 4095-byte relative path had passed its input bound even though adding the
workspace root exceeded the bound. The registry now also validates the anchored
absolute path. A cached-plan/nested-condition immutability regression was added.
The final combined run of the same command above passed **72 tests in 0.396s**
(41 original plus 31 new), exit code 0. The earlier targeted failure was a code
defect found and fixed during this change, not a dependency/environment failure.

Post-change checks parsed all 44 Python files and passed Git/new-file whitespace
checks. Hash comparisons preserved 61 pre-existing files and the baseline report;
the existing implementation/verification records retain their original content,
with milestone evidence appended and the test minimum corrected to Python 3.11.


## Shared operations service evidence (1 November 2026)

Before changes, the existing 41 foundation plus 31 registry tests passed:
**72 tests in 0.359s**. The first service batch passed **103 tests in 0.588s**.
Review reproduced a CLI defect with one targeted failing regression: an explicitly
empty `--operation-params` string was being replaced with `{}`. It now reaches
validation and is rejected. Duplicate JSON keys are also rejected. Subsequent
coverage added private-ledger temporary-file round trips, incomplete verification,
unknown execution outcomes and expiry during pre-dispatch revalidation.

Final combined command, from `E:\FYP\code 2\linxai`:

```powershell
& 'C:\Users\sabih\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest test_safety_regressions test_action_registry test_operations_service -q
```

**109 tests passed in 0.587s**, exit code 0, on bundled Windows CPython 3.12.14:
41 unchanged foundation tests, 31 unchanged registry tests and 37 new lifecycle,
adapter, audit and CLI tests. The targeted intermediate failure was a reproduced
code defect fixed in this change, not a dependency/environment failure. The final
suite had no failures or missing dependencies. No model HTTP client is required.

Demonstrated with trusted system doubles and isolated `TemporaryDirectory` assets:

- Read workflows complete with one UUID/fingerprint across validation, execution,
  verification and ledger records. CLI calls the same service without constructing
  the legacy pipeline or silently falling back on error.
- Disallowed/root/setuid/malformed identities, client permission claims, unsupported
  actions and malformed parameters do not execute. Administrative actions remain
  broker-required even with an overly permissive injected policy.
- Missing/malformed/failed/late/uncorrelated checks block. Modified action, parameter,
  target, argv, stdin, check list, postconditions or timeout cannot reuse approval.
  Replay, expiry, changed identity/policy/configuration/state also block dispatch.
- Execution failures do not trigger verification or generated rollback. Missing or
  failed postconditions cannot produce success; a deliberately corrupted disposable
  file remains visible for review with recovery unsupported.
- Adapter exceptions/unmatched execution IDs report unconfirmed side effects.
  Audit errors before execution prevent it; post-execution audit errors retain
  known side effects with an explicit incomplete-audit result.
- Mocked subprocess adapters assert exact arrays, shell=False, stdin isolation,
  controlled environment, cwd and deadlines. Timeout/launch/output-limit cases fail.
- Private JSONL round trips use real temporary files with mocked POSIX ownership,
  permissions, flags and locking. This tests serialization/correlation and rejection
  branches, not native Linux ACL, O_NOFOLLOW or flock semantics.

`python -B -m operations.cli --help` passed without loading the model stack. No
real service command, privileged action, Linux file-creation subprocess, model,
network mutation, installer, PAM or Multipass change was run. Production Linux
adapters are implemented but native integration remains unverified. See
`docs/OPERATIONS_SERVICE.md` for the precise remaining gaps and legacy boundaries.

Final source checks parsed all 49 Python files and passed `git diff --check` plus
new-file whitespace checks. Existing main-entry-point CRLF warnings were resolved
only in the edited CLI tail; the prior pipeline/foundation body is preserved.
Hash verification found 66 pre-existing files unchanged, including all registry
code, both existing suites and the baseline report. The three updated records
retain their original byte prefixes, with this milestone's evidence appended.


## Cloud handoff and development environment (2 November 2026)

Earlier 41/72/109-test results above are historical Windows evidence. Fresh setup
uses `pyproject.toml`/`uv.lock`, separate optional profiles, an isolated app venv,
explicit safe test groups and ordinary-user Linux CI. The old installer is not used.
See `DEVELOPMENT_ENVIRONMENT.md`, `CLOUD_HANDOFF.md` and the measured capability report.

Actual checks: Windows offline **116 passed in 1.004 s**; final sequential WSL
ordinary-user combined group **131 run, 124 passed, 7 skipped in 8.820 s**. The
native subset **9 run, 8 passed, 1 skipped in 5.342 s** includes real resource/port
reads, private file/directory creation and ledger verification, denial cases and the
installed console launcher. Service status skipped because WSL is not running
systemd; six kernel/desktop/hardware/model tests remained opt-in and skipped.
The original 109 test methods and production operations implementation are preserved.

Online Windows/native Linux installation and cached/offline native setup succeeded.
uv 0.13.3 resolved 47 pinned packages; `uv lock --check --offline` passed. Only default
app/development dependencies were installed; no AI/model/desktop/hardware/sensor
provisioning occurred. CI actions are pinned to verified official commit IDs.

Retained failures: DrvFS venv/editable-metadata mode errors required native Linux
source plus venv storage, not a permissions change. A test run overlapped setup and
hit the existing directory-worker deadline once; sequential targeted/full reruns
passed without changing the timeout/assertion. This timing sensitivity remains
reported in `CAPABILITY_REPORT_2026-11-02.md`, not erased or called load acceptance.

The native source snapshot verified 93 files with zero mismatches and all eight
operations hashes equal to the selected E: tree. It had no Git metadata; its old
parent SHA plus file manifest identifies the pre-commit working source. The handoff
commit identifies the final source. Actual Cloud, systemd/privileged actions, desktop,
camera/voice, BCC/enforcement, model and full release acceptance remain pending.


## Gate A candidate verification (2 November 2026)

Status: IMPLEMENTED—LAB ACCEPTANCE PENDING, not PASS. Detailed source identity,
commands, environment matrix, negative cases, failures/corrections and pending
procedures are in GATE_A_BASELINE.md and INSTALLATION.md. Starting revision:
33fc8a9b5ea2ffb4b38db91d1a940bfa1110fb79, branch
codex/cloud-handoff-2026-11-02; Gate A is uncommitted reviewable working changes.

Actual Windows command: .venv-windows\Scripts\python.exe -B scripts/test.py offline:
125 run, 123 passed, 2 POSIX-only skips, 1.573 s. Native Ubuntu 24.04 WSL2 ordinary
UID/EUID 1000, CPython 3.12.3: scripts/test.py offline 125 passed (0.744 s);
scripts/test.py linux 11 run, 10 passed, 1 skipped (6.850 s). The cached/offline
scripts/run_gate_a_lab.py installed a non-editable wheel under a private prefix
containing spaces, tested installed CLI calls outside source and removed it:
11 run, 10 passed, 1 skipped (6.322 s), report PARTIAL. service.status success
requires real systemd and remains pending. Real unavailable-manager requests
failed validation. Mandatory unavailable-tool/service tests use adapter doubles;
these are not native package-removal or service-state evidence.

Separately executed actual installed launcher and installer as WSL root: both
exit 2 before application imports/provisioning; ordinary-user managed removal
passed afterward. No real service mutation, OS package install, PAM edit, host
permission/mount/security change, model startup/download, device capture or BPF
attach occurred. New files/directories were private disposable user fixtures.

Current passive capability inventory is not authentication, GUI, camera,
microphone, monitoring or target-kernel enforcement acceptance. Codex Cloud saved
environments query returned []: no actual Cloud checks executed. Updated hosted
Linux CI is pending publication/run; previous green handoff CI is historical.
Review git diff (including untracked inputs) and git diff --check before committing.
Native source snapshots use working-tree manifests; operation hashes are retained
in sanitized docs/evidence/gate-a artifacts. Full systemd-lab commands and explicit
root-refusal opt-in are in INSTALLATION.md. Never change a skip to a fake success.

Final combined native explicit groups: scripts/test.py all ran 142 tests in
28.652 s, with 135 passed and 7 skipped (absent systemd plus six opt-in kernel/
desktop/hardware/model tests). Zero failures/errors. No opt-ins were enabled.
Sanitized run artifacts: docs/evidence/gate-a/{wsl-probe,installed-lab,root-denial-and-os}.json.


## Gate B implementation checkpoint — 2 November 2026

Implemented production broker transport, OS peer identity, root allowlist, polkit
exact-operation authorization, persistent replay admission, service/TCP checks,
verified state, private root audit, bounded supervision and protected packaging.
See BROKER.md. Default OperationService administrative refusal remains intact.
Original IDs 15–26, 29, 58–59 and 63–70 advance partially; no source IDs removed.
Windows broker contracts: 10 run, 9 passed/1 Linux peer skip; real Linux/native
checks follow. Real polkit/service acceptance remains pending without systemd.
This pending target acceptance does not block C–H independent implementation.

Gate B actual current native combined run: 155 run, 148 passed, 7 skipped in
7.714 s. Includes real socket peer credentials, bounded output/time processes,
private SQLite persistence and symlink denial. No actual auth/service mutations.
Windows combined: 135 run, 132 passed, 3 skipped in 1.391 s before the added
post-dispatch storage-failure regression. Deployment tar built, never installed.


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

Gate D native combined safe suite: 175 run, 167 passed, 8 skipped in 11.399 s.
No BCC/kernel hook was loaded. The separate pinned Qt environment installation
completed; desktop workflow execution is now running separately.


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

E native combined safe run: 186 run, 178 passed, 8 skipped in 11.365 s.
Read-only root inspection of /sys/kernel/security/lsm returned No such file or
directory in WSL; no active BPF LSM acceptance can be inferred from config flags.
TCP-specific kernel provenance and bounded model retry refinements were added
after that combined run and pass the 15 focused policy/detector tests; their actual
BCC compilation remains pending. No privileged service/hook was installed.


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

Gate G final Qt offscreen: 3 tests passed in 6.899 s. Real Qt event loop, deterministic backend and voice stand-in; stale asynchronous preview rejected. No physical desktop/microphone evidence. Pinned uv lock check passed.


## Gate H integrated development candidate — 3 November 2026

Status PARTIAL. Full source/acceptance boundaries and procedures are in
RELEASE_CANDIDATE.md. Original requirement IDs 1–72 are preserved with separate
implementation/evidence/pending columns. No full-scope release PASS is asserted.

Actual current checks:
- Windows CPython offline suite: 180 run, 177 passed, 3 POSIX skips, zero failures/
  errors (2.604 s). Original 41 foundation and existing registry/service tests retained.
- Ordinary Ubuntu 24.04 WSL CPython 3.12.3 combined explicit groups: 212 run,
  202 passed, 10 skipped, zero failures/errors (30.107 s). Skips: no running
  systemd service.status plus nine separately opt-in kernel/desktop/hardware/model tests.
- Three real Qt offscreen tests passed separately (latest 0.586 s): preview/confirm,
  voice stand-in to preview without confirmation, stale async preview refusal.
  Real Qt is evidence; deterministic backend/voice remains a stand-in.
- Fresh offline installed desktop candidate: seven steps all exit 0. Locked clean
  wheel installation, installed 20-action/face/voice/SSH-metadata imports, actual CLI
  memory read, actual agent natural-language job and Python project, installed Qt
  window and managed uninstall. Imports verified inside installed venv from foreign cwd.
- New native concurrent audit rotation, unsafe archive and oversized-record denial
  passed. Audit files retain four bounded 8 MiB generations under a shared private
  lock; unsafe files or failed writes block admission rather than suppress evidence.
- Short actual read/audit soak: 10.000766 seconds, 11 verified operations, 0 failures,
  54,425 retained audit bytes. This limited workload is NOT 24-hour system stress.
- Pinned uv lock check passed; 58 current module/script files parsed; Linux CI YAML
  parsed; all 72 original IDs checked in order. Hosted CI execution remains pending.

A first installed candidate failed because stale checkout build/lib was reused by
setuptools: an old registry reached the wheel alongside the current agent. Source
unit tests passed and did not reveal it. Fixed non-editable builds by copying only
current declared application inputs into a new temporary source directory; existing
checkout build output was preserved. The repeat installed workflow passed. A later
inspection found legacy Paramiko imported by typed metadata; lazy compatibility
exports plus core/installed coverage fixed that dependency leak. No tests were weakened.

Cloud tests actually executed: NONE for B–H. Native Linux lab: WSL ordinary-user
files/process/IPC/installed Qt evidence above. Real privileged broker/polkit,
systemd success/lifecycle, BCC attach/LSM enforcement, SSH authentication/vendor,
physical camera/spoof/microphone/WER, real-model and 24-hour acceptance: NOT RUN.
Hardware/device tests actually executed: NONE; development-file adapter and model/
kernel/hardware doubles are explicitly simulations. All target commands/procedures
are in RELEASE_CANDIDATE.md and per-component guides. Primary face and automatic
response remain disabled in supplied root examples. No host mounts, PAM, security
settings or operational services were modified to obtain passing tests.


## Current integrity and artifact verification follow-up — 3 November 2026

The packaged 0945a13 candidate passed manifest/source/wheel/protected-code hash
verification and five actual Linux artifact steps: locked dependency installation,
replacement by the exact hashed wheel, installed agent/project workflow, CLI memory
read and managed uninstall. It is a historical checkpoint, superseded by the new
approval/storage fixes. scripts/verify_candidate.py now automates this artifact
procedure and rejects tampered wheels or self-consistent protected archives whose
code differs from committed source. Neither artifact verification nor source
hashes establish signed provenance, root deployment or hardware acceptance.

Final review reproduced two durable-job binding defects with failing regressions:
asset retargeting after preview, and changed queued requests after confirmation.
Both are fixed; execution-factory scope and restart expiration are also covered.
Existing mandatory checks, trusted identity/authorization and service approval
binding are preserved. Deep remote nesting now rejects before recursive planning.

Three expanded native runs encountered observation deadlines under high I/O:
214 run/10 skips with 1 failure+1 error (148.554 s); repeat 214 with 1 failure
(117.592 s); 215 with 1 failure+1 error (169.837 s). Both initially failing cases
passed unchanged in isolation (2 tests, 5.147 s). A read-only pressure snapshot
showed I/O some/full avg60 approximately 38%, with CPU/memory avg10 zero; this
suggests contention, not a proven sole cause. These failures are preserved rather
than relabelled as passes. No host security or filesystem settings were changed.

Review removed redundant directory sync and repeated SQLite schema-header writes,
while keeping every ledger fsync and rejecting unknown schema versions. It also
corrected integration observation windows: the previous roughly two-second agent
wait was shorter than the existing five-second action plus three validation phases;
the pipe peer used ten seconds while the existing remote transport allows thirty.
Harness observation now derives from those existing contracts. Production command,
validation, expiry, authorization and output limits are unchanged; all success,
postcondition and replay assertions remain. This is not latency acceptance.

The resulting combined native run: **219 run, 209 passed, 10 skipped, zero failures/
errors in 159.833 s**. This includes all approval/storage fixes. The subsequent
remote-nesting regression is additionally verified separately; later final records
identify the exact current totals. Full target/Cloud/new hosted CI/hardware and
24-hour acceptance remain pending, independently of passing logic/integration tests.


Current complete suites after all integrity and nesting fixes: Windows **186 run,
183 passed, 3 skipped**, zero failures/errors (3.479 s); native WSL **220 run,
210 passed, 10 skipped**, zero failures/errors (24.053 s). See candidate/
windows-current.json and native-final-suite.json. Older failing runs remain in
native-timeout-*.json. The speed difference between runs is not a performance
benchmark. Installed/artifact verification of this new committed source follows
separately; the 0945a13 artifact record is historical. No security deadline or
success assertion was removed, and no unavailable target feature was simulated
and relabelled native.


Final fixed code checkpoint: **0cb5a907a38639d3adc516dfc20b7c3149a23a28**.
Two offline builds produced identical wheel/source/protected-archive hashes in the
same environment. Exact packaged wheel SHA256 is
16b3c1a244049ac67b76e6b4fd3f7e2a7dd2e4ca099b52ec613111e1e4f7645f.
Five actual Linux artifact steps all passed: locked dependency installation, exact
wheel replacement, installed agent/project workflow, CLI memory read and managed
uninstall. See artifact-0cb5a90.json and reproducible-0cb5a90.json. This new wheel
contains the resolved-target/queued-work/factory binding and storage fixes; the
0945a13 artifact is superseded. A later evidence-only commit changes documentation
without changing tested application/protected code. Gate H remains PARTIAL because
original implementation breadth and real target/hardware acceptance are unfinished.
Remote read verified branch codex/cloud-handoff-2026-11-02 still at 33fc8a9; current
local implementation commits were not pushed. Cloud/new hosted CI were not executed.


## Gate B target acceptance — VirtualBox Ubuntu 24.04.4 VM, 8 November 2026

**PASS (bounded service route).** On a VirtualBox guest (Ubuntu 24.04.4, kernel
6.8.0-124, systemd 255, polkitd 124) with the owner logged in on the local console
(`tty1`, `seat0`, `Remote=no`, `Active=yes`), `LINXAI_TEST_BROKER_LAB=1 python3 -B
scripts/accept_broker.py` exited 0. Four real one-shot polkit authentications with
the owner's OS password authorized `service.start`, `service.restart`,
`service.stop` and the validated restoration of `linxai-lab-acceptance.service`;
each returned `succeeded`, `executed=true`, `verified=true`. An earlier run on the
same target, where the lab wrapper registered the text agent for the wrong process,
failed closed (`authentication_authorization_required`, nothing executed, no retry).
Code was commit f3519e8 (byte-identical after CRLF normalization). Evidence:
docs/evidence/vm-lab-2026-11-08/. Not covered: root audit ledger export, deliberate
cancellation/wrong-password denial, desktop agent, broker reboot lifecycle.

WSL finding the same day: after enabling systemd in WSL, polkit still denied every
`allow_active`-only action because WSL has no logind seat, including from a PAM
login session. WSL therefore cannot host Gate B approval acceptance under the
shipped policy; it remains suitable for unprivileged Linux tests.

## Gate D monitor target run — same VM, 8 November 2026

**Acceptance FAIL; real capture works.** With the root BCC sensor deployed from
an LF build of f3519e8 (hash-identical to committed blobs), all three probes
attached on kernel 6.8.0-124 with `kernel_lost=0`, and events carried
`kernel_start_identity`. `LINXAI_TEST_KERNEL=1 scripts/accept_monitor.py` refused
because sensor health was `degraded`. Measured on an idle VM: ≈140 events/s
arriving, ≈75/s published, median kernel→sensor latency 25 s, `queue_dropped`
19622 after four minutes. A labelled diagnostic captured a `/tmp` exec 67 s late,
lost the `/etc/shadow` attempt, and produced no incident because the monitor
(≤32 events per 0.5 s) was 660 events behind. Causes: per-event fsync'd SQLite
prune+insert on the capture thread, unfiltered `openat`, non-IPv4 `connect`
events rejected as invalid, monitor rate ceiling, and sticky degraded health.
Evidence: docs/evidence/vm-lab-2026-11-08/monitor/.

**Gate D rerun after throughput fix — PASS.** Batched durable writes, a pre-queue
relevance filter, recoverable health and a draining monitor (uncommitted patch in
docs/evidence/vm-lab-2026-11-08/monitor/) brought the sensor to `ready` with zero
queue/kernel/invalid/storage loss on the same VM. `LINXAI_TEST_KERNEL=1
scripts/accept_monitor.py` exited 0: both actions captured with
`kernel_start_identity` in ≈230 ms and both incidents produced by the independent
monitor. Steady-state kernel→sensor latency median 1.6 s, p95 2.6 s (observation).
Offline suite: 193 run, 189 passed, 4 skipped, 0 failures; 14/14 monitor tests on
the VM including a real-SQLite atomic batch test.

## Development checkpoint — requirements 41 and 46–50 (uncommitted), 8 November 2026

Security-aware preview warnings, typed process inventory, identity-bound priority
lowering with captured admin restoration, and a short-window resource forecast
were added on top of the Gate D fix. Windows offline group: 209 run, 201 passed,
8 skipped (Linux-only), 0 failures. VM (Ubuntu 24.04.4, ordinary user): the same
group ran all 209 with 0 skipped and 0 failures, including native lowering of a real
child process (0→7, verified), refusal of a stale start time and of raising
priority, and a verified `resource.forecast`. Broker/polkit acceptance of
`process.priority.restore` needs the updated policy file deployed and is pending.

## Measurements — resources, intents, 8 November 2026

Resource benchmark (requirement 51): `scripts/bench_resources.py` pins itself to N
CPUs and runs five background scenarios sized per CPU. In WSL2 (N=2) lowering the
background to nice 19 through the typed action cut foreground CPU-task time by
27–78 % and wake-up p95 by 74–87 % under oversubscription. On the VirtualBox VM
(N=1) CPU-task time fell 31–79 %; the VM's wake-up latency is hypervisor-bound and
inconclusive. An earlier unpinned run with 8 hogs on the 2-vCPU VM caused guest soft
lockups (VirtualBox on Hyper-V/NEM) and was discarded; the VM had to be reset.

Intent evaluation (requirement 3): `scripts/eval_intents.py`, local
`qwen2.5:1.5b` (host Ollama; the VM is too slow for inference). Final: 15/15 unsafe
or unsupported requests refused, 0 false actions; 100 % tuning / 73.3 % held-out
action accuracy. Two misclassifications found in earlier runs were fixed with
pre-model refusals (account/credential changes, destructive disk operations) and
regression tests. Offline group on Windows (CPython 3.12): 242 run, 232 passed,
10 skipped (Linux-only), 0 failures. With the default CPython 3.14 three
dev-environment tests error by design (supported range 3.11–3.13).

Pending admin step (cannot be automated: the owner types the password at the VM
console): deploy the current bundle and polkit policy, start the sensor, then
`run-restore.sh` (49), sensor overhead (44) and the 24 h soak (72).

Node recipe: `tests.test_native_workflows` on the VM ran 5 tests; the new
`project.node` test passed (real worker, `node --check` on the generated file,
owner edit refused). VM offline group: 242 run, 0 skipped, 0 failures. VM `linux`
group: 26 run, 2 failures that are environment prerequisites, not regressions —
the installed console launcher is absent (locked setup not run on the VM) and the
remote-peer test needs the installed `operations` package on the peer interpreter.

## Sensor overhead and soaks — VM, 9 November 2026

After the owner's admin step (`admin-session.sh`, bundle sha256 9d739d3d…, broker
and BCC sensor active, 3 kprobes, not enabled at boot):

- Sensor overhead (44), user-space sensor process: 0.93 % of one vCPU over 180 s
  idle, 1.43 % during the pinned benchmark. Foreground CPU-task times with and
  without the sensor differ by −5.5 % to +5.0 % across idle and the ten loaded /
  optimized measurements, i.e. within run-to-run noise; no measurable slowdown.
  In-kernel probe cost is charged to traced tasks and not separated.
- Operations-only soak (72, partial, 8 h, before the sensor was deployed): 950
  cycles, availability 99.89 %, op latency p95 0.605 s, 3 host pauses totalling
  405 s reported separately.
- Full integrated 24 h soak started (typed reads, sensor health, monitor
  freshness, RSS, hourly detection probe); first probe detected in 2.0 s.

Priority restoration acceptance (49), VM console, owner session: an owned child
was lowered 0→10 by the unprivileged typed action (verified), a restore above the
nice-0 floor (−5) was refused before dispatch, and `process.priority.restore` went
through the root broker after polkit `auth_admin` (`org.linxai.process.manage`):
status succeeded, verified, audit complete, final nice 0, 1 thread changed, 0
failed. PASS. Evidence: `restore/restore-acceptance.json`.

## Network/attack-tool detection and real SSH remote operations — VM, 9 November 2026

Detection (38, 39): new model-free rules `shell_network_connection` (shell or raw
network tool opening an outbound TCP connection), `attack_tool_execution` and a
wider backdoor-port list. `scripts/accept_detection.py` on the real kernel with the
deployed sensor and monitor: bash `/dev/tcp` reverse-shell shape 0.32 s, `nc` 0.23 s,
port 31337 0.26 s, `nmap`-named exec 0.55 s — all with `kernel_start_identity`;
benign controls (curl, python connect, `bash -c true`, ls) raised no incident.
PASS (`detection-network.json`). A first run reported the fixture's own incident as
a false alarm because the control window overlapped it by its 1 s slack; the window
was fixed, not the rule. The monitor was restarted once (≈10 s) during the 24 h soak
to load the new rules.

Remote (52–57): `lab-scripts/remote-setup.sh` (ordinary user: dedicated key with a
`restrict` authorized_keys entry, pinned known_hosts, peer venv) and
`scripts/accept_remote.py` over real `/usr/bin/ssh`. Two configured assets — the VM's
loopback and NAT address, i.e. the same machine — each verified memory, disk and
`ssh.service` status end to end (1.6–3.2 s). Host-key mismatch: execution failed,
host-key error reported. Raw shell, nested remote and unknown asset refused before
SSH. Replayed operation id: first exit 0, second refused. PASS
(`remote-acceptance.json`). Physically separate servers remain untested.

Windows offline group (CPython 3.12) after these changes: 243 run, 233 passed, 10 skipped (Linux-only), 0 failures.
