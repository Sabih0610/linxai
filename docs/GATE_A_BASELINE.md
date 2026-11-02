# Gate A evidence — reproducible Linux application baseline

2 November 2026. Status: **IMPLEMENTED—LAB ACCEPTANCE PENDING**.
The installed ordinary-user typed workflow is implemented and tested. Gate A is
not PASS: current service.status success needs a running systemd lab, and actual
Codex Cloud execution is unavailable. No kernel/hardware acceptance is claimed.

## Source and predecessor checks

Selected repository: E:\FYP\code 2\linxai. Initial working tree was clean on
codex/cloud-handoff-2026-11-02 at
33fc8a9b5ea2ffb4b38db91d1a940bfa1110fb79. Existing remote:
https://github.com/Sabih0610/linxai.git. These Gate A changes are reviewable working
changes on that branch; no Gate A commit, push, merge or deployment was performed.
Cloud must load a future reviewed commit containing these changes, not assume
that the starting handoff commit already contains them.

Read AGENTS, scope/handoff, architecture review, original requirements inventory,
implementation/baseline/verification records and action/service contracts. Inspected
install/uninstall, main entry point, registry, service, Linux adapter, CLI, sensor
daemon/unit templates, package data, lock/setup/test/CI infrastructure. The existing
registry, OperationService, plan adapter, mandatory checks, final-operation digest,
single-use approval and audit implementation were reused. Their code is unchanged
apart from an extra installed-CLI identity gate. All original 109 regression methods
remain; the 109 count is historical, not an acceptance target.

Confirmed defect: the inherited installer required root, installed broad unpinned
system packages/Python dependencies, started model/services/PAM and generated an
`exec sudo python3 /opt/linxai/main.py` launcher. main.py already rejected root
legacy startup. The new installer resolves that conflict for the supported typed
application workflow without activating unmigrated legacy execution.

## Implemented behavior

- Ordinary-user install/remove wrappers and scripts/install_app.py manage only a
  private dedicated prefix, with an installation receipt, lock hash and verified
  wheel import path. Existing prefixes and unrelated files are preserved. Removal
  checks receipt, ownership, confinement and symlinks and retains audit/workspaces.
- setup_dev.py supports locked non-editable installation and isolated import smoke
  checks. No dependency/lock changes were necessary. No global pip, OS package,
  model, PAM, permission repair, mount or service provisioning occurs.
- Both installed launchers forward argument boundaries/JSON literally, use isolated
  Python, reject root/set-ID before app import and expose only operations.cli.
  Console entry startup separately refuses elevated identity before ledger creation.
- Native test coverage adds ownership denial using existing root-owned /usr without
  writing there, literal shell metacharacters/spaces/newlines in content, and missing
  service/manager failure. Existing traversal/symlink/overwrite, binding, authorization,
  dispatch and correlated postcondition/audit tests remain enforced.
- Missing-tool/service regressions prove validation blocks execution. Missing tools
  are mocked, not removed from the host. Real WSL service-manager absence is tested.
- Capability schema 2 adds passive OS-auth/PAM/system-bus and microphone/ALSA/tool
  evidence, explicit camera/sensor boundaries and separate OS-interpreter BCC discovery.
  It never authenticates, loads BPF, captures audio/video or starts a model.
- A disposable native lab installs the actual wheel under a prefix containing spaces,
  exercises installed launchers outside the checkout, checks/removes its installation
  and writes JSON. Skips or missing root evidence return incomplete (exit 3), not PASS.
  Root refusal through sudo -n is a separate explicit lab flag. Linux CI now runs
  this installed lab and retains its report even on failure; the new CI has not run.

## Actual evidence, separated by environment

| Check | Actual result | Boundary |
| --- | --- | --- |
| Starting Windows offline suite | 116 passed | Historical starting development baseline rerun in this task; no Linux integration |
| Final Windows offline | 125 run, 123 passed, 2 skipped; 1.573 s | POSIX argv/removal tests skipped; original 109 retained |
| Native WSL offline | 125 passed; 0.744 s | Ordinary UID/EUID 1000, CPython 3.12.3; deterministic adapters are still mocks |
| Final combined explicit native test groups | 142 run, 135 passed, 7 skipped; 28.652 s | Six optional groups/tests and absent-systemd status skip; no opt-ins enabled |
| Native backend integration | 11 run, 10 passed, 1 skipped; 6.850 s | Real disk/memory/ports/file/directory/audit; service.status success skipped |
| Native installed-wheel lab, cached/offline | 11 run, 10 passed, 1 skipped; 6.322 s | Installed current wheel/launchers, foreign cwd, private native prefix, removal passed; report PARTIAL |
| Actual installed root launcher | Exit 2, ordinary-user refusal | Separate WSL root invocation of the generated launcher; Python never started |
| Actual root installer | Exit 2, ordinary-user refusal | Shell preflight; no installation/provisioning attempted |
| New hosted Linux CI | Pending | Workflow updated; not pushed/run for these changes |
| Codex Cloud | Not executed | Accessible saved Cloud environments query returned [] with no further page |
| Desktop/hardware/device/kernel enforcement | Not executed | Probe presence/configuration is not acceptance evidence |

The native source is a manifested snapshot of the selected tracked **and untracked**
working tree, not an archive of stale HEAD. It runs from an ordinary user's native
WSL filesystem with an isolated venv. The capability/evidence artifacts include
operations hashes; the snapshot reports no mismatches. The isolated development
venv was resynced to this current snapshot before native backend tests. The wheel
import path was verified in its private site-packages, not the checkout.

Native environment: existing Ubuntu 24.04 WSL2, ordinary account, Python 3.12.3,
kernel 6.6.87.2-microsoft-standard-WSL2. PID 1 is WSL init; systemctl reports
`System has not been booted with systemd as init system (PID 1). Can't operate.`
and `Failed to connect to bus: Host is down`. No service was started to bypass it.
WSL also emits its existing `/etc/wsl.conf:1` parse warning; it was not edited.
The historical Multipass /opt/linxai/source-mount questions remain unresolved;
WSL evidence does not establish that guest's revision or deployment.

Retained failures/corrections: the first cached install failed because the pinned
uv 0.13.3 wheel was not cached. An online isolated install populated caches, then
cached install succeeded. A first Windows missing-tool test incorrectly used the
real Windows runtime check; fixing the test's mocked Linux context made it exercise
the intended mandatory-tool failure. No production check was relaxed. A Windows
documentation read hit default-encoding failure and was rerun with explicit UTF-8.
No unsuccessful attempt is presented as successful Linux acceptance.

## Acceptance and requirement evidence

| Gate A acceptance | Implementation | Native evidence / remaining work |
| --- | --- | --- |
| Supported Linux/Python/dependency matrix | Implemented | INSTALLATION.md; only Python 3.12 native in this task |
| Reproducible user installation/launchers | Implemented | Online then cached wheel install, exact arguments/content, managed removal passed |
| Ordinary startup / root refusal | Implemented | Actual user launch + separate real root refusals passed |
| Six native actions | Implemented | Five success cases passed; service.status success pending systemd lab |
| Traversal/symlink/ownership/overwrite denial | Implemented | Real native filesystem checks passed without /usr mutation |
| Missing required tools/services fail closed | Implemented | Tool/service doubles plus real unavailable WSL manager; loaded-systemd missing-unit case still pending lab |
| Capability probe | Implemented | Passive native inventory executed; no device/auth/BPF acceptance |
| Cloud checks / isolated lab runner | Implemented runner/CI | Actual Cloud unavailable; updated CI and full systemd lab pending |

Original inventory coverage advances 15–20 (validation), 22–25 (typed execution,
bounded deadlines/results), 58–59 (operation audit) and 63–64/66–68/70 (installation,
configuration/integration/compatibility). These are **partial requirements**, not
claims that entire features are accepted. Item 65 independent sensor deployment
and item 69 full integration remain pending. REQUIREMENTS_TRACEABILITY.md retains
all 1–72 identifiers and the separate agreed extensions. Original missing PDF/SRS
source requirements remain unknown; no fabricated IDs or performance results.

## Remaining gaps and exact next step

On a reviewed disposable Ubuntu 24.04/systemd lab, ordinary account, native checkout
containing these working changes, supported Python and existing loaded dbus fixture:

```sh
python3 scripts/setup_dev.py
.venv/bin/python -B scripts/test.py offline
.venv/bin/python -B scripts/test.py linux
.venv/bin/python -B scripts/capabilities.py --output capabilities-gate-a.json
LINXAI_TEST_SERVICE=dbus .venv/bin/python -B scripts/run_gate_a_lab.py \
  --check-root-rejection --report gate-a-lab.json
# After initial package cache population:
LINXAI_TEST_SERVICE=dbus .venv/bin/python -B scripts/run_gate_a_lab.py \
  --offline --check-root-rejection --report gate-a-offline-lab.json
```

The root-refusal flag requires existing passwordless sudo only for the negative
startup test; do not alter authorization to satisfy it. Capture verbose results,
zero skips, report exit/status, source revision/hashes and OS package versions.
Publish a reviewed candidate only when requested, then run the updated CI and any
accessible Cloud checks. Do not mark Gate A PASS before missing acceptance evidence
is supplied. Next implementation gate after acceptance: B, trusted broker/OS auth
using the existing registry/service; keep privileged actions blocked meanwhile.

Full desktop/durable jobs (C), independent monitoring/detection (D), enforcement
and policy memory (E), provisioning/DevOps/remote/device/SOC/resource workflows (F),
account-bound face/password/voice (G) and measured release/load acceptance (H)
remain outside this milestone. The retained legacy main pipeline, remote executor,
sensor scripts and PAM prototypes are not silently migrated or enabled.

Changed files: .gitattributes; .github/workflows/linux.yml; AGENTS.md; README.md;
install.sh; uninstall.sh; operations/cli.py; scripts/setup_dev.py;
scripts/capabilities.py; scripts/test.py; scripts/install_app.py;
scripts/run_gate_a_lab.py; test_gate_a.py; tests/test_linux_integration.py;
docs/INSTALLATION.md;
docs/GATE_A_BASELINE.md; docs/CLOUD_HANDOFF.md; docs/DEVELOPMENT_ENVIRONMENT.md;
docs/IMPLEMENTATION_PLAN.md; docs/VERIFICATION.md; docs/ENVIRONMENT_BASELINE.md;
docs/REQUIREMENTS_TRACEABILITY.md; and sanitized docs/evidence/gate-a records.
