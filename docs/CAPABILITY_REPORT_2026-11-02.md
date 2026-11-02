# Actual development capabilities and verification — 2 November 2026

This is fresh local development evidence, separate from the historical Windows
reports and from any future Codex Cloud/CI result. No Cloud runtime was provisioned
or inspected from this local chat. Do not treat WSL UID 0 as dedicated-kernel control.

## Source used

Primary repository: `E:\FYP\code 2\linxai`, initially `main` at
`51e54c6888bddcfec07cd544acc295b3ce833e45` with later source uncommitted/untracked.
Work is prepared on `codex/cloud-handoff-2026-11-02`. The final commit containing
this file identifies the handoff; the old parent alone does not identify the code tested.

Native tests used a selected-working-tree snapshot containing **93 files**, including
tracked and untracked implementation, with **zero manifest hash mismatches**. It was
copied to `/home/sabih/.cache/linxai-development/source-2026-11-02` because Windows
mounts rejected venv/metadata file-mode operations. This snapshot intentionally has
no `.git`; its report's `git rev-parse` fails honestly and records the old parent and
manifest instead. It is not a stale clone of the old commit.

All eight operations-module SHA-256 values match the selected Windows source.
The complete measured fingerprints and machine evidence are in
`evidence/linux-2026-11-02.json`; Windows evidence is in the companion JSON.
The three key current implementation fingerprints are:

| Module | SHA-256 |
| --- | --- |
| `operations/registry.py` | `a6e4cc6955ca390d3938eefe5f777e946dded540f63fb3d5444c821fc1bad019` |
| `operations/service.py` | `28ab970b2ece4ddcdfd348845ece7cc923c2e98887d403a4e2117a4119dffa69` |
| `operations/system.py` | `f34aea041cf9927b1ea1063b0f89daa42e7568e53c4313bb58ed77a9dd64f140` |

## Measured environments

| Capability | Windows host | Native WSL test environment |
| --- | --- | --- |
| OS | Windows 11 build 26200 | Ubuntu 24.04.3 LTS, glibc 2.39 |
| Python | Isolated CPython 3.12.14 | Isolated CPython 3.12.3 |
| App environment | `.venv-windows` in selected source | `/home/sabih/.cache/linxai-development/venv-2026-11-02` |
| Package tooling | uv 0.13.3; locked sync succeeded | pip 24.0 bootstrap, uv 0.13.3; locked and cached/offline sync succeeded |
| Installed defaults | linxai 0.1.0, PyYAML 6.0.3, psutil 7.1.3, uv 0.13.3 | Same pinned application/development packages |
| Identity | Windows user; POSIX identity unavailable | Tests ran as existing `sabih`, UID/EUID 1000; effective capability mask zero |
| Default WSL identity | Not applicable | Default distro launch is root; switched explicitly to existing ordinary account without user/security changes |
| Service manager | No Linux systemd | `systemctl` exists, but PID 1 is WSL init; `/run/systemd/system` absent |
| Resource/socket tools | Linux tools absent | `/usr/bin/df`, `free`, `ss` available and exercised |
| GUI | No Linux GUI context | DISPLAY/Wayland configured, X11 and Wayland sockets present; Qt/actual desktop not tested |
| Camera | No Linux device context | No `/dev/video*` device exposed |
| BCC | Not available in app environment | `bcc` absent from app and probed OS Python; no install attempted |
| Ollama/model | Windows executable found, not started/queried | Ollama not on PATH; no model download or inference |

Kernel: `6.6.87.2-microsoft-standard-WSL2`. Read-only configuration reports
CONFIG_BPF, BPF_SYSCALL, BPF_EVENTS, BPF_LSM and KPROBES enabled; BTF vmlinux exists.
Active securityfs LSM list was unavailable. These are capability clues only: no
probe compilation/attachment, BPF LSM policy, enforcement or dedicated-kernel
ownership/control was established. The root inspection's broad capability mask
does not change that conclusion. BCC must be supplied/tested with the sensor OS
interpreter separately from the app venv.

WSL emits `Expected ' ' or '\n' in /etc/wsl.conf:1`. Existing commands nevertheless
ran; no attempt was made to edit WSL configuration, enable systemd, change mount
permissions, grant capabilities or alter host security to make tests pass.

## Commands and actual results

| Check | Result |
| --- | --- |
| Pinned dependency resolution | 47 packages resolved into `uv.lock`, including optional profiles; no optional weights downloaded |
| Windows isolated setup | Succeeded; installed typed console launcher `--help` works |
| Windows offline group | **116 run, 116 passed**, 1.004 s |
| Windows Linux group (before added launcher check) | **8 skipped**, explicitly native-Linux-only |
| Native Linux setup | Succeeded from source-verified native copy; cached `--offline` re-sync also succeeded |
| Initial native combined group | 130 run, 7 skips, no failures, 17.387 s (before added launcher check) |
| Sequential native integration rerun | **9 run, 8 passed, 1 skipped**, 5.342 s |
| Final sequential native combined group | **131 run, 124 passed, 7 skipped**, no failures/errors, **8.820 s** |
| Dependency consistency | `uv lock --check --offline` passed |

Final native command:

```sh
cd /home/sabih/.cache/linxai-development/source-2026-11-02
/home/sabih/.cache/linxai-development/venv-2026-11-02/bin/python -B scripts/test.py all
```

The final total includes 109 preserved original regressions, 7 new setup contracts,
9 unprivileged Linux checks and 6 explicitly gated optional checks. The 7 skips are
one real service-status fixture (systemd not running) plus the 6 optional checks
whose opt-in flags were unset. No assertion was removed or timeout increased.

Demonstrated native behavior: disk/memory/listening-port reads; file creation with
exact content; directory creation; real private JSONL correlation; traversal,
overwrite and symlink rejection; altered approval rejection; administrative dispatch
blocked; installed console launcher runs a verified memory query as ordinary user.
Service-status execution, three privileged service changes, GUI, camera, voice,
real models and kernel enforcement are still skipped/pending, not inferred successes.

## Failures encountered and retained

- Creating a Linux venv directly on `/mnt/e` failed with `PermissionError: [Errno 1]
  Operation not permitted` during file mode setup. Moving only the venv was not
  sufficient: setuptools editable metadata writes in the mounted source also failed.
  A native Linux snapshot and native venv resolved these setup-environment failures
  without chmod/chown, WSL mount edits or system package installation.
- One 131-test run overlapped a package rebuild and recorded a directory worker's
  existing five-second deadline failure (one failure, seven skips; 62.709 s).
  The overlap was an orchestration error, and timing sensitivity is retained as an
  observed limitation rather than asserted to be a proven root cause. After setup
  completed, the targeted Linux group and final full sequential group both passed
  with the original timeout and unchanged production code. This is not load acceptance.
- Some scratch-output creation in Windows Documents was denied. Evidence was emitted
  on stdout or through ignored project scratch files instead; this did not require
  weakening tests or changing host permissions.

## Remaining environment/release gaps

The old Multipass guest/source mount is not newly verified; WSL does not establish
that `/opt/linxai` contains this source. Gate A remains partial: one systemd action,
the inherited system installer, independent sensor transport and final desktop/
camera/kernel feasibility still need acceptance. No monitoring, broker, model,
camera/microphone or network-device lab was configured. Hosted CI source is supplied
and must be checked separately after publication; local WSL results are not hosted
CI or actual Cloud results. Native checks have no claim of sustained-load latency,
false-positive accuracy, full feature acceptance or universal exactly-once execution.
