# LINxAI development environment baseline

Recorded 1 November 2026 (Asia/Karachi, UTC+05:00).
Selected source: `E:\FYP\code 2\linxai`.
This report records the current read-only investigation. Historical documentation
is identified separately; Windows unit results do not verify Linux integration.

## Confirmed scope and task boundary

Read `AGENTS.md`, `docs/IMPLEMENTATION_PLAN.md` and `docs/VERIFICATION.md`
before proceeding. The confirmed product is an offline-first Linux operations
desktop application covering Linux administration, DevOps, supported network
devices, background security monitoring, validated adaptive response, scoped
response-policy memory and privileged authentication. Ollama inference stays local.
The CLI remains a compatibility interface; UI/model processes must stay unprivileged.
Typed actions, independent operation policy and trusted Linux authentication are
required before expanding autonomy. Automatic threat response must remain disabled.
PySide6 is proposed, not a confirmed framework choice.

This task establishes milestone 0 evidence only. No implementation, mount,
permission, PAM, service or package changes were made. No installer, attack
simulation, model inference, BCC probe loading or application startup was run.
No commit, checkout, reset, stash, staging or remote update was performed.

## Verified repository facts

- Current branch: `main`.
- HEAD: `51e54c6888bddcfec07cd544acc295b3ce833e45`.
- Commit subject: `Fix command resilience and service fast paths`.
- Index: no staged changes (`git diff --cached --stat` was empty).
- Before this report, Git showed seven modified tracked files and five untracked
  files. The existing work was inspected and preserved.

```text
 M ai/__init__.py
 M ai/engine.py
 M ai/fast_path.py
 M ai/prompts.py
 M cie/validator.py
 M executor/controller.py
 M main.py
?? AGENTS.md
?? ai/plan_schema.py
?? docs/IMPLEMENTATION_PLAN.md
?? docs/VERIFICATION.md
?? test_safety_regressions.py
```

The existing tracked diff totals 164 insertions and 190 deletions across seven
files. It contains lazy AI exports; generated/cached plan validation; conditional
service routing and cache protection; the corrected prompt JSON example;
fail-closed malformed/unknown/failed/incomplete/over-budget checks; registration of
port-range/process-count checks; ordinary/retry validation gates; POSIX
`start_new_session`; and suppression of automatic model-generated rollback.
The new untracked schema and tests are necessary parts of that foundation work.

These remain incomplete security foundations: empty declared-check lists can
approve, the synchronous deadline does not cancel a running check, and generic
shell/alternate execution paths still require consolidation. Passing this suite
does not establish authorization, Linux authentication or enforcement.

A SHA-256 preservation snapshot covered 63 existing tracked/untracked,
non-ignored files before writing this report. A final comparison verified their
bytes unchanged. The only repository addition for this task is
`docs/ENVIRONMENT_BASELINE.md`; ignored/generated files are outside that snapshot.

## Tests and host Python: verified

The PATH `python.exe` resolved to
`C:\Users\sabih\AppData\Local\Microsoft\WindowsApps\python.exe` and could not
launch: `The file cannot be accessed by the system.` The launcher command
`py -0p` reported `No installed Pythons found!` These are environment/discovery
failures, not regression failures.

The available bundled runtime successfully ran the selected working tree:

```powershell
Set-Location -LiteralPath 'E:\FYP\code 2\linxai'
& 'C:\Users\sabih\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -B -m unittest test_safety_regressions -v
```

`-B` only disables bytecode writes; it does not change the existing test suite.

| Check | Current result |
| --- | --- |
| Python identity | CPython 3.12.14, MSC v.1944, 64-bit AMD64 |
| Host reported by Python | `Windows-11-10.0.26200-SP0` |
| Existing offline suite | **41 tests passed in 0.306s**, `OK`, exit code 0 |
| Source parsing with `ast.parse` | All 39 Python source/test files parsed |
| Lightweight imports | `import ai`, `from ai import SYSTEM_PROMPT`, `from ai.fast_path import classify_fast` passed |
| HTTP client on this runtime | `requests` unavailable; no installation attempted |
| Git whitespace checks | `git diff --check` and `git diff --cached --check` passed |

Git emitted LF-to-CRLF conversion warnings for six existing modified files; these
were not whitespace-check failures and no normalization was performed.

The suite replaces model HTTP calls with doubles and forbids real subprocess and
connection helpers during test methods. It covers plan shape, prompt examples,
cache handling, declared-check failure/deadline behavior, conditional routing,
retry gates and suppressed generated rollback. Expected simulated-error log lines
appeared in passing negative tests. There were no test failures or dependency
failures with the bundled runtime. The missing HTTP client means this runtime is
not evidence that the full application can start.

## Multipass inspection: verified host observations

- `multipass` was not resolved by `Get-Command` on PATH.
- The executable exists at `E:\FYP\multipass\bin\multipass.exe`
  (27,570,688 bytes). Its runtime version could not be queried.
- `Get-Service -Name Multipass` returned **Status `Stopped`, StartType `Disabled`**.
  This is a Windows service observation, not the state of `linxai-dev` itself.
- `C:\ProgramData\Multipass\multipassd.conf` was readable and contained
  `local.driver=hyperv`. This is persisted configuration, not proof of a running
  Hyper-V guest.
- Listing `E:\FYP\multipass` and `C:\ProgramData\Multipass\data` was denied,
  including the attempt outside the restricted execution sandbox. No stored VM
  instance/mount metadata could be read.
- A `Win32_Service` CIM query did not return promptly and was cancelled. The
  service status above came from the separate successful `Get-Service` call.

The following read-only commands were attempted by absolute executable path:

```powershell
& 'E:\FYP\multipass\bin\multipass.exe' version
& 'E:\FYP\multipass\bin\multipass.exe' list --format json
& 'E:\FYP\multipass\bin\multipass.exe' info linxai-dev --format json
& 'E:\FYP\multipass\bin\multipass.exe' exec linxai-dev -- uname -sr
```

`version`, `list` and `info` failed both under restricted execution and in an
approved outside-sandbox read-only attempt. The outside-sandbox guest `exec`
attempt failed in the same way. The exact shared process-launch error was:

```text
Program 'multipass.exe' failed to run: An error occurred trying to start process 'E:\FYP\multipass\bin\multipass.exe' with working directory 'E:\FYP\code 2\linxai'. Access is denied.
```

The PowerShell diagnostic category was `ResourceUnavailable`. No Multipass client
or guest output was obtained; a numeric CLI exit code cannot be assigned because
the executable did not launch. This is an access/environment blocker, not evidence
of a LINxAI code failure. It does not identify whether ACLs, security software or
another host policy caused denial. No permissions or security settings were changed.

## Historical information: not reverified in the guest

`README.md` and `docs/SETUP.md` describe Multipass 1.16.1 with Hyper-V,
`linxai-dev`, Ubuntu 22.04.5 LTS/kernel 5.15, 4 CPUs, 8 GB RAM and a 40 GB disk.
They record `E:\FYP\code -> /opt/linxai`. Those are historical claims, not the
current guest identity, resource allocation or mount state.

The selected repository's `config/settings.json` currently requests model
`qwen2.5:1.5b` at `http://localhost:11434`, with eBPF enabled and voice disabled.
This is verified source configuration only. It does not prove the guest has
Ollama running, that the model is installed/loaded, or that BCC is available.
The eBPF daemon source imports `bcc.BPF`; source availability is not a successful
guest BCC import, probe compilation, attachment or enforcement test.

Historical `tests/attack_simulation.py` is present in both `E:\FYP\code` and
`E:\FYP\backup\code`. These files were inventoried only and not executed or
copied into the selected tree. Historical demo/test paths must be reviewed for
mutating behavior before selective recovery.

## Source mismatch evidence

The two host paths are different source trees:

| Host source | Verified HEAD |
| --- | --- |
| Selected `E:\FYP\code 2\linxai` | `51e54c6888bddcfec07cd544acc295b3ce833e45` plus the uncommitted foundation work above |
| Historical `E:\FYP\code` | `37aabc72e9b198335c0f160db6521a68f3ffd84e` |

Raw-byte SHA-256 comparisons found that the historical tree lacks `AGENTS.md`,
`docs/IMPLEMENTATION_PLAN.md`, `docs/VERIFICATION.md`, `ai/plan_schema.py`,
`test_safety_regressions.py`, and even `ai/fast_path.py`. Its existing AI exports,
engine, prompt, validator, executor controller, main entry point and eBPF daemon
also differ. `config/settings.json` has identical bytes in these two host trees.
These are host comparisons, not guest hashes; a matching Git HEAD alone would
also be insufficient to prove deployment of uncommitted fixes.

Selected-tree fingerprint for a future guest comparison (raw bytes; line endings
must match for equal hashes):

| File relative to selected root | SHA-256 |
| --- | --- |
| `main.py` | `2779b88e892c1a4f9456278db0462260d9c4b0d2420f3edc29805717a928b7a5` |
| `ai/engine.py` | `db09c0c96748da670ac6c180a8dec1f8b7db7cab715499ece681f6337818149c` |
| `ai/fast_path.py` | `819b0d63788c7bfaa83559edef2fdbede245004170b4e9071dc4752f785d31f5` |
| `ai/plan_schema.py` | `a8151c1764cf14628ec482bcc36d7c2f5c25dadde62c3447c4591dcbca62094f` |
| `cie/validator.py` | `71fd658794cb2b7cae4d01e2a2124fcd362838204bea316d8d5bf3c7f96a36d7` |
| `executor/controller.py` | `3dd986cc70f3e6927c1c29c5051121f08a34d26d5bd36412fc6855304842ae1c` |
| `test_safety_regressions.py` | `fe11b4775d015a5070b619b4becd17158730c22459c41713599254e37eef1b67` |
| `config/settings.json` | `3dda686eb0dff705e9e83b4027748bb7e117085b2bcee6c93a0e9d05fb2f5964` |
| `ebpf/daemon.py` | `8ff4a0e0c7b2272eac3656c879eda35ac11ba13db7aa8ab6c565cb103416c838` |

**Finding:** `/opt/linxai` has not been shown to contain the selected source or
latest fixes. If the historical mount remains active, it would expose the older,
different `E:\FYP\code` tree. Current guest mismatch is unresolved; the host
source mismatch and risk of stale deployment are verified. No remount was attempted.

## Unresolved items and smallest next action

The guest's existence/running state, current OS/kernel, mount source/options,
`/opt/linxai` revision and working files, interpreter/virtual environment,
installed Python dependencies, Ollama runtime/model inventory, BCC availability
and reproducible application startup remain unverified. Milestone 0 is therefore
documented but not complete.

The smallest next diagnostic is to run the single read-only command below in an
existing trusted Windows terminal where Multipass execution is permitted, and
retain its complete output:

```powershell
& 'E:\FYP\multipass\bin\multipass.exe' info linxai-dev --format json
```

This distinguishes this execution context's launch denial from a wider host
restriction and may report daemon unavailability. The observed stopped/disabled
service is a separate blocker; service recovery or permission changes require a
separately authorized follow-up. Do not start/enable services, remount, install
packages or change ACLs as part of this baseline.

Once existing guest access is available, collect read-only evidence: `cat
/etc/os-release`, `uname -a`, `findmnt -T /opt/linxai`, `/proc/mounts`, guest Git
HEAD/status, and `sha256sum` of the fingerprint files above. Inspect `command -v
python3`, `python3 --version`, `sys.executable`, `sys.prefix`, `sys.base_prefix`
and installed dependency availability using that guest interpreter. Inspect
`ollama list`, `ollama ps` and a plain `import bcc` without loading probes or
requesting inference. Also establish the actual app/service interpreter from
existing configuration. Compare both mount metadata and file contents before
deciding whether a deliberately authorized mount/deployment alignment is needed.

The next implementation task, after resolving the runnable-baseline gate, is
milestone 1: implement the typed action registry and shared operations service,
with server-selected privileges, operation-derived mandatory checks, final-operation
approval, trusted authentication, one execution path, state-based recovery and
operation IDs. Preserve these foundation fixes; add negative tests for bypass,
retry, setup/export and recovery paths. Do not begin the desktop or increase
automatic response autonomy on the current shell guard.


## Additional development evidence — 2 November 2026

An existing Ubuntu 24.04.3 WSL2 environment and ordinary UID 1000 account were
accessible. A native-filesystem snapshot of the selected working tree verified all
93 included files and the eight current operations-module hashes. Isolated setup
and unprivileged integration were exercised there; see
`CAPABILITY_REPORT_2026-11-02.md` for results, skipped systemd/hardware/model/kernel
checks and retained environment/timing failures. No mounts or host security settings
were changed. This adds WSL evidence; it does not verify or replace the recorded
Multipass guest, historical mount, `/opt/linxai` revision or final Linux desktop lab.
