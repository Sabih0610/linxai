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
