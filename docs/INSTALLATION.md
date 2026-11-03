> Current integrated instructions: RELEASE_CANDIDATE.md. The sections below record
> the Gate A installation boundary; B–G now supply protected components and desktop
> workflows. They remain separately reviewed target deployments. `--voice` explicitly
> installs pinned input packages; no weights are downloaded. Non-editable installs
> now build from clean temporary source, preserving old checkout build output.

# Gate A application installation and Linux support

This installs the current typed CLI on an ordinary Linux account. The final
product remains a Linux desktop with independently supervised monitoring and
trusted OS authorization. Those components are separate gates, not implicitly
installed by this command. Read GATE_A_BASELINE.md for actual evidence and limits.

## Platform and dependency matrix

| Environment | Application support | Evidence / boundary |
| --- | --- | --- |
| Ubuntu 24.04, CPython 3.12, native Linux filesystem, ordinary account | Primary application baseline | Native WSL installation and five actions exercised; full systemd lab acceptance pending |
| Ubuntu 24.04, CPython 3.11 | CI compatibility target | Earlier handoff CI is historical; updated installed-application CI must run before acceptance |
| CPython 3.13 | Declared by package metadata | Not accepted until installation and native tests pass; no current execution evidence |
| Ubuntu 22.04 stock Python 3.10 | Unsupported application interpreter | Supply an independently managed supported interpreter; installer does not replace OS Python |
| Debian/other Linux distributions | Unverified | Require trusted fixed tool paths and the same ownership/systemd/native tests; no portability claim |
| WSL2 Ubuntu 24.04 | Partial development/lab support | Native source and venv required; current WSL has no systemd. Not desktop/kernel/hardware acceptance |
| Windows/macOS | No application operation support | Windows offline tests only; install and operation identity checks refuse unsupported OS |
| Root, setuid/setgid, unsafe/shared workspace or prefix | Unsupported | Refused rather than repaired; do not change security settings to pass tests |
| Container or hosted runner without systemd | Partial development support | Missing capabilities produce skipped tests or explicit operation failures; root is not kernel ownership |

Application interpreter: CPython >=3.11,<3.14 with venv/ensurepip. Build backend:
setuptools 80.9.0. Lock/sync: uv 0.13.3. Default installed set: LINxAI 0.1.0,
PyYAML 6.0.3, psutil 7.1.3 and uv 0.13.3. All transitive packages and wheel hashes
are locked in uv.lock. Optional AI/desktop/remote/hardware/voice profiles remain
separate in DEVELOPMENT_ENVIRONMENT.md; routine installation selects none.

Runtime system tools are **OS supplied**, not pip dependencies: /usr/bin/df
(coreutils), /usr/bin/free (procps), /usr/bin/ss (iproute2), /usr/bin/systemctl
(systemd), and /usr/bin/python3 for the fixed isolated file-creation worker.
Linux procfs and a running systemd manager plus a loaded fixture service are
needed for their respective actions. Service status does not require a service
to be active. Exact OS package versions belong in the lab capability record.
Missing/untrusted tools or unavailable services fail mandatory validation before
dispatch, with check identifiers in the result and detailed reasons in the audit.
No implicit package install or shell fallback occurs.

## Install and launch

Start from a reviewed checkout on a native Linux filesystem. Do not run with sudo.
For development use scripts/setup_dev.py; application installation builds a
non-editable wheel, then verifies that imports resolve inside its private venv.

```sh
python3 --version
sh install.sh
"$HOME/.local/share/linxai/bin/linxai" --help
"$HOME/.local/share/linxai/bin/linxai" memory.usage
```

Default prefix is $HOME/.local/share/linxai. Supply an absolute dedicated prefix
with `sh install.sh --prefix "$HOME/.local/share/linxai-candidate"`. Use
`LINXAI_PYTHON=/path/to/python3 sh install.sh` for a supported alternate interpreter.
The prefix must not exist; existing installations/unrelated data are preserved.
Existing parents must be directories without symlinks, foreign owners or group/
other writers. New application directories are private. No existing permissions,
shell profile, OS package, PAM file, mount, service or model is changed.

First installation needs access to pinned PyPI artifacts. A matching existing uv
is reused; otherwise only pinned uv is bootstrapped through pip **inside the new
venv**. After populating the package/build cache, `sh install.sh --offline --prefix
"$HOME/.local/share/linxai-offline"` refuses uncached inputs. No system pip changes
or automatic Python downloads occur. uv `--locked --no-editable` is used; see
[official uv sync documentation](https://docs.astral.sh/uv/concepts/projects/sync/).

Create the permitted workspace yourself in a safe owned directory. Shared /tmp
is intentionally unsuitable for production confinement.

```sh
mkdir -m 700 "$HOME/linxai-workspace"
"$HOME/.local/share/linxai/bin/linxai" file.create \
  --workspace "$HOME/linxai-workspace" \
  --parameters '{"path":"hello with spaces.txt","content":"hello\n"}'
"$HOME/.local/share/linxai/bin/linxai-ops" service.status \
  --parameters '{"service":"dbus"}'
```

The default audit is $HOME/.linxai/operations.jsonl. Audit directories/files must
pass the existing ownership/private-mode/no-symlink checks. Each operation retains
its ID across checks, dispatch, verification and audit. Administrative service
actions still return authentication_authorization_required. Recovery stays
unsupported unless a future validated restoration action and prior state exist.

Both prefix/bin launchers reject root/set-ID before importing app code, unset
PYTHONPATH/PYTHONHOME, use isolated Python and forward `"$@"` unchanged. They accept
typed positional action identifiers and JSON parameters. Unsupported actions and
legacy `--command`, `--demo`, `--attack-sim` options fail explicitly; they never
dispatch the legacy shell pipeline. The inherited main.py compatibility interface
and its unmigrated paths remain outside this installed workflow. The venv's own
console entry points also reject elevated operation startup before opening audit.

## Remove / replace

```sh
sh uninstall.sh
# Or the same --prefix used during installation:
python3 -I scripts/install_app.py --prefix "$HOME/.local/share/linxai-candidate" --uninstall
```

Removal requires a matching caller-owned receipt/private prefix and safe parent
chain. It refuses unrecognized top-level files and altered receipt/managed-path
symlinks. It removes only that prefix's managed venv/bin/receipt and retains audit,
configuration, workspaces, OS packages and any historical system installation.
An incomplete install retains a receipt and can be removed the same way. There is
no automatic in-place upgrade or rollback; remove/reinstall a reviewed candidate.
Historical /opt/linxai deployments need a separate reviewed migration; the new
uninstaller never disables their services or edits PAM.

## Reproduce lab evidence

```sh
python3 scripts/setup_dev.py
.venv/bin/python -B scripts/test.py offline
.venv/bin/python -B scripts/test.py linux
.venv/bin/python -B scripts/capabilities.py --output capabilities-gate-a.json
.venv/bin/python -B scripts/run_gate_a_lab.py --report gate-a-lab.json
```

The runner installs into a temporary private native prefix containing spaces,
tests the actual installed wheel/launchers from a foreign working directory and
removes that prefix. It reuses all native backend tests, including correlated
file audit, malicious literal content, traversal/symlink/overwrite and root-owned
workspace denial. It creates no services/devices. Exit 0 means application lab
criteria executed; exit 3 means pending checks; exit 1 means failure. Inspect JSON
and verbose output, not only the exit code. First run may need package access;
repeat with `--offline` after caches are populated.

In an explicitly authorized disposable Ubuntu/systemd lab with existing non-root
user and passwordless sudo **only for a negative root-startup check**, run:

```sh
LINXAI_TEST_SERVICE=dbus .venv/bin/python -B scripts/run_gate_a_lab.py \
  --offline --check-root-rejection --report gate-a-lab.json
```

The opt-in runs `sudo -n` only against the generated launcher and requires its
ordinary-user refusal before Python import. It does not execute an operation as
root. Do not configure sudo or start services merely to make this pass. Select an
already loaded fixture with LINXAI_TEST_SERVICE if dbus is unavailable. CI runs
this explicit lab step on hosted Ubuntu; a new run is pending publication.

## Sensor and future integration boundary

App package data includes ebpf/probes/*.c and executor/pam source; inclusion is not
permission to load it. The BCC sensor uses its OS /usr/bin/python3 and distro
bindings separately (requirements/sensor-os.json), never PyPI bcc or an app venv
with system-site-packages. Historical systemd units are documented here as templates and
are not installed/enabled. Their /opt paths, hard-coded ubuntu identity and model
ordering do not define a supported Gate A deployment.

Gate D must supply reviewed root-owned immutable deployment code, independent
readiness/lifecycle, bounded transport/storage and real kernel acceptance before
sensor installation is supported. Never run privileged sensor imports from this
user-owned wheel/checkout. The inherited sensor's overhead comments are historical
claims, not measured evidence.

The passive capability probe reports kernel flags/BTF/process capabilities,
systemd, GUI sockets, OS-auth tools/PAM/system-bus presence, camera nodes and ALSA
metadata/audio tools without opening devices, invoking authentication, starting
models or attaching BPF. Missing/unknown fields remain unknown. Presence, root or
configuration flags establish no authentication, desktop, microphone/camera or
target-kernel enforcement acceptance.
