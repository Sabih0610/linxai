# Typed action registry: first shared-operations slice

Implemented 1 November 2026 in `operations/`. This is a closed, executable-free
preparation API. It validates requests, constructs immutable typed parameters,
derives required checks and expected postconditions, and builds argument arrays.
It does not run commands, evaluate checks, authenticate, grant permission or
verify outcomes. Every prepared action has `execution_supported=False`.

## API and trust boundary

```python
from operations import ActionRegistry, adapt_plan

# Backend-owned configuration; never take this root from a model or client plan.
registry = ActionRegistry(permitted_workspace="/home/ubuntu/linxai-work")
query = registry.prepare("ports.listen", {"port": 80, "protocol": "tcp"})
request = adapt_plan({
    "intent": "service_restart", "target": "nginx",
    "command": "untrusted suggestion", "requires_sudo": False,
    "risk_level": "low", "pre_conditions": [],
}, registry)
assert request.contract.privilege.value == "authenticated_admin"
assert not request.execution_supported
```

`prepare` accepts a registered identifier and an object containing only that
action's parameter fields. It returns a frozen `PreparedAction` with a frozen
contract, typed frozen parameters, tuple `argv`, bytes `stdin`, tuple
`mandatory_checks` and tuple `postconditions`. Each requirement carries an
identifier and immutable key/value arguments. `ACTIONS` is a read-only catalog.
No action accepts client timeout, executable, privilege, authorization or recovery
overrides. `UnsupportedAction` and `InvalidParameters` are explicit `ActionError`
subclasses (`ValueError`); there is no fallback.

These Python objects are not security capabilities. A future service must
reconstruct them from validated action identifiers/parameters and its own
configuration; it must not deserialize or trust caller-built `PreparedAction`
objects. Importing this package does not load the legacy executor or model client.

## Action contracts

Every action requires `linux_runtime` and `trusted_executable` for its fixed
absolute binary path. Every postcondition list requires exit code zero plus the
observations below. Timeouts are fixed specifications; this package has no runner
that enforces them yet. **Recovery is unsupported for all nine actions**; model
rollback strings are never copied to a contract.

| Identifier | Parameters | Privilege | Additional mandatory checks | Argument array / timeout | Expected outcome beyond exit zero |
| --- | --- | --- | --- | --- | --- |
| `disk.usage` | none | unprivileged | none | `/usr/bin/df -P -B1 --exclude-type=fuse.sshfs`; 10 s | Parsed disk usage observation, preserving the legacy SSHFS exclusion |
| `memory.usage` | none | unprivileged | `/proc/meminfo` readable | `/usr/bin/free --bytes`; 5 s | Parsed memory usage observation |
| `ports.listen` | optional nullable integer `port`, default all; `protocol`: `tcp` (default) or `udp` | unprivileged | socket inventory available for protocol | `/usr/bin/ss -H -l -n -t` or `-u`, optionally one filter argument `sport = :N`; 5 s | Parsed matching socket inventory; an empty inventory is a valid result |
| `service.status` | `service` | unprivileged | systemd available, named service exists | `/usr/bin/systemctl --no-pager show --property=Id,LoadState,ActiveState,SubState -- UNIT`; 10 s | Named service state observed; inactive is a valid status |
| `service.start` | `service`, optional `port_free` / `port_occupied` | authenticated admin | systemd available, service exists, service not masked, action/target authorization, requested TCP constraints | `/usr/bin/systemctl --no-ask-password start -- UNIT`; 30 s | Fresh observation of target `ActiveState=active` |
| `service.stop` | same | authenticated admin | systemd available, service exists, action/target authorization, requested TCP constraints | same with `stop`; 30 s | Fresh observation of target `ActiveState=inactive` |
| `service.restart` | same | authenticated admin | same as start | same with `restart`; 30 s | Fresh observation of target `ActiveState=active` |
| `file.create` | `path`, optional UTF-8 `content` (default empty, at most 65,536 encoded bytes) | unprivileged | unprivileged identity, safe configured workspace, no symlink components, writable existing parent, absent target | Fixed isolated Python create program, described below; 5 s | Regular file, confined entry and exact content SHA-256 |
| `directory.create` | `path` | unprivileged | same workspace/identity/parent/absence checks | Fixed isolated Python create program; 5 s | Directory entry confined to configured workspace |

Unprivileged is a requirement, not permission to elevate when a read fails. Port
inventory deliberately omits `ss -p`; process-owner visibility is not guaranteed.
Service status uses `show` so a normally inactive service is not confused with
`systemctl status`'s nonzero exit. Start/restart contracts target services expected
to remain active; successful completion of a one-shot service is not yet modeled.
No service command changes enablement, configuration, listener ports or user units.

Service names accept a conservative ASCII systemd subset: alphanumeric initial
character, then alphanumeric/underscore/dot/hyphen, with at most one concrete
`@instance`, optional `.service`, and at most 255 characters including the suffix.
Options, whitespace, control characters, paths, glob patterns, escaped names,
empty templates, repeated suffixes, `..` and other unit types are rejected.
`apache`/`httpd` normalize to `apache2`, matching the existing builder aliases.
Ports are integer 1..65535; booleans and floats are rejected. The direct API does
not coerce strings. Conflicting free/occupied constraints for one port are rejected.

## Workspace creation

There is no default permitted workspace. The backend must supply a canonical,
absolute POSIX root other than `/`. Filesystem requests are rejected without it.
Relative paths are anchored there; absolute paths must be strictly beneath the
same root by path components, not string prefix. The root itself is not a target.
No environment, home-directory or current-directory expansion occurs.

Paths use bounded ASCII components containing letters/digits/underscore/dot/space/
hyphen, without a leading hyphen. Empty, `.`/`..`, repeated/trailing separators,
Windows paths, backslashes, controls, shell syntax and components over 255 bytes
are rejected. Both the input and workspace-anchored path are at most 4095 bytes. Existing parents must be
present; recursive parent creation and overwriting are outside this contract.

The array is `/usr/bin/python3`, `-I`, `-c`, a fixed backend-owned program,
workspace, relative path, and kind. It never interpolates a request into program
source. File content is separate UTF-8 stdin, with no added newline. The program
refuses root and non-Linux identities, opens each directory component through
directory descriptors with `O_NOFOLLOW`, and creates files with
`O_CREAT|O_EXCL|O_NOFOLLOW` (mode 0600) or directories with `mkdir` (mode 0700).
It cannot overwrite an existing target, follow a parent symlink, or use a shell.
The registry never launches this program. Its syscall paths have offline mock
coverage; actual Linux filesystem behavior is not yet verified.

`workspace_safe` is a future live check, not a lexical guarantee: pin/verify the
root and parent identities, directory ownership and write access, and reject
untrusted writable ancestors. Directory descriptors prevent symlink following
but do not alone prevent a cooperating process from renaming an open parent out
of the workspace. The service must resolve this ownership/concurrency boundary
and verify confinement after creation. Partial writes can leave a new incomplete
file; automatic cleanup/recovery is not implemented.

## Legacy AI-plan adapter

`adapt_plan(plan, registry)` maps `disk_usage`, `memory_usage`, `port_check`,
`port_list`, `service_status`, `service_start`, `service_stop`, `service_restart`
and explicitly typed `file_create` plans to the catalog. It does not mutate the
plan. Commands, `risk_level`, `requires_sudo`, rollback and explanatory metadata
are ignored regardless of their suggested authority. Structured parameters are
validated independently, including for cached/fast-path plans. No command text
is parsed to recover a missing service, port, path or create kind.

- Existing numeric port strings are normalized only at this adapter boundary.
  A `port_check` requires an explicit port/target; two supplied values must agree.
- Service plans require `target`. A nonempty listener `port` is rejected because
  this milestone does not configure services, rather than silently dropping it.
- `file_create` requires explicit `kind` or `file_create_kind`; file/regular_file
  and directory/folder/dir are supported. Explicit path/target/name/filename and
  optional location are resolved inside the configured workspace. Multiple
  supplied paths/kinds must agree. Directory content is rejected. This narrows
  the legacy command/explanation-based guessing and recursive mkdir behavior.
- Missing or empty `pre_conditions` never removes server-derived requirements.
  A redundant `service_exists` must match the target. Supported service TCP
  `port_free`/`port_occupied` conditions become typed constraints and therefore
  additional mandatory checks. Unknown/malformed/mismatched conditions are
  rejected, not silently discarded. The same port cannot be both free/occupied.
- Unsupported actions, unknown plan fields and nonempty unsupported semantic
  slots fail explicitly. Empty legacy fast-path defaults are accepted.

## Migration boundary and next slice

The original CLI, CIE and `ExecutionController` are unchanged. No route is
silently redirected to this registry, and its presence does not secure the old
generic-shell, setup/export, retry or remote paths. Existing useful behaviors
and the 41 foundation tests are preserved. The broader service milestone remains
incomplete; the VM/source baseline gate also remains unresolved.

Next implement a service that accepts typed requests, reconstructs contracts,
evaluates every mandatory check with fail-closed missing/error/timeout handling,
obtains independent action/target-scoped authentication and authorization, and
binds final approval to the exact operation and observed state. Only then add
dispatch with fixed executables, controlled environment and enforced deadlines,
fresh postcondition verification, operation IDs and validated state-based recovery.
Do not treat `requires_sudo`, a check declaration, a frozen object or a successful
exit status as authorization. Do not add a raw-shell fallback during migration.


## Shared lifecycle follow-up (1 November 2026)

The registry itself remains preparation-only and unchanged. Its contracts are now
consumed by `OperationService` in `operations/service.py`, with independent identity/
authorization, required observation handlers, exact-operation approval, bounded
unprivileged dispatch and correlated verification/audit. `PreparedAction` is still
not a permission grant. All admin actions remain broker-required and all recovery
flags remain unsupported. Only the explicit typed CLI is migrated; see
`docs/OPERATIONS_SERVICE.md` for current behavior and the unmigrated legacy paths.
