# Shared operations service

Implemented 1 November 2026 as an in-process ordinary-user API around the existing
`ActionRegistry`. This continues the registry architecture; it does not add a
parallel action vocabulary. The CLI and a future local desktop process can call
the same `OperationService`. No daemon or authenticated IPC transport is installed.

## Calling the migrated CLI workflow

On Linux, run as your ordinary account, without sudo:

```sh
python3 main.py --operation memory.usage
python3 main.py --operation disk.usage
python3 main.py --operation ports.listen --operation-params '{"port":80,"protocol":"tcp"}'
python3 main.py --operation service.status --operation-params '{"service":"nginx"}'
python3 main.py --operation service.restart --operation-params '{"service":"nginx"}'
```

The last command returns `authentication_authorization_required` without executing
or changing a service. `python3 -m operations.cli memory.usage` is an equivalent
standalone frontend. Output is one JSON result with an operation ID; exit code
0 means verified success, and 2 means any other reported outcome. These examples
are documented Linux commands, not evidence they were run successfully on Linux.

`--operations-workspace /home/USER/linxai-work` configures the permitted creation
root for `file.create`/`directory.create`. The root must already exist, be owned
by the account and private (no group/other permissions). Parents must exist;
symlinks, foreign owners and group/other-writable ancestors are rejected. This
conservative policy also rejects a workspace under shared `/tmp`. The service
does not chmod/chown existing paths or create workspace parents.

The default ledger is `~/.linxai/operations.jsonl`, separate from the legacy audit.
Its immediate directory must be owned/private, and its ancestors must have trusted
ownership and no untrusted write access. A missing immediate directory may be
created with mode 0700; existing permissions are never changed. If legacy setup
left `~/.linxai` public or root-owned, use `--operations-audit` with a log path in
an existing owned private directory. An unsafe or unwritable audit path blocks
execution explicitly. No service/user permission changes are performed as a repair.

The typed route is selected before `LINxAIPipeline` construction, so it does not
initialize Ollama, the model HTTP client, monitoring or resource management.
Unsupported actions/parameters terminate with an error; there is no fallback to
`ExecutionController`. Typed and legacy command/daemon modes cannot be combined.
An explicitly empty or malformed JSON parameter argument is rejected, including
duplicate keys. The main CLI also rejects root/setuid startup of the legacy app.

## Shared Python API

```python
from operations.registry import ActionRegistry
from operations.service import OperationService, LocalPolicy
from operations.system import LinuxSystemAdapter
from operations.audit import JsonlAudit

# Backend-owned dependencies/configuration, not fields accepted from a UI/model.
system = LinuxSystemAdapter()
identity = system.resolve_identity()
service = OperationService(
    ActionRegistry(permitted_workspace="/home/USER/linxai-work"),
    system, LocalPolicy(owner_uid=identity.uid),
    JsonlAudit("/home/USER/.linxai/operations.jsonl"),
)
result = service.run({"action": "memory.usage", "parameters": {}})
```

The request envelope accepts exactly `action` and a parameter object. Identity,
approval flags, commands and privilege claims are not accepted. For AI integration,
the existing `adapt_plan` remains the structured-plan boundary; a caller must
submit its validated typed fields through this service, never dispatch its raw
plan or prepared argv directly. Natural-language CLI paths are not yet migrated.

The service supports the registry's six unprivileged actions: disk/memory usage,
listening ports, service status, file creation and directory creation. All three
service mutations are hard-blocked pending the broker, even if an injected policy
would otherwise allow them. The Linux adapter independently rejects admin dispatch.

## Lifecycle and approval binding

1. Assign a UUID, audit receipt, snapshot/validate the JSON request using the registry.
2. Resolve UID/EUID/account from the OS, refuse root/setuid contexts, and evaluate
   the independent backend-owned local UID/action policy. The Linux identity source
   also refuses setgid contexts. No UI/model identity or boolean is authoritative.
3. Reconstruct the final registry operation, including target, typed parameters,
   fixed argv/stdin, mandatory checks, timeout and postconditions.
4. Evaluate every mandatory requirement. Missing, malformed, unknown, failed,
   uncorrelated, incomplete or over-budget observations block approval. Observation
   records contain the same operation ID and a hash of their evidence.
5. Issue a process-local random single-use token, expiring after 30 seconds by
   default (backend maximum 60). Approval binds the UUID, identity, request,
   registry contract, parameters/target, complete argv, stdin hash/length, checks,
   postconditions, timeout and recovery declaration through a SHA-256 fingerprint.
6. Consume the token, resolve identity/authorization again, rerun all checks and
   require the same captured state evidence. Reconstruct against current registry
   configuration and recheck policy/fingerprint/expiry before dispatch. A changed
   operation/configuration/state needs a new validation/approval.
7. Execute the stored operation's exact argv with `shell=False`, no sudo, fixed
   PATH/C locale, controlled cwd/environment, closed descriptors and an operation
   timeout. Temporary output streams retain at most 1 MiB per stream in the result;
   excess output causes failure. File content stays on stdin, never in source code.
8. Verify every postcondition and record a correlated result. Exit zero alone does
   not establish success. Invalid/empty required observations cannot approve.

`prepare(request)` and `execute(approval)` expose the same lifecycle for delayed
local dispatch; `run(request)` performs both. Approval objects are not authentication
credentials or safe IPC input. The server-held token/state is authoritative. Tokens
are not logged and cannot be reused or carried across process restarts. Unknown
tokens/replays receive a new rejection ID rather than trusting a caller-supplied ID.
The registry's `PreparedAction.execution_supported=False` remains a preparation-only
marker; only this service's policy, approval and dispatcher permit the bounded
unprivileged lifecycle. It is never flipped by a model or treated as a grant.

Live checks cover Linux identity, trusted root-owned non-setuid binaries, proc
availability, systemd/unit existence and workspace ownership/confinement/absence.
Service status uses noninteractive `systemctl show`. Files use the registry's fixed
isolated exclusive/no-follow creation program. Resource/socket/service outputs are
parsed and checked against the requested protocol/port/unit. File verification
checks entry type, ownership/mode, confinement and exact content digest through
no-follow descriptor reads. Unsupported check/postcondition handlers fail closed.
Privileged TCP-condition/authentication handlers remain unavailable because their
actions cannot reach dispatch without the future broker.

## Results, audit and recovery

`OperationResult` reports status, reason, UUID, fingerprint, executed/verified flags,
retained stdout/stderr, `recovery="unsupported"` and `audit_complete`. `executed`
is null when an adapter exception or uncorrelated response leaves side effects
unconfirmed; it is not falsely reported as no execution. `succeeded` is emitted
only after all postconditions pass. Failed verification leaves any new file for
review and reports failure; the service never guesses an inverse operation.

All current registry actions explicitly lack a restoration contract. Although
validation captures required state evidence, no supported restoration action exists,
so this slice implements no automatic restoration. Model rollback strings remain
outside the service. Captured prior state plus a separately validated restoration
action is required before adding restoration.

Validation, approval, execution, verification and result ledger events share the
UUID and operation fingerprint. The JSONL writer uses private owned regular files,
rejects symlinks/hardlinks/unsafe directory modes, appends under thread/process
locks and fsyncs. It propagates errors. A required audit failure before dispatch
prevents execution; one after dispatch produces `audit_failed` and retains known
execution/verification information with `audit_complete=False`. Raw file content,
model command text, stdout/stderr and approval tokens are not copied into the ledger.

## Migration boundaries and precise gaps

- Only the explicit `--operation` / standalone typed CLI and direct Python service
  calls are migrated. Legacy `--command`, interactive natural-language operations,
  setup/nginx/export shortcuts, retries, remote/VPS paths and old logging/monitoring
  still use their existing implementations. They do not gain this service's policy
  or correlation guarantees. Selecting the typed route never silently invokes them.
- There is no trusted privilege broker, PAM/face/password integration, cross-user
  authenticated IPC, desktop UI, remote action authorization or privileged dispatch.
- There is no durable operation queue, crash reconciliation, cancellation, approval
  persistence or restoration. Abandoned approvals may leave an approval record without
  a final execution result. Do not infer success after a process crash.
- Observation budgets reject late synchronous checks after they return; they cannot
  interrupt a blocked filesystem read. Subprocess deadlines kill/wait the direct
  process; no generic descendant-tree supervision is claimed. Temporary spooling
  bounds retained memory, not total disk writes before a deadline.
- State rechecks and no-follow descriptor operations reduce races but cannot make
  validation and execution atomic. Same-account concurrent renames/content changes
  and executable replacement by root remain integration/threat-model work. Workspace
  permissions are deliberately restrictive; unsupported ownership/layouts fail.
- These are Windows offline/mock and temporary-file results. Actual Linux binary
  paths/output compatibility, POSIX ownership/locking, systemd, filesystem races,
  Ollama, BCC and the selected source at `/opt/linxai` remain unverified. The prior
  Multipass access/source mismatch findings remain in `ENVIRONMENT_BASELINE.md`.
