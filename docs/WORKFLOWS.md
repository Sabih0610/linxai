# Typed provisioning, remote Linux and network-device development

Gate F extends the existing registry/service/jobs rather than executing legacy
recipe command strings. The current coherent paths are repeatable Python stdlib
project provisioning, strict authenticated SSH to a typed peer, and a persistent
development switch with inspect/diff/apply/verify/validated restoration. This is
partial breadth: Node/MERN/package/deployment recipes, physical vendors and broader
resource actions remain in the requirements matrix, not silently removed.

## Python environment / DevOps recipe

`environment.python` and `project.scaffold` require an explicit path under the
owner's configured workspace. The fixed isolated OS-Python worker rejects root,
unsafe directories, traversal/symlinks, conflicting files and unmanaged existing
environments. It uses venv without pip/network downloads, copies the trusted OS
interpreter, records its digest and preserves existing packages/files. Generation
is fd-anchored; activation paths are rewritten to the final owned path. Existing
interpreter verification hashes it without executing potentially untrusted startup
files. Conflicting owner edits fail prerequisites before new work is performed.
No broad system pip, apt/curl fallback or project-supplied shell script is run.

Natural language examples: `create a python environment in demo` and
`provision a python project at demo`. Both produce the standard preview, exact
confirmation, mandatory checks, supervised execution and verified result. A failed
partial environment is left for review, not recursively deleted or blindly retried.

## Configured assets and strict SSH

The agent reads a private owner-owned ~/.linxai/assets.json at startup; it is not
accepted from model/request fields. At most 32 named assets are admitted. Example:

```json
{
  "switch": {"platform":"development_file", "path":"/home/OWNER/linxai-work/switch.json", "ports":["port1","port2"]},
  "lab": {"platform":"linux_ssh", "host":"example.invalid", "username":"owner", "port":22,
    "expected_uid":1000, "python":"/home/owner/.local/share/linxai/venv/bin/python",
    "key_path":"/home/OWNER/.ssh/LAB_KEY", "known_hosts":"/home/OWNER/.ssh/known_hosts"}
}
```

These are metadata examples, not real credentials/devices. The development file's
parent must already be private/owned. SSH key and known-hosts files are checked for
ownership, links, permissions and change since approval. Existing VPSServer endpoint
fields are reused through vps/server_types.py; the legacy Paramiko manager remains
outside this trusted route. No AutoAddPolicy is used by the new path.

`remote.operation` uses /usr/bin/ssh as an exact argument array with shell=False,
BatchMode, StrictHostKeyChecking, a configured known-hosts file and no user SSH
configuration, agent forwarding, local command, control-master or host-key update.
SSH necessarily invokes a **fixed quoted remote bootstrap**, never a model command:
the configured interpreter runs -I -B -m operations.remote_peer. Only typed JSON is
sent on stdin. The peer derives identity from the OS SSH login, loads its own private
~/.linxai/remote.json workspace configuration, rejects replay and invokes the same
registry/service/broker. Local caller UID/model claims cannot grant remote privilege.
Remote service changes still require that host's trusted OS authorization.

The peer result binds UUID, expected remote UID and verified outcome. Missing
credentials, host mismatch, malformed output and timeouts fail explicitly; lost
responses are not automatically retried. `on lab show memory usage` uses this route.
For remote create operations, use paths relative to the peer's independently
configured workspace. Recursive remote requests and raw command fields are rejected.

Actual SSH authentication requires a prepared known host/key/ordinary account;
none was available for this task. Native tests execute the real peer protocol and
replay database locally through pipes; that is **not SSH authentication evidence**.

## Device interface and development adapter

Stable contracts are device.initialize, device.inspect, device.interface.set and
device.interface.restore. `development_file` implements the shared protocol with
real private JSON state and exclusive transaction snapshots. Other platforms fail
explicitly; this adapter does not claim router/switch vendor compatibility.

The Assets view initializes/inspects the configured development device and previews
interface up/down changes. The backend obtains its own revision before constructing
the mutation; omitted client preconditions cannot omit this check. Approval binds
the asset/interface/state/revision/transaction. Stale state, unknown interfaces,
symlinks and consumed transaction IDs reject dispatch. Atomic replacement and
fsync preserve the captured state; all product writers use the per-device lock.
Concurrent external writers are unsupported and must be reconciled by the owner.

A verified interface change offers a typed restoration only after prior state is
captured and current restoration checks pass. Restoration is a new preview/action,
requires the exact post-change revision, same asset/UID, an unconsumed snapshot and
300-second lifetime. It never executes a rollback string or overwrites intervening
edits. Failed/uncertain operations require review; no universal recovery is claimed.

## Actual verification and pending acceptance

Windows: 166 tests run, 163 passed/3 POSIX skips (1.537 s). Four new native tests
passed in 25.851 s: real repeatable Python project/interpreter; preservation of
owner edits; development-device diff/apply/verify/restore/replay/stale/symlink cases;
actual local typed remote peer with durable replay rejection. No physical device,
real SSH login or service mutation was tested. Full combined runs are recorded in
VERIFICATION.md. Vendor/emulator selection remains a deployment decision; the
shared contract and development adapter are usable meanwhile.

Requirement coverage advances environment/DevOps scope, 15–25, 52–62 and 63–70
partially. Predictive resources (50), full legacy recipe breadth, multi-host lab
acceptance and performance remain explicitly pending. All original 1–72 identifiers
and unknown source labels are preserved.
