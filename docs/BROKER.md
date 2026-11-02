# Gate B: bounded privileged service mechanism

Implementation and deterministic verification are separate from real target
acceptance. The broker extends OperationService; it does not introduce a second
action vocabulary. Default OperationService still refuses administrative dispatch.

Production transport is a version-1 length-prefixed JSON Unix socket protocol,
262144-byte frames, one request per connection, four workers, eight backlog slots
and a five-second initial read timeout. Requests contain only version, canonical
UUID request_id and typed action/parameters. UID/argv/authenticated/sudo/model
claims are rejected. SO_PEERCRED plus /proc start time and all UID/GID credentials
identify a live ordinary peer; PID reuse/credential change fails closed.

Root-owned configuration allows one owner UID and at most 32 explicit .service
units. The broker only supports service.start/stop/restart and cannot manage its
own or polkit/dbus infrastructure. Independent authorization checks use pkcheck's
pid,start,uid subject, the exact action/target/digest/operation ID and the existing
OS agent. Passwords never enter the app or model. Denial, cancellation, no agent,
timeout and missing broker are explicit failures. auth_admin has no retained
authorization default; the operation-bound in-memory grant expires after 30 s.

The broker reconstructs the registry action, runs every mandatory check, compares
fresh state before dispatch, executes the exact argv with shell=False, verifies
fresh service state and emits the same UUID/fingerprint throughout. TCP constraints
are live ss queries. Captured service observations include current state, so stale
approvals fail. Persistent request admission rejects replays, including after
restart. The bounded admission table fails closed at 10000 entries; archive it in
a reviewed maintenance procedure rather than silently reusing old IDs. Loss of a
response after dispatch is unknown; the client never retries automatically.

Root audit is private, fsynced JSONL, rotated at 8 MiB with three retained generations.
State SQLite is private, synchronous, schema-versioned and capped at 8192 pages.
The supervising adapter bounds pipes and deadlines and kills its process group
on overflow/timeout. Root output is capped at 8192 bytes per stream. Restoration
is not automatically inferred: normal operations still report recovery unsupported.
The explicit lab captures prior state and restores via a fresh validated broker
start/stop operation, never a model rollback string.

## Packaging and isolated target acceptance

`python scripts/package_trusted.py dist/linxai-broker.tar` creates a deterministic
manifested archive; it never deploys. Create dist first. Review its contents. The
ordinary-user application installer does not install privileged components.
On a deliberately prepared isolated lab, an administrator must extract the reviewed
artifact to root-owned paths, install root-owned /etc/linxai/broker.json based on the
example, and select only linxai-lab-acceptance.service for automated acceptance.
Use a harmless long-running fixture with ExecStart=/usr/bin/sleep infinity. No
service or authorization configuration is changed by routine tests.

The unit invokes OS Python with -I. broker_entry verifies the whole root-owned,
non-writable, symlink-free code bundle **before importing operations**; the app's
user-owned wheel or checkout is never a privileged import path. The unit is separately
supervised, uses private state/runtime directories and filesystem restrictions.
The broker refuses to unlink an unknown stale socket. After an abnormal crash,
review its owner/type and reconcile root audit before restarting; automatic unlink
is intentionally not a recovery policy.

On the prepared system with real polkit/agent and ordinary configured owner:

```sh
LINXAI_TEST_BROKER_LAB=1 .venv/bin/python -B scripts/accept_broker.py
```

This actually starts/restarts/stops only the named fixture and records results and
validated prior-state restoration in broker-acceptance.json. Authentication that
cannot complete unattended remains pending; no test-only bypass is installed.
Contract doubles are not real OS authentication/service evidence. WSL currently
has no systemd/polkit bus, so this target procedure is pending while C–H development
continues. Peer-credential/process/storage tests can run natively without root.

Official decisions: [pkcheck subject triple and cancellation](https://www.freedesktop.org/software/polkit/docs/latest/pkcheck.1.html),
[polkit mechanism practices](https://www.freedesktop.org/software/polkit/docs/latest/polkit-apps.html),
[Unix peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html).
