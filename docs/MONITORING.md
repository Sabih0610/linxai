# Independent capture and deterministic incidents

Gate D reuses ebpf/daemon.py and its three C probes. The deployed OS-interpreter
sensor is independent of the model, desktop and ordinary-user application agent.
The root sensor and user monitor have separate systemd unit templates; routine
installation does not enable them. Desktop Security reads the monitor's private
SQLite state and shows missing, degraded and stale capture explicitly.

The protected bootstrap verifies the immutable root-owned bundle before imports.
Its `sensor` component loads OS BCC only during explicitly deployed startup.
Root owner configuration controls the read-only local event socket. Clients verify
root peer credentials; the sensor independently checks peer UID. It accepts only
bounded poll/event lookups, never commands or raw event injection. A lifetime lock
prevents duplicate collectors. A four-entry socket backlog and absolute two-second
read deadline bound slow clients. Missing BCC/load failures become unavailable;
partial probe loads are cleaned up. No model/UI dependency is in either unit.

Kernel callbacks enqueue at most 1024 records; transport retains 2048 entries and
serves 32 at a time. Kernel lost samples, callback drops, buffer eviction, cursor
gaps, invalid records and stale capture are visible. Root event evidence retains
2000 private SQLite records. User monitoring retains 2000 events and 1000 incident
snapshots, with explicit eviction and degraded-storage behavior. Authoritative
response policy is not stored in this user-writable incident database.

Normalized evidence includes schema/version, host/boot identity, UID, PID, parent
when supplied, kernel monotonic time, group-leader process start time, target and
transport provenance. Missing identity is marked incomplete; PID/process name
alone is never a reusable process authorization key. The existing x86_64 syscall
wrapper exec argument handling was corrected; other architectures are unverified.
Kernel start-time reads and BCC attachment still require actual target compilation.

Deterministic rules identify non-root sensitive-file attempts and temporary-path
execution attempts. They create warning incidents, not proof of malicious intent.
Near-matches and root reads are tested benign. Current probes observe syscall
entry, so return/outcome is explicitly unknown; capture is not prevention. Model
output and event text cannot mutate the system through the detector.

The ordinary-user monitor polls independently, validates bounded records,
deduplicates event IDs, preserves cursor/epoch and records state. UI closure and a
blocked model do not stop this path. Process supervision/readiness and kernel event
loss need real target evidence; deterministic thread tests are not that evidence.

Build a reviewed protected archive with scripts/package_trusted.py. Root extraction,
OS BCC packages/headers, service configuration and target hook access are separate
deployment/acceptance procedures. Never run root imports from the app's wheel or
user-owned checkout. Existing /opt units remain historical and are not installed.
Use the new deployment/linxai-sensor.service and user linxai-monitor.service only
after reviewing the actual target's privileges and paths. Sensor unit capability
reduction/hardening must be tested against BCC on that kernel before release;
the current template is an isolated-lab deployment input, not hardened acceptance.

```sh
# Ordinary-user deterministic checks; never attaches BPF:
.venv/bin/python -B -m unittest test_security_monitor -v
# Prepared isolated target, real sensor and monitor already running:
LINXAI_TEST_KERNEL=1 .venv/bin/python -B scripts/accept_monitor.py
```

The target runner executes a harmless owned temporary script and attempts to open
/etc/shadow without reading credentials. It requires real captured identities and
the correlated independently produced incident. It never installs/enables hooks
or changes permissions on host paths. Current WSL has no BCC/systemd and cannot
supply this acceptance; default invocation reports pending (exit 3).

Requirement coverage: original 30–44, 58–60, 65, 67–70 advance partially. Prevention
item 45 and adaptive policies are E; measured overhead/performance remain H. The
model/UI absence test uses a simulated event adapter and is labelled accordingly.

Sources: [BCC callback and perf-buffer contracts](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md),
[BCC process start-time example](https://github.com/iovisor/bcc/blob/master/tools/exitsnoop.py).
