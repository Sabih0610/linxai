# Scoped response and recurring enforcement

Gate E adds response.network.block and response.policy.revoke to the **existing**
registry/OperationService/broker. The application is not reduced to these actions:
the full inventory and F–H breadth remain required. This initial prevention path
is limited to owner UID + exact IPv4 address + exact TCP destination port. It does
not claim general threat prevention, IPv6/SCTP/UDP coverage, existing-connection
termination or prevention of the unfamiliar incident's first syscall.

An incident proposal is built from the kernel evidence (`security/response.py`
`block_request`): the target is always the exact observed address and port. The
bounded loopback Ollama adapter may only suggest a duration (30–300 s) within a 10 s
budget; a slow, absent or malformed model, or one naming any other target, leaves the
default duration (120 s). Changed on 13 November 2026 after the red-team run, where a
cold model on the 2-vCPU target timed out and containment depended on it. Event text is
untrusted; backend code supplies policy/evidence IDs. A preview/confirmation produces a durable job,
then root authorization and mandatory checks. Model commands, risk, requires_sudo,
authenticated flags, caller UID or policy limits are never executable authority.
Desktop Security offers response and revocation previews through the same flow.

The protected broker reconstructs typed parameters and binds actor, target,
duration, evidence/policy UUID, fixed helper argv/stdin and operation UUID to the
approval digest. The final operation UUID is compiled into the fixed stdlib helper
payload before authorization; revalidation reconstructs it identically. Root kernel
policy and broker audit records correlate by that UUID. The ordinary service still
refuses all privileged actions when no broker exists.

The separate root policy daemon is deployed through the protected bootstrap, not
the user-owned app environment. It verifies root-owned response.json limits,
fresh matching root-sensor evidence, host/boot/start provenance, owner UID, exact
allowed target, duration, capacity and native kernel qualification independently.
User incident SQLite and model memory are never authoritative policy storage.
Production requires BCC's OS interpreter and an active BPF LSM, not only CONFIG
flags. The BPF LSM socket_connect program preserves previous denial decisions,
limits itself to IPv4 TCP and uses bounded maps. Empty/expired entries allow the
hook. No hook is loaded during routine setup/tests.

Kernel qualification is an explicit root-only procedure in the immutable bundle.
It creates only new loopback fixtures and proves actual owner denial, benign UID/
address/port near-matches, revocation and expiry before writing a root qualification
record bound to the program digest and boot. The application cannot submit a
qualification=true claim. A policy install then reads back its exact map entry;
postcondition verification runs a fixed probe dropped to the configured ordinary
UID and requires both EPERM and a corresponding kernel denial-counter increase.
Map presence or exit zero alone is not containment evidence.

Policies retain schema/version, exact scope, source event, root configuration and
program/boot provenance, operation UUID, validation origin, expiry and revocation.
Simulated test providers store verification_origin=simulated; these are not native
acceptance. Failed verification remains installed/reviewable rather than promoted.
TTL uses CLOCK_BOOTTIME and bpf_ktime_get_boot_ns so suspend does not extend expiry.
Kernel expiry does not wait for the desktop/model. The independent daemon removes
expired/revoked entries and records lifecycle state.

Default automatic response is **disabled**. An explicitly root-configured owner
may enable it within exact target/duration/capacity limits. The unprivileged
response worker's status boolean is only a scheduling hint: the broker asks the
root authority again, binds its decision to operation/digest/owner and reruns all
mandatory checks. A false UI/model claim cannot grant permission. Known active
policies cover matching recurrence without invoking the model. Restore after a
daemon restart requires previously active root policy, identical configuration/
program/boot, native qualification, owner auto-enable and the **original** expiry;
otherwise status requires review. No arbitrary rollback or PID-only policy exists.

TCP evidence uses a TCP-specific kernel observation in addition to retained
unknown-protocol syscall observations; unknown protocol cannot authorize a TCP
policy. The agent's model-response worker bounds failed proposals to three
attempts with backoff before escalation, one thread and eight recent
incidents per poll, separately from capture/detection/jobs. Missing model/kernel/
authority degrades response status; it cannot stall deterministic monitoring.
Local model HTTP has fixed loopback destination, no proxy/redirect path, absolute
30-second deadline and bounded headers/body. No model is started or downloaded.

## Prepared target procedures

The archive contains deployment/linxai-policy.service and response.example.json.
An administrator reviews protected extraction and creates /etc/linxai/response.json
for the actual owner and lab targets. Keep auto_enabled=false until that scope and
native verification are accepted. The unit is independent of desktop/model but
requires the root sensor for authoritative evidence. Root component hardening and
actual BCC/kernel compatibility remain target acceptance tasks.

```sh
# Routine simulated contracts, no BPF:
.venv/bin/python -B -m unittest test_response_policy test_local_http -v
# Prepared target, root-owned installed bundle and policy daemon already running:
LINXAI_TEST_KERNEL=1 /usr/bin/python3 -I -B /usr/lib/linxai-trusted/broker_entry.py qualify
# Default lightweight runner invocation returns PENDING (exit 3):
.venv/bin/python -B scripts/accept_policy.py
```

The qualification command must run in an explicitly authorized root lab context;
never import user-owned project source as root or change host security to pass.
Capture its JSON plus actual broker/agent incident-response, recurrence, benign,
expiry/revocation evidence. Root qualification alone is not password-authentication
acceptance; B's polkit scenario remains separate. Native first-incident and recurring
latencies, false positives and overhead are unmeasured until H's controlled runs.

Current automated results use simulated kernel/evidence/auth adapters. The actual
WSL environment has no BCC/systemd, so no native enforcement claim is made. Original
requirements 36, 40–45, 58–60 and expanded adaptive-policy scope advance partially;
all other original requirements remain in the matrix.

References: [BCC LSM contract](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md),
[boot-time helper semantics](https://man7.org/linux/man-pages/man7/BPF-HELPERS.7.html).
