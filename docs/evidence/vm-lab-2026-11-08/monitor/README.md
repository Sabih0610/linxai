# Gate D monitor target run — same VirtualBox Ubuntu VM, 8 November 2026

**Result: acceptance FAIL (sensor not ready). Real kernel capture WORKS, but the
capture → monitor path cannot keep up with an idle server's event rate.**

## What ran

- Trusted bundle rebuilt from commit `f3519e8` with LF endings
  (`git -c core.autocrlf=false archive`); bundle SHA256 `4691a00e…132d`; deployed
  files hash-identical to the committed blobs.
- Root sensor `linxai-sensor.service` (OS Python 3.12, python3-bpfcc 0.29.1,
  kernel 6.8.0-124 with headers/BTF) started by `lab-scripts/deploy-sensor.sh`;
  not enabled at boot. Legacy `/opt/linxai` eBPF/core daemons stayed stopped.
- Ordinary-user monitor started as a transient user unit from the same source.
- `scripts/accept_monitor.py` with `LINXAI_TEST_KERNEL=1`, then
  `lab-scripts/diag_monitor.py` (same actions, no `ready` requirement, longer
  wait), clearly labelled diagnostic.

## Findings

| Observation | Evidence |
| --- | --- |
| All three BCC probes compiled and attached (`execve`, `connect`, `openat`); `kernel_lost=0` | `sensor-health-final.txt` |
| Captured events carry real kernel identity (`identity_quality=kernel_start_identity`, group-leader start time, boot/host IDs) | `monitor-diagnostic-degraded.json` |
| Idle VM produces ≈140 events/s (mostly `openat`); sensor publishes ≈75/s | 30 s measurement: 2245 events read, `queue_dropped` +1928 |
| Kernel→sensor latency grew to median 25 s, p95 32 s; the diagnostic exec event arrived 67 s late | measurement + diagnostic |
| After 4 min: `queue_dropped` 19622, `buffer_evicted` 2651, `invalid` 1263; health stuck at `degraded` with `capture_stale` | `sensor-health-final.txt` |
| Official runner refused: `RuntimeError: Real kernel capture not ready`, exit 1 | `accept-monitor-official-run1.log` |
| Diagnostic: `/tmp` exec captured; `/etc/shadow` attempt dropped; no incident created because the monitor was 660 events behind | `monitor-diagnostic-degraded.json` |

## Causes (from source)

1. **Per-event durable writes on the capture thread.** `Buffer.publish` calls
   `Store.prune` and `Store.put` for every event; `Store` uses
   `journal_mode=DELETE` + `synchronous=FULL`, so each event costs two fsync'd
   transactions. On this virtual disk that caps throughput near 75 events/s.
2. **No pre-queue filtering of `openat`.** The sensor runs with
   `filter_noise=False`, so every file open is queued although the deterministic
   file rule only concerns `/etc/shadow` and `/etc/sudoers`.
3. **Non-IPv4 `connect` events are emitted.** `connect.c` sends an event for every
   `connect()`, including AF_UNIX, with address `0.0.0.0` and port 0; the
   normalizer rejects port 0, which accounts for the `invalid` counter. Each TCP
   connect is also reported twice (syscall and `tcp_v4_connect` probes).
4. **Monitor rate ceiling.** `security/monitor.py` reads at most 32 events per
   0.5 s tick (≈64/s), with a durable write per event, so it falls behind the
   sensor even without drops.
5. **Sticky health.** Once `degraded`/`capture_stale` is set it never returns to
   `ready`, so the runner can never start after any transient overload.

## Not established

Incident creation from real capture, kernel event-loss behaviour under the
sensor's own limits (the loss happened in user space), restart/reboot lifecycle,
overhead measurement (item 44) and any enforcement (item 45, Gate E).

## Rerun after the throughput fix — PASS

Fix (uncommitted at time of run; exact diff in `monitor-throughput-fix.patch`,
SHA256 `129038a0…`, including the test-only temp-dir follow-up; the deployed trusted code is unaffected by that test change): `Store.write_batch`
(one durable transaction for retention plus a batch), `Buffer.publish_many`,
pre-queue `admit()` filter (watched files only; IPv4 connects with a real port;
all execs), loss counters with a 10 s recovery window instead of sticky
`degraded`, live delivery when root evidence persistence fails (`store_errors`),
and a draining monitor that commits each batch's events, incidents and cursor
together. Bundle `linxai-trusted-fix.tar` SHA256 `ed147f04…633c` = f3519e8 + patch, LF.

| Observation | Evidence |
| --- | --- |
| `LINXAI_TEST_KERNEL=1 scripts/accept_monitor.py` exit 0: `/tmp` exec and `/etc/shadow` attempt captured with `kernel_start_identity`, delays 232 ms and 222 ms; independent monitor created `temporary_executable_attempt` and `sensitive_file_attempt` incidents | `accept-monitor-run2-pass.json`, `accept-monitor-official-run2.log` |
| First 30 s: health `ready`, `queue_dropped` 0, `invalid` 0, `kernel_lost` 0, `store_errors` 0, 444 filtered | `fixed-sensor-first-30s.txt` |
| Steady 30 s after backlog: still `ready` with zero loss counters, 3863 filtered in total; kernel→sensor latency median 1.6 s, p95 2.6 s (variable; not a benchmark); sensor ≈11 % CPU averaged over 2 min | `fixed-sensor-health-and-latency.txt` |
| Offline suite 193 run / 189 passed / 4 skipped; `test_security_monitor` 14/14 on the VM including the real-SQLite atomic batch test | test runs |

Remaining for Gate D: latency variance (perf-buffer polling loop), restart/reboot
lifecycle of the sensor unit, a wider benign/adversarial corpus with false-positive
measurement, overhead benchmark (item 44). Monitor `gaps: 660` in its persisted
status is carried over from the failed run before the fix.
