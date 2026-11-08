# Gate B broker target acceptance — VirtualBox Ubuntu VM, 8 November 2026

**Result: PASS for the bounded service route on a prepared local-console target.**
`scripts/accept_broker.py` (opt-in `LINXAI_TEST_BROKER_LAB=1`) exited 0. Real polkit
authentication, real systemd mutations, broker post-condition verification and
validated prior-state restoration all succeeded.

## Target

| Item | Value |
| --- | --- |
| Host | Windows 11 Pro, VirtualBox 7.1.12 running on Hyper-V (NEM mode), 2 vCPU / 4 GiB |
| Guest | Ubuntu 24.04.4 LTS, kernel 6.8.0-124-generic, systemd 255, polkitd 124 |
| Session | `tty1` on `seat0`, `Remote=no`, `Active=yes` (VM console, not SSH) |
| Owner | `linxai` (uid 1000), the only configured broker owner |
| Allowlist | `linxai-lab-acceptance.service` only (`ExecStart=/usr/bin/sleep infinity`, `DynamicUser=yes`) |
| Code | Commit `f3519e8` via `git archive`; bundle from `scripts/package_trusted.py`, SHA256 `b77dee64…81a0` |

Full values are in `environment.txt`. The deployed trusted code is byte-identical
to the committed blobs after line-ending normalization (`broker.py` → `8aa9c805…`,
`broker_entry.py` → `22cf6a6b…`). The bundle was built on Windows with
`core.autocrlf=true`, so it carries CRLF line endings; Python is unaffected, but
future bundles should be built with `git -c core.autocrlf=false archive` or on Linux.

## Runs

| Run | File | Outcome |
| --- | --- | --- |
| 1 | `broker-acceptance-run1-no-agent-denied.json` | Lab wrapper registered `pkttyagent` for the parent shell, not the requesting process. polkit found no agent; the broker returned `authentication_authorization_required`, `executed=false`, `audit_complete=true`, no retry. **Fail-closed behaviour confirmed.** |
| 2 | `broker-acceptance-run2-pass.json` | Agent registered for the exact client pid/start. Four one-shot authorizations (polkit journal), `service.start`, `service.restart`, `service.stop` each `succeeded`, `executed=true`, `verified=true`, distinct operation IDs and fingerprints. Restoration returned the fixture to its prior `inactive` state. |

`journal-polkit-broker-fixture.txt` correlates each authentication
(`ONE-SHOT authorization for action org.linxai.service.manage for
unix-process:3697:48696 [/usr/bin/python3 -B scripts/accept_broker.py]`) with the
matching systemd start/stop of the fixture.

## Procedure

`lab-scripts/` holds the exact scripts used. An administrator ran
`sudo bash deploy-broker.sh` on the console (manifest verification, root-owned
`/usr/lib/linxai-trusted`, policy action file, broker unit, root-owned
`/etc/linxai/broker.json`, fixture unit; nothing enabled at boot). The legacy June
root daemons `linxai-core` and `linxai-ebpf` (`/opt/linxai`) were stopped, not
removed, for the duration. `run-acceptance.sh` ran from the console; the owner typed
their own password at each prompt. No polkit rule, test bypass or password was
supplied by tooling. A VirtualBox snapshot `before-broker-acceptance-2026-11-08`
precedes all changes; `uninstall-broker.sh` removes the deployment.

## What this does and does not establish

Establishes, for original items 16, 20, 22, 25, 26 and Gate B: peer-bound
authorization through real polkit with an OS password, exact allowlisted
mutation, fresh post-condition verification, correlated operation IDs, validated
restoration, and fail-closed denial when no authentication agent is reachable.

Does not establish: the root audit ledger contents (root-only, not exported here);
user-initiated cancellation and wrong-password denial (not exercised); desktop
polkit-agent behaviour; restart/reboot lifecycle of the broker unit; any kernel,
face, voice, SSH or device acceptance.

Finding for the product: on a console/server login no session authentication agent
exists, so the agent/CLI route needs to provide one (as the lab wrapper did) or
report that authorization requires a desktop session. WSL cannot satisfy the
shipped `allow_active` policy at all because it has no logind seat.
