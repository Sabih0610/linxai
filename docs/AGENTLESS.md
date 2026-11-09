# Agentless Linux targets (no LINxAI installed on the target)

`remote.operation` on an asset with platform `linux_agentless` runs typed actions on
a Linux machine that only has sshd, coreutils, iproute2 and systemd.

| | Agent peer (`linux_ssh`) | Agentless (`linux_agentless`) |
| --- | --- | --- |
| Install on target | LINxAI peer | nothing |
| Re-validation | target re-validates every request | controller only |
| Audit / replay store | both sides | controller only |
| Kernel threat detection on target | possible (install the sensor) | **not possible** |
| Admin changes | target broker + polkit | target `sudo -n` policy (owner-granted) |

## How it works

`/usr/bin/ssh` with a pinned known_hosts file, key-only login, BatchMode, no agent,
forwarding or control master; the remote command is built from a fixed template per
action, with registry-validated values shell-quoted, run under `env LC_ALL=C`.

| Action | Template | Verification |
| --- | --- | --- |
| `disk.usage` | `df -P -k -x tmpfs …` | parsed per filesystem |
| `memory.usage` | `cat /proc/meminfo` | parsed total/available/used % |
| `ports.listen` | `ss -H -ltn` (optional port filter) | parsed address/port |
| `service.status` | `systemctl show <unit> -p …` | parsed state |
| `service.start/stop/restart` | `sudo -n systemctl <verb> -- <unit>` (system scope) or `systemctl --user …` | re-read: active / inactive; restart must change `ActiveEnterTimestampMonotonic` |

The prerequisite check proves reachability through the pinned host key and, for
services, that the unit is loaded. System-scope changes need a narrow `NOPASSWD`
rule for `/usr/bin/systemctl` on the target; without it LINxAI reports a clear
policy refusal and never prompts for or types a password.

## Asset

```json
{"web1": {"platform": "linux_agentless", "host": "192.0.2.30", "port": 22, "username": "ops",
          "key_path": "/home/owner/.ssh/linxai_ops", "known_hosts": "/home/owner/.linxai/known_hosts",
          "systemd_scope": "system"}}
```

## Evidence

`scripts/accept_agentless.py` 9/9 on the VirtualBox VM through its loopback and NAT
addresses (same machine — not two physical hosts): reads, user-service
start/restart/stop with a new activation time, system change refused by the
target's sudo policy, unloaded unit refused, shell injection / raw command / file
write refused, host-key mismatch refused (`evidence/vm-lab-2026-11-08/agentless-acceptance.json`).

## Windows targets (`windows_agentless`)

Same pinned-SSH hardening against the built-in Windows OpenSSH server. Each action is a
fixed PowerShell template sent with `-EncodedCommand` (base64 UTF-16LE, so no shell
quoting), returning JSON: `Win32_LogicalDisk`, `Win32_OperatingSystem`,
`Get-NetTCPConnection -State Listen`, `Win32_Service`, and `Start/Stop/Restart-Service`.
Service names are limited to `[A-Za-z0-9_.-]`. A restart of an own-process service must
show a new process id; for shared-process services the proof is reported as unavailable.
Changes need rights on the target; refusals are reported, never bypassed.

Evidence: `scripts/accept_windows_agentless.py` 8/8 against the owner's Windows 11 PC
from the Linux VM controller (VirtualBox NAT 10.0.2.2), host key pinned and matched to
the fingerprint the owner's setup printed: disk/memory/ports/service reads; Print
Spooler start, restart (new process id) and stop, returned to its original state;
unknown service, PowerShell injection, raw command and file write refused; host-key
mismatch refused (`evidence/windows-lab-2026-11-09/`). One-time owner setup:
`windows-openssh-setup.ps1` (OpenSSH server, Manual start, lab key only).
