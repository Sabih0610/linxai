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

Windows targets (WinRM/OpenSSH + PowerShell templates) are not implemented yet.
