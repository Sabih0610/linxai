# Lab environments: the LINxAI VM and the WSL network/IoT lab

One place that says where the test labs are, how they were built, what runs in them and
how to rebuild them. Written 15 November 2026 **from the repository only**: the VM was
not booted to check it (no VirtualBox on the host at the time). Every fact cites its
source; anything not recorded is listed under [Unknowns](#9-unknowns-check-these-in-the-vm).
Where this file and an evidence README disagree, the evidence README is the record.

Two labs were used, not one:

| Lab | Where it lives | What it ran |
| --- | --- | --- |
| **VirtualBox VM `LINxAI`** | `D:\LinxAI\LINxAI\` on the owner's Windows PC | Broker, kernel sensor, policy daemon, monitor; Gates B, D, E; red team; remote/agentless Linux; integrated acceptance and soak |
| **WSL2 `Ubuntu-24.04`** | `E:\WSL\Ubuntu-24.04\ext4.vhdx` (9.5 GB) | Nokia SR Linux NETCONF lab (Docker), IoT lab (Mosquitto + Modbus simulator), Go/C++/Docker recipe validation, knowledge base build (probably) |

`docs/SETUP.md` describes an **older** Multipass VM (`linxai-dev`, Ubuntu 22.04). It is
historical and does not describe either lab above.

## 1. The VM itself

From `D:\LinxAI\LINxAI\LINxAI.vbox` (VirtualBox settings format 1.19) and
`docs/evidence/vm-lab-2026-11-08/README.md`, `environment.txt`, `gate-e/environment.txt`.

| Item | Value |
| --- | --- |
| VirtualBox | 7.1.12, on Hyper-V (NEM mode). Reinstall the same version: `https://download.virtualbox.org/virtualbox/7.1.12/` |
| Files | `LINxAI.vbox`; base disk `LINxAI.vdi` (15.6 GB); **differencing disk** `Snapshots/{20f85d0e-3755-459f-b6ac-8e7d1e7b0b50}.vdi` (9.6 GB). The differencing disk holds every change since 8 Nov. **Copy or move the whole folder; never the base `.vdi` alone** |
| Snapshot | `before-broker-acceptance-2026-11-08` ("Clean state before LINxAI Gate B broker deployment"), 2026-11-08 03:10 UTC. Restoring it discards all lab work since |
| Hardware now | 2 vCPU, 4096 MB RAM (the snapshot recorded 5 vCPU / 8000 MB), VMSVGA 16 MB, SATA AHCI disk, Intel 82540EM NIC |
| Network | NAT; port forward `SSH`: host `127.0.0.1:2222` → guest `10.0.2.15:22`. From the guest, the Windows host is `10.0.2.2` |
| Install media | `ubuntu-24.04.4-live-server-amd64.iso` (Ubuntu **Server**), was at `E:\downloads\` (no longer there) |
| Guest OS | Ubuntu 24.04.4 LTS, hostname `linxai`, root on LVM (`/dev/mapper/ubuntu--vg-ubuntu--lv`, about 47 GiB) |
| Kernel | 6.8.0-124-generic on 8 Nov; unattended-upgrades installed **6.8.0-147-generic** on 9 Nov, running from the Gate E reboot through the 13 Nov red team |
| Boot | `lsm=lockdown,capability,landlock,yama,apparmor,bpf` (BPF LSM added for Gate E, section 3) |
| Base software | systemd 255.4-1ubuntu8.16, polkitd 124-2ubuntu1.24.04.3, Python 3.12.3, bpfcc 0.29.1+ds-1ubuntu7, BTF present |
| User | `linxai`, uid 1000, the only broker owner; the console session is `tty1` on `seat0` |
| Lab directory | `/home/linxai/linxai-lab/`: `src/` (archive of f3519e8), `src-dev/` (development tree the later runs used), `runs/`, bundle tars, lab scripts |

**Access.** Start the VM, then `ssh -p 2222 linxai@127.0.0.1` from Windows. The login
method (password or key, and which key) is not recorded. Anything that needs polkit
(`auth_admin`) must be run at the **VM console**: polkit only prompts an active local
seat, so SSH sessions and WSL cannot approve admin actions.

**Stability.** Under sustained load the VM loses guest time. Soft lockups appeared at a
load of about 28; an unpinned 8-process benchmark forced a VM reset; unattended-upgrades
caused lockups of up to 115 s and restarted the sensor (`docs/VERIFICATION.md` 517–519,
594–611). Pause unattended-upgrades before long soaks.

## 2. Packages on the VM

| Software | How it got there | Source |
| --- | --- | --- |
| polkit | `deploy-broker.sh` installs it if missing: `apt-get install -y polkitd pkexec` | `lab-scripts/deploy-broker.sh:14-17` |
| BCC | OS packages only, never PyPI `bcc`: `python3-bpfcc bpfcc-tools libbpfcc-dev` plus `linux-headers-$(uname -r)` | `requirements/sensor-os.json` |
| bpftool | used by `deploy-sensor.sh`; install not recorded (`linux-tools-$(uname -r)` on Ubuntu) | `deploy-sensor.sh:45` |
| LangGraph 1.2.20 | in a test venv; optional, not in the locked set; venv path not recorded | `VERIFICATION.md` 630–632 |
| Node.js | `/usr/bin/node` exists; install not recorded | `VERIFICATION.md` 534–536 |
| nc, perl, curl | used by the red-team scripts; install not recorded | `QA_2026-11-13.md` |
| nginx | leftover from June; one config listens on **port 4444**, which the red-team scripts reuse | `QA_2026-11-13.md` 98–99 |
| Ollama | the docs disagree: the 8 Nov intent evaluation used the **Windows host's** Ollama ("the VM is too slow"), but the 13 Nov red team reached a model on `127.0.0.1:11434` and calls it "the target's cold model (2 vCPUs)". Models in use: `qwen2.5:1.5b` (default), `qwen2.5:0.5b` | `VERIFICATION.md` 521–522; `QA_2026-11-13.md` 23; `DISCOVERY.md` |

`scripts/setup_dev.py` (the locked uv environment) was **never** run on the VM; tests ran
with the OS `/usr/bin/python3`, so two `linux`-group tests that need the locked setup
fail there (`VERIFICATION.md` 537–539).

## 3. Kernel change: BPF LSM (Gate E)

`docs/evidence/vm-lab-2026-11-08/lab-scripts/gate-e-1-enable-bpf-lsm.sh`, at the console:

```sh
sudo bash ~/linxai-lab/gate-e-1-enable-bpf-lsm.sh   # needs CONFIG_BPF_LSM=y
sudo reboot
```

It appends `,bpf` to the active `/sys/kernel/security/lsm` list and writes
`/etc/default/grub.d/99-linxai-bpf-lsm.cfg`, then runs `update-grub`. Undo:
`sudo rm /etc/default/grub.d/99-linxai-bpf-lsm.cfg && sudo update-grub && sudo reboot`.

## 4. LINxAI components deployed on the VM

**Trusted bundle.** Build with `python scripts/package_trusted.py dist/<name>.tar` from a
clean commit, using LF line endings (`git -c core.autocrlf=false archive`, or build on
Linux). Every deploy script verifies the bundle against
`usr/share/doc/linxai/broker-manifest.json` before installing anything.

| Bundle | Built from | SHA-256 prefix |
| --- | --- | --- |
| `linxai-broker.tar` | f3519e8 (CRLF, built on Windows) | `b77dee64` |
| `linxai-trusted-lf.tar` | f3519e8, LF | `4691a00e` |
| `linxai-trusted-fix.tar` | f3519e8 + monitor throughput patch | `ed147f04` |
| `linxai-trusted-dev.tar` | development tree | `9d739d3d` |
| 13 Nov bundle | a14a75d, later the widened sensor (4 kprobe programs) | not recorded |

**What gets installed** (all root-owned; **nothing is enabled at boot**, so after a reboot
the services must be started again):

| Path | Contents |
| --- | --- |
| `/usr/lib/linxai-trusted/` | trusted code: `broker_entry.py`, `operations/`, `security/`, `ebpf/`, `executor/face_auth.py` (dirs 0755, files 0644) |
| `/usr/share/polkit-1/actions/org.linxai.service.policy` | actions `org.linxai.service.manage`, `response.manage`, `process.manage`, `face.manage`, all `allow_active=auth_admin` |
| `/etc/systemd/system/linxai-broker.service` | `python3 -I -B /usr/lib/linxai-trusted/broker_entry.py`; socket `/run/linxai/broker.sock` |
| `/etc/systemd/system/linxai-sensor.service` | `broker_entry.py sensor` (root BCC capture); socket `/run/linxai-sensor/events.sock` |
| `/etc/systemd/system/linxai-policy.service` | `broker_entry.py policy` (BPF LSM enforcement); socket `/run/linxai-policy/control.sock` |
| `/etc/systemd/system/linxai-lab-acceptance.service` | harmless fixture (`sleep infinity`, `DynamicUser=yes`) the broker may start/stop |
| `/etc/linxai/broker.json` | `{"owner_uid":1000,"services":["linxai-lab-acceptance.service"]}` |
| `/etc/linxai/response.json` | `{"owner_uid":1000,"targets":[{"address":"127.0.0.1","port":4444}],"max_duration":300,"max_active":16,"auto_enabled":false}` (mode 0644) |
| `/var/lib/linxai-{broker,sensor,policy}/` | daemon state (removed by the uninstall scripts with `--purge`) |

**Monitor.** Runs as the ordinary owner, not as root, as a transient user unit (from
`lake/lake_demo.sh`; run from the source tree):

```sh
systemd-run --user -q --unit=linxai-monitor-lab --working-directory="$PWD" \
  /usr/bin/python3 -B -c 'import sys; sys.path.insert(0, "."); from security.monitor import main; main()'
```

It must be started through `main()` (the module has no `__main__`). Its database is
`~/.linxai/security.sqlite`.

### Rebuild order

All scripts are in `docs/evidence/vm-lab-2026-11-08/lab-scripts/`. Copy them and the
bundle tars into `~/linxai-lab/` on the VM. Steps marked **console** need the owner's
password typed at the VM console.

1. Install Ubuntu Server 24.04, user `linxai`; install BCC, headers, bpftool (section 2).
2. Disable the legacy June services (section 7).
3. **console** `sudo bash deploy-broker.sh` (broker, polkit action, fixture, `broker.json`).
4. **console** `sudo bash deploy-sensor.sh` (sensor; needs `broker.json` and kernel headers).
   For a development build, `sudo bash admin-session.sh` runs steps 3 and 4 together.
5. **console** `sudo bash gate-e-1-enable-bpf-lsm.sh`, then `sudo reboot`.
6. **console** `sudo bash gate-e-2-qualify.sh` (policy daemon, `response.json`, kernel qualification).
7. Start the monitor (above).
8. Remote/agentless peers (section 6).

Undo: `uninstall-sensor.sh` and `uninstall-broker.sh` (add `--purge` to delete state).

> **Check before reuse: `deploy-sensor.sh` ignores its argument.** It always extracts
> `linxai-trusted-lf.tar` (line 15). `admin-session.sh` passes `linxai-trusted-dev.tar`
> and deploys the broker from it first, so as committed the sensor step would replace the
> dev code in `/usr/lib/linxai-trusted` with the older LF build. Either the lab copy of
> `linxai-trusted-lf.tar` had been replaced at the time, or this went unnoticed. Make the
> script take the tar name (`"${1:-linxai-trusted-lf.tar}"`) before using it again.

## 5. Acceptance runs on the VM, in order

Opt-in variables keep these out of the normal test suites (`scripts/test.py` groups:
`offline`, `linux`, `privileged`, `desktop`, `hardware`, `model`, `all`).

| Date | Run | Command / opt-in | Result |
| --- | --- | --- | --- |
| 8 Nov | Gate B broker (console) | `run-acceptance.sh` → `LINXAI_TEST_BROKER_LAB=1 scripts/accept_broker.py` | run 1 failed closed (no polkit agent), run 2 PASS |
| 8 Nov | Gate D monitor | `LINXAI_TEST_KERNEL=1 scripts/accept_monitor.py` | FAIL, then PASS after the throughput fix |
| 8 Nov | resources, intents | `bench_resources.py` (1 vCPU pinned), `eval_intents.py` | `docs/evidence/vm-lab-2026-11-08/bench`, `intents/` |
| 9 Nov | process restore (console) | `run-restore.sh` → `LINXAI_TEST_BROKER_LAB=1 scripts/accept_restore.py` | PASS |
| 9 Nov | detection | `scripts/accept_detection.py` | 4/4 fixtures |
| 9 Nov | remote SSH peer | `LINXAI_TEST_REMOTE_LAB=1 scripts/accept_remote.py` | PASS |
| 9 Nov | agentless Linux | `LINXAI_TEST_AGENTLESS_LAB=1 scripts/accept_agentless.py --system vmloop --user vmloop-user --second vmnat` | PASS |
| 9 Nov | agentless Windows | `LINXAI_TEST_WINDOWS_LAB=1 scripts/accept_windows_agentless.py --asset win` | 8/8 |
| 9 Nov | integrated soak | `scripts/soak_integrated.py --hours 24` | stopped at 8.9 h |
| 9 Nov | Gate E (console) | `gate-e-1`, reboot, `gate-e-2` (`LINXAI_TEST_KERNEL=1 accept_policy.py`) | PASS |
| 9 Nov | end to end | `LINXAI_TEST_INTEGRATED=1 scripts/accept_integrated.py` | 13/13 |
| 13 Nov | red team | `LINXAI_TEST_REDTEAM=1 scripts/redteam_detect.py`; `redteam_block.py` at the console | 7/14, then 14/14 after widening; block 8/8 |

Results: `docs/evidence/vm-lab-2026-11-08/`, `docs/evidence/qa-2026-11-13/`, `docs/QA_2026-11-13.md`.

## 6. Remote and agentless targets (on the VM)

* **Typed SSH peer** (`lab-scripts/remote-setup.sh`, no sudo): key `~/.ssh/linxai_peer`
  (`restrict` line in `authorized_keys`), pinned `~/.linxai-peer/known_hosts`, peer venv
  `~/.local/share/linxai/peer-venv` pointing at `~/linxai-lab/src-dev`, assets
  `~/.linxai-peer/assets.json`.
* **Agentless Linux** (`lab-scripts/agentless-setup.sh`): user unit
  `linxai-agentless-demo.service`; assets `vmloop` (127.0.0.1), `vmloop-user`, `vmnat`
  (the VM's NAT address) in `~/.linxai-peer/agentless.json`. No NOPASSWD sudo rule, on
  purpose: system-scope changes are refused.
* **Windows target** = the owner's Windows PC, reached from the VM at `10.0.2.2`.
  `docs/evidence/windows-lab-2026-11-09/windows-openssh-setup.ps1` (elevated) installs
  OpenSSH Server (manual start) and adds the lab key (`linxai-windows-lab`) to
  `C:\ProgramData\ssh\administrators_authorized_keys`. The test uses the Spooler service.
  **After a Windows reinstall this must be redone**, and the private key/asset file on
  the VM side is not recorded.

## 7. Legacy June components on the VM

`linxai-core` and `linxai-ebpf` (from `/opt/linxai`) are still installed and
`linxai-core` is **enabled at boot**. It runs model text with `shell=True` and the eBPF
daemon auto-kills processes. Every deploy script only stops them for the run. Disable
them once:

```sh
sudo systemctl disable --now linxai-core linxai-ebpf
```

The repository templates (`systemd/linxai-core.service` with `User=ubuntu`) do not match
the VM user, so the installed unit files differ from the repo.

## 8. The WSL2 lab (network devices, IoT)

Distro `Ubuntu-24.04`, user `sabih`, source copied from `/mnt/e/FYP/code 2/linxai` to
`~/linxai-dev` (the drive letter was E: then). The disk survives at
`E:\WSL\Ubuntu-24.04\ext4.vhdx`; after installing WSL, re-register it without copying:

```powershell
wsl --import-in-place Ubuntu-24.04 E:\WSL\Ubuntu-24.04\ext4.vhdx
```

**Nokia SR Linux** (`docs/evidence/netconf-lab-2026-11-09/lab-scripts/`, `netconf-lab-2026-11-10/`):

```sh
docker run -t -d --privileged --name srl1 -p 127.0.0.1:2830:830 -p 127.0.0.1:2022:22 \
  ghcr.io/nokia/srlinux sudo bash /opt/srlinux/bin/sr_linux     # srl-up.sh
```

Then `srl-netconf.sh` (NETCONF on 830, lab key `/root/linxai-netlab/id_ed25519`, LLDP,
OpenConfig), `lab-root-prep.sh` (disables `ethernet-1/1`, copies the key to
`~/.linxai-netlab/`), `lab-user-prep.sh` (pins the host key trust-on-first-use, writes
`~/.linxai-netlab/assets.json`, mode 0600). srl2 listens on `127.0.0.1:2831` with state
in `~/.linxai-netlab/state2`; **its `docker run` line is not recorded**. Image observed:
SR Linux 26.7.2-519, 7220 IXR-D3L. Batch/EVPN/LAG prep: `batch-prep.sh`,
`srl-lag-prep.sh`, `run-batch-evpn.sh`. Run: `run-accept.sh`
(`LINXAI_TEST_NETCONF_LAB=1`). A freshly reset switch gives 10/11 on the first run
(documented first-use DNS residue), 11/11 after.

**Cisco IOS XR**: DevNet "IOS XR Always On" sandbox (`sandbox-iosxr-1.cisco.com`, XRd
25.3.1, hostname `xrd-1`), validate-only, never committed. Password login only with a
pinned host key; the password sits in an owner-written private file named by the asset's
`password_file`. Run: `LINXAI_TEST_NETCONF_SHARED=1 python3 -B scripts/validate_netconf_shared.py --assets a.json --asset xr`.

**IoT** (`docs/evidence/iot-lab-2026-11-09/lab-scripts/`): Mosquitto 2.0.18 on
`127.0.0.1:1883` (no anonymous access; `iot-root-prep.sh` writes random passwords to
`~/.linxai-iot/{mqtt,device}.pass` and the broker ACL), pymodbus 3.6.9 simulator
`scripts/iot_lab_sim.py` on `127.0.0.1:5020` unit 1 (`iot-user-prep.sh`). Run:
`run-iot.sh` (`LINXAI_TEST_IOT_LAB=1`). Python packages `pymodbus`, `paho-mqtt`,
`ncclient` (install not recorded).

**Knowledge base**: `python3 -m discovery.kb --root ~/kb-data --out ~/kb-data/linxai-kb.sqlite`
from clones of YangModels/yang, Juniper/yang, Huawei/yang (layout in `discovery/kb.py`);
1,306 platform releases. ntc-templates are at `D:\FYP\kb-data\ntc-templates` on Windows.
Clone commands, revisions and which machine holds `~/kb-data` are not recorded.

**Recipes**: Go (`golang:1.22-alpine`), C++ (Alpine CMake, host g++) and Docker recipes
were validated in WSL with `LINXAI_TEST_RECIPES=1` (`docs/WORKFLOWS.md`).

## 9. Unknowns: check these in the VM

Not recorded anywhere in the repository. Boot the VM and fill these in:

* SSH login method from Windows (password or key, which key).
* apt commands for BCC, headers, bpftool, Node, nc, perl; whether Ollama and which models
  are installed on the VM.
* Path of the LangGraph test venv.
* Which bundle is currently in `/usr/lib/linxai-trusted` (compare
  `usr/share/doc/linxai/broker-manifest.json` with a fresh `package_trusted.py` build),
  and whether `/etc/linxai/*.json` still match section 4.
* Which LINxAI and legacy units are enabled (`systemctl list-unit-files 'linxai*'`), the
  installed legacy unit files, and the nginx config on 4444.
* Files in `~/linxai-lab/` that exist only in the VM (scripts edited there, `runs/` output).
* Where the Windows-lab private key and asset file live; where the Cisco password file is.
* srl2's `docker run` line; the knowledge-base clone commands and revisions.

Read-only commands that answer most of these, run as `linxai`:

```sh
uname -a; cat /proc/cmdline; cat /sys/kernel/security/lsm
apt list --installed 2>/dev/null | grep -Ei 'bpfcc|linux-(headers|tools)|polkit|nodejs|nginx|netcat|perl'
systemctl list-unit-files 'linxai*' --no-pager; systemctl --user list-unit-files 'linxai*' --no-pager
ls -la /etc/linxai /usr/lib/linxai-trusted ~/linxai-lab ~/.linxai ~/.linxai-peer
command -v ollama && ollama list
ls /etc/nginx/sites-enabled; grep -rn 4444 /etc/nginx 2>/dev/null
```
