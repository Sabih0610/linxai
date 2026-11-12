# LINxAI Linux desktop development candidate

LINxAI combines a Linux desktop/CLI with typed administration, local natural-language
planning, durable operations, independent monitoring and scoped incident response.
The desktop/model run as an ordinary user. A separately protected broker enforces
OS authorization; no model command or UI credential flag grants privileges.

Start with [the candidate guide](docs/RELEASE_CANDIDATE.md),
[the current plan](docs/IMPLEMENTATION_PLAN.md), [verification](docs/VERIFICATION.md)
and [all original requirements 1–72](docs/REQUIREMENTS_TRACEABILITY.md).
Current status is PARTIAL: bounded workflows are integrated; full recipe/resource
breadth and target kernel/authentication/device/hardware/release acceptance remain.

```sh
python3 scripts/setup_dev.py
.venv/bin/python -B scripts/test.py offline
.venv/bin/python -B scripts/test.py linux
sh install.sh --desktop
```

Never run the application installer or desktop with sudo. No packages, services,
PAM, models or hardware are provisioned/opened as a startup side effect. See the
candidate guide for agent/desktop startup, optional local voice, protected bundle
review, reproducible artifacts and separately opt-in acceptance runners.

The original scope remains Linux administration, provisioning/DevOps, remote Linux,
network devices, SOC, independent deterministic kernel monitoring, bounded AI
response and validated recurring policies, account-bound face/password and voice.
Unknown source requirements remain unknown. No measured detection/overhead,
biometric assurance or universal threat-prevention claim is made.

Network and system engineering extensions (November 2026):
[network devices over NETCONF](docs/NETWORK_DEVICES.md) (typed OpenConfig and native
features, confirmed commit, verified restore, coordinated multi-device batches),
[device discovery, vendor knowledge base and chat grounded in gold capability
profiles](docs/DISCOVERY.md) (Nokia SR Linux lab and Cisco IOS XR sandbox, local
`qwen2.5:1.5b`/`0.5b` with blind evaluation), [IoT](docs/IOT.md) and
[agentless Linux/Windows targets](docs/AGENTLESS.md). Progress log: [PROGRESS.md](docs/PROGRESS.md).

Older status, sudo-installer and timing claims are retained only as
[historical documentation](docs/history/README_PRE_CANDIDATE.md).
