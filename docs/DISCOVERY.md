# Device discovery and the vendor knowledge base

Goal: connect an unknown network device, let LINxAI analyse it read-only, and give the
AI a clean, evidence-backed **gold capability profile** instead of raw device output.
Both pipelines follow the same medallion layout as the security lake (`security/lake.py`).

## 1. Offline vendor knowledge base (`discovery/kb.py`)

Built from public vendor data that needs no account. It is downloaded into its own
folder outside the repository and treated as untrusted *data*: parsed, never executed.

| Source | Content used |
| --- | --- |
| YangModels/yang (Cisco) | NETCONF hello capability lists per IOS-XR / IOS-XE / NX-OS release and platform, platform metadata (product IDs), vendor deviation modules |
| Juniper/yang | OpenConfig model list and `jnx-openconfig-dev` deviations per Junos and Junos Evolved release |
| Huawei/yang | model list and deviation modules per VRP router platform and version |

| Layer | Table | Content |
| --- | --- | --- |
| Bronze | `bronze_file` | every source file used: path, size, SHA-256 |
| Silver | `silver_platform`, `silver_module`, `silver_deviation` | one row per vendor platform/release, its advertised modules and parsed deviations |
| Quarantine | `quarantine` | unparsable capability lists, platforms without modules |
| Gold | `gold_support` | predicted support of every LINxAI feature per platform, with evidence |

Build: `python3 -m discovery.kb --root ~/kb-data --out ~/kb-data/linxai-kb.sqlite`.
Result (10 November 2026): **1,306 platform/release records**: Cisco IOS-XR 809, IOS-XE
379, NX-OS 79; Huawei VRP 23; Junos 8; Junos Evolved 8. They come from 11,911 source files,
with 20 quarantined (11 unparsable capability lists, 9 platforms without modules). Summary
and per-feature counts: `evidence/discovery-2026-11-10/knowledge-base-summary.json`.

A knowledge-base verdict is a *model-level prediction*: the platform advertises the
models a feature writes and the vendor has not marked those nodes `not-supported`.
Example of why it is not enough on its own: most IOS-XR 7.9 platforms advertise the
OpenConfig NTP nodes, but the live Cisco sandbox rejected NTP ("unknown namespace").

## 2. Live discovery of a registered device (`scripts/discover.py`)

1. **Owner registers the device**: address, NETCONF port, user, credentials file and
   the pinned host-key fingerprint. LINxAI never scans unregistered addresses and never
   guesses credentials.
2. **First contact** (no login): which management ports answer (22, 23, 80, 443, 830,
   5985/5986, 502, 1883, 8883, 57400) and what SSH announces. Telnet, cleartext HTTP and
   MQTT without TLS become security notes. A loopback lab address is a port-forward, so
   only its own NETCONF port is checked.
3. **`device.discover`** (typed, read-only, audited, pinned host key): hello capabilities,
   the vendor deviation modules named in them (bounded to 16 and a 20 s budget),
   OpenConfig system / platform / interface / LLDP state, and a SHA-256 fingerprint of the
   running configuration. The configuration content itself is never stored, because it
   can hold secrets.
4. **Optional `--probe`**: for each feature the model says is supported, the typed
   `device.config.probe` stages an example edit on a real port, lets the device
   validate it, and always discards it. The running config is checked unchanged in every phase.
5. **Medallion** in a private store:

| Layer | Content |
| --- | --- |
| Bronze (`disc_bronze`) | each raw reply, compressed, with SHA-256 and time |
| Silver (`disc_silver`) | identity, module count, NETCONF capabilities, components, interfaces (management flagged), LLDP neighbours, config fingerprint |
| Quarantine (`disc_quarantine`) | failed or unparsable replies (e.g. a model the device does not implement) |
| Gold (`disc_gold`) | the capability profile below |
| History (`disc_history`) | config fingerprint per discovery, for drift detection |

### Gold capability profile

* identity: vendor, OS, version, model, serial, hostname
* `safe_changes`: candidate datastore, confirmed commit and validate all present
* interfaces, with management interfaces flagged and never offered for changes
* LLDP neighbours
* per feature, from weakest to strongest evidence:
  * `supported` / `supported_with_limits` / `unsupported` by model and vendor deviation
  * `validated by device` / `rejected by device` (probe)
  * `proven`: committed and restored by LINxAI on this device before (transaction history)
  * fleet: `proven on <device>`, or a warning from another device on the same vendor, OS and version
  * warning when earlier attempts never completed a restore cycle (likely refused at commit)
* knowledge-base prior for the same vendor/OS/version
* security notes: insecure services, SSH software, configuration changed since the last discovery
* `proposed_asset`: features and ports for the owner to approve. Nothing is enabled until
  the owner approves it, and features with warnings are excluded.

A probe that fails on LINxAI's side (for example a local allowlist refusal) or for a
feature that needs another one first is reported as "not probed" / "not validated alone".
It is never taken as device evidence.

## 3. Lab results (10 November 2026)

Two Nokia SR Linux 26.7.2 switches (7220 IXR-D3L) in the WSL lab, discovered from only an
address, credentials and a pinned host key (`evidence/discovery-2026-11-10/gold-*.json`):

| | srl1 (with change history) | srl2 (fresh device) |
| --- | --- | --- |
| Identity | Nokia SR Linux 26.7.2, 7220 IXR-D3L, `mgmt0` management | same |
| Proven (committed and restored before) | 17 | 3 |
| Validated by device probe | 5 (the others were already proven) | 13 |
| Fleet evidence from srl1 | n/a | 14 features |
| Unsupported (vendor deviation) | VLAN, access VLAN, OSPF | same |
| Warnings (excluded from proposal) | OpenConfig QoS x4, NTP | same, NTP from its own history and QoS from srl1 |
| Proposed features | 17 | 17 |

The profiles match the hand-made lab findings:
* VLAN, access VLAN and OSPF are unsupported by Nokia's own deviations.
* OpenConfig QoS and NTP validate but never commit on this release.
* The native QoS and EVPN profiles are proven.

srl2's proposal excludes OpenConfig QoS only because of srl1's evidence on the same
version. Validate-only probes alone would have offered it.

Cisco IOS XR sandbox: the pinned host key still matched, but the login was refused. The
shared sandbox password has changed and the owner has to refresh the password file.

## Not done yet

* SSH command-line families (Cisco/Huawei/Juniper `show`/`display` output). The
  ntc-templates parsing templates and their real sample outputs are downloaded for this;
  the parser needs the TextFSM library.
* Cisco discovery: the shared sandbox now rejects the saved password, so the owner must
  refresh the password file (the host key still matched).
* Wiring the chat planner to read gold profiles.
* Data from sources that need an account: Cisco DevNet reservable sandboxes, Juniper
  vLabs, Arista cEOS.
