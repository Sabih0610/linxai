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

### Cisco IOS XR (DevNet "IOS XR Always On" sandbox, `gold-cisco-xr.json`)

Same procedure: the owner launched the sandbox and saved its password file; LINxAI connected
with the pinned host key. Identity: Cisco IOS XR 25.3.1 (XRd), hostname `xrd-1`,
`MgmtEth0/RP0/CPU0/0` flagged as management. Probes are validate-only and always discarded.
The sandbox is shared, so nothing was committed.

| Result | Features |
| --- | --- |
| Validated by the device (10) | hostname, banner, DNS server, interface description, IPv4, static route, OSPF interface, BGP global, ACL entry |
| Not validated alone (needs another feature first) | BGP neighbour, BGP peer group, access VLAN |
| Rejected by the device | NTP server (`unknown-namespace`), although the knowledge base predicts support from the advertised models |
| Unsupported by model | VLAN, OpenConfig QoS, the SR Linux native profiles |
| Not probed | LAG member (the device has no LAG interface) |

What the Cisco run found and fixed:
* **Protocol instance naming.** IOS XR rejects an OpenConfig static route under the instance
  name `static` (SR Linux's name) and validates it under `DEFAULT`. The first probe run therefore
  marked static routes unsupported, which was wrong. An asset can now carry `protocol_names`
  (`{"STATIC": "DEFAULT"}`); discovery proposes it for IOS XR and the probe checks it.
* **Tunnel entries are not ports.** XR lists SR-TE tunnels (`srte_c_...`) in the interface
  model without a type or state. Only typed Ethernet/LAG interfaces are proposed as ports now.
* **Shared sandboxes drop sessions under load.** Some runs failed LINxAI's pre- or post-check
  at random. Discovery now repeats read-only and validate-only actions up to three times
  (10 s and 20 s pauses), each attempt audited, before reporting "not probed".
* NTP: the same `unknown-namespace` rejection was seen on IOS XR 7.9 earlier, so the knowledge
  base's model-level prediction is overruled by device evidence on both releases.

## 4. Chat grounded in the gold profile (`ai/network_planner.py`)

A chat request that names a registered NETCONF device is handled from that device's gold
profile (stored by `scripts/discover.py --state <agent state>` in `discovery.sqlite`).
Other requests go to the existing planner unchanged.

* **Capability questions** ("what can srl1 do") are answered from the profile only. The
  answer covers identity, proven, supported, not offered (with the reason), unsupported
  (with the vendor evidence), ports and security notes. The UI shows it with Confirm
  disabled.
* **Change requests** map to ONE typed feature:
  1. **Fixed patterns** handle common phrasings exactly (hostname, description, banner,
     DNS, NTP, IPv4, static route, LAG, BGP neighbour, VLAN, access VLAN).
  2. Otherwise a **deterministic keyword shortlist** narrows the candidates. The local
     model (Ollama, `qwen2.5:1.5b`) chooses only on a tie, and then only among the tied
     features.
  3. The model then fills that feature's settings from field hints.
* **Grounding** (anti-hallucination): every address, number, port and name the model
  returns must appear in the request. Banner and description text must be the
  requester's exact words. Only naming defaults (ACL name, sequence) may come from the
  example. Malformed or extra output is refused, never repaired.
* **Gating**: features the profile marks unsupported or warned are refused with the
  evidence, before the device is contacted. A device without a profile must be discovered
  first. Quoted, translated or override wording never yields a change (the existing
  injection guard).
* The result is only a proposal. The agent reads the device for a preview revision,
  previews the typed `device.config.set` with the profile evidence ("committed and
  restored on this device 11 times"), and the owner confirms. Apply, verify and restore
  are unchanged.

**Accuracy against srl1's real profile with the local model** (`scripts/eval_network_intents.py`):

| Run | Correct | Wrong change proposals |
| --- | --- | --- |
| Tuning set (27 requests), first design | 17/27 | 1 |
| Tuning set, final design (tuned on this set) | 27/27 | 0 |
| **Held-out set (20 new phrasings), first and only blind run** | **15/20** | **1** (banner text re-capitalised) |
| Held-out set after general fixes (no longer blind) | 17/20 | 0 |

The tuning-set score is optimistic because the design was tuned on it. The held-out
first run is the honest estimate.

**Optimising the small model (same qwen2.5:1.5b, no new model).** A new **blind set** of 32
requests across both profiles (Nokia srl1 and Cisco xr, including Cisco-style phrasing such
as `router bgp 65300` and `Gi0/0/0/0`) was written first and scored on the old design. Only
the score was looked at, not the cases. Then:

1. **Schema-constrained decoding** (Ollama `format` = JSON schema): the choose step can only
   emit one of the tied features or `none`; the fill step can only emit the feature's own keys,
   integers where the feature takes numbers, the profile's port names and the ACL action words.
2. **One worked example per feature** in the fill step, with documentation values used in no
   evaluation set.
3. **Interface abbreviations**: `Gi0/0/0/0` resolves to the profile's `GigabitEthernet0/0/0/0`
   only when exactly one port matches; grounding accepts the abbreviation.
4. Fixes found on the (no longer blind) held-out set:
   * the request's own action word wins over one copied from the example;
   * an invented value for an *optional* setting (BGP router id) is dropped instead of refusing
     the request, while an invented required value still refuses;
   * free text never keeps a trailing "on <device>".

| Blind set (32 requests, two vendors) | Correct | Wrong change proposals | Avg. time per model request |
| --- | --- | --- | --- |
| Old design (`chat-blind-baseline.json`) | 26/32 | 0 | 2.6 s |
| **Optimised, scored once** (`chat-blind-final-1.5b.json`) | **30/32** | **0** | 2.9 s |

The optimised design also scores 27/27 on the tuning set and 20/20 on the old held-out set
(both seen before, so not blind). The two blind misses are refusals ("srl1 new name:
pod4-leaf1" and "on xr give Gi0/0/0/0 the ip 10.10.10.1/30"); they were left unfixed so the
blind score stays honest.

**Smaller model: `qwen2.5:0.5b` (398 MB) against `qwen2.5:1.5b` (986 MB)**, same design and bounds.
The first 0.5B blind run is `chat-blind-final-0.5b.json`. On the older sets the 0.5B model
proposed the **device's own name as a value** ("please rename srl1 to access-sw-3" became hostname
`srl1`; a DSCP policy named `srl1`). Grounding accepted it because "srl1" is in the request. It was a
real hole for any model, now closed: the target device's name is never evidence for a setting value. An address given as
`a.b.c.d/n` is split into address and prefix length. All sets were then re-run on both models
(`chat-compare-after-fix/`, not blind):

| | qwen2.5:1.5b | qwen2.5:0.5b |
| --- | --- | --- |
| Blind set, first run (32) | **30/32, 0 wrong** | **29/32, 0 wrong** |
| Blind set after the fix (not blind) | 30/32, 0 wrong | 29/32, 0 wrong |
| Old held-out set (20), before the fix | 20/20, 0 wrong | 17/20, **2 wrong** (device name as value) |
| Old held-out set after the fix | 20/20 (twice), 19/20 (once), 0 wrong | 18/20, 0 wrong |
| Tuning set (27) after the fix | 27/27, 0 wrong | 26/27, 0 wrong |
| Avg. time per model request (blind) | 2.9 s | 2.6 s |

Findings:
* With the bounds and grounding in place, the 0.5B model is within one blind request of the
  1.5B model and makes no wrong proposals; its extra misses are refusals (ACL action wording,
  a policy name).
* On this laptop the speed gain is small (about 10 %), because each request is two short
  constrained calls and much of the time is fixed overhead; the memory saving is the larger
  gain (398 MB against 986 MB).
* Even at temperature 0, Ollama is not perfectly repeatable: the same held-out set gave
  20, 19 and 20 out of 20 on three runs of the 1.5B model. Single-run scores are therefore
  quoted with about ±1 request.
* 1.5B stays the default. 0.5B is a usable choice for low-memory hosts behind the same bounds. The remaining misses are refusals ("no supported
network change recognised"), not wrong changes. Every wrong proposal would still have
been shown in the preview for confirmation.

**Live end to end on srl1** (`scripts/accept_network_chat.py`,
`evidence/discovery-2026-11-10/chat-live-srl1.json`):
* "set the hostname of srl1 to chat-lab" and "add dns server 192.0.2.153 on srl1" each
  went from chat sentence to gold-grounded plan to a committed, verified change and its
  restore.
* "create vlan 40" and "add ntp server" were refused before the device was contacted,
  quoting the vendor deviation and the failure history.
* "what can srl1 do" was answered from the profile.

Result: 6/6. On the first run, right after a switch reset, the whole-config check
failed once. That is SR Linux's known first-use DNS residue (an empty native
`dns-instance mgmt`, see NETWORK_DEVICES.md). The rerun on the same switch passed 6/6
with the whole config identical.

## Not done yet

* SSH command-line families (Cisco/Huawei/Juniper `show`/`display` output). The
  ntc-templates parsing templates and their real sample outputs are downloaded for this;
  the parser needs the TextFSM library.
* Cisco commit and restore: the Always-On router is shared, so only validate-only probes ran.
  Proving commits needs a private reservable sandbox (or the sandbox rules allowing it).
* A fine-tuned (LoRA) small model on phrasings generated from the typed registry; it needs a
  training library and the owner's OK to install it.
* Data from sources that need an account: Cisco DevNet reservable sandboxes, Juniper
  vLabs, Arista cEOS.
