# Network devices over NETCONF (vendor-neutral extension)

LINxAI manages routers and switches through the same typed device actions it already
uses — `device.inspect`, `device.interface.set`, `device.interface.restore` — with a
new asset platform `netconf`. The AI never sends device commands: it can only propose
one of these typed actions, which the owner previews and confirms.

## Status (10 November 2026)

| Target | Status |
| --- | --- |
| Nokia SR Linux v26.7.2 (free container, WSL2 lab) | **Accepted**: `scripts/accept_netconf.py` 11/11 (`docs/evidence/netconf-lab-2026-11-09/`); config features 10/11 and two-device batch 3/3 (`docs/evidence/netconf-lab-2026-11-10/`) |
| Juniper Junos (vJunos, free, needs KVM) | Not yet tested — same NETCONF/OpenConfig path |
| Cisco IOS XR (DevNet always-on sandbox `sandbox-iosxr-1.cisco.com`, shared) | **Validated non-disruptively**: `scripts/validate_netconf_shared.py` 5/5 — inspect, change prerequisites (not executed), wrong host key refused before password auth, exact OpenConfig edit staged under our lock, validated by the router and discarded, running config unchanged (`docs/evidence/netconf-lab-2026-11-09/cisco-iosxr-shared-validation.json`). No commit on the shared router, per Cisco's sandbox rules |
| Cisco IOS-XE / NX-OS | Not yet tested — IOS-XE always-on sandboxes were unreachable; IOS-XE needs the candidate datastore feature |
| Huawei VRP8 / CloudEngine | Not yet tested — same path; university hardware needed (no free emulator confirmed) |
| IoT (MQTT, Modbus), agentless remote machines | Built and accepted — see `IOT.md` and `AGENTLESS.md` |

Rows marked Accepted or Validated are verified claims; IOS XR is validated without committing.

Update 10 November 2026 (later): Cisco retired the old shared sandbox; the owner launched
the new DevNet "IOS XR Always On" deployment (same host, per-deployment password). LINxAI
discovered it read-only as IOS XR 25.3.1 (XRd) and its validate-only probes accepted 10
features; NTP was rejected. Still no commit on the shared router. Device discovery, the gold
capability profiles and the chat planner that reads them are documented in
[DISCOVERY.md](DISCOVERY.md).

## How a change is made (fixed worker, ordinary user)

1. Connect with key-only SSH; compare the device host key with the pinned SHA256
   fingerprint **before any RPC**; refuse on mismatch.
2. Require capabilities `candidate`, `confirmed-commit:1.1`, `validate` and the
   OpenConfig interfaces model; refuse otherwise.
3. Check the expected revision (hash of the allowlisted interfaces' state from the
   preview); refuse if the device changed since the preview.
4. Lock the candidate (refuse — never discard — if another operator has pending
   edits), write a transaction snapshot of the prior state, edit one allowlisted
   interface (`enabled` true/false), validate.
5. **Confirmed commit** with a 60 s automatic rollback; read the running config back;
   confirm only if it matches, otherwise cancel (device rolls back).
6. Postcondition re-read in a separate process; the result offers a typed
   `device.interface.restore` (valid 300 s, revision-bound, single use).

Private-candidate devices (SR Linux) reject a confirmed commit under a lock; the
worker then commits without the lock, still guarded by the revision check.

## Asset configuration (owner-configured, private file)

```json
{"core1": {"platform": "netconf", "host": "192.0.2.10", "port": 830, "username": "netops",
           "key_path": "/home/owner/.linxai/netconf/id_ed25519",
           "host_key_sha256": "SHA256:<43 base64 chars>",
           "state_dir": "/home/owner/.linxai/netconf/state",
           "ports": ["ge-0/0/1"]}}
```

`ports` is the allowlist; nothing else on the device can be changed.

## Enabling NETCONF on devices (check the vendor docs for your release)

- Juniper Junos: `set system services netconf ssh` (port 830); OpenConfig support
  depends on release.
- Cisco IOS-XE: `netconf-yang` and `netconf-yang feature candidate-datastore`
  (confirmed commit requires the candidate datastore).
- Cisco IOS-XR: `netconf-yang agent ssh` and `ssh server netconf`.
- Huawei VRP8/CloudEngine: enable the NETCONF service over SSH (port 830) per the
  CloudEngine configuration guide.
- Nokia SR Linux: see `evidence/netconf-lab-2026-11-09/lab-scripts/srl-netconf.sh`.

## Plan for the one-hour supervised university session

Before the session (offline): run `test_workflows` and `accept_netconf.py` against
the free lab; prepare the asset file with the device's pinned host key (ask the
supervisor for it) and **one spare test port**.

1. (5 min) Supervisor confirms the test port and that NETCONF is enabled.
2. (10 min) `device.inspect` only — read-only; record capabilities and revision.
3. (15 min) `accept_netconf.py` on the single allowlisted port: change, independent
   read-back, refusals, restore, rollback safety nets. Every change is undone.
4. (10 min) Repeat on the second vendor if time allows.
5. (10 min) Collect the JSON evidence and the device's own commit log for the report.

Abort criteria: any FAIL in step 3, any unexpected capability gap, or any change
outside the test port — the confirmed-commit timer reverts unconfirmed changes.

## Configuration features (`device.config.read` / `set` / `restore` / `batch`)

Beyond the interface on/off actions, an owner can enable typed OpenConfig features per
asset (`"features": [...]` in the asset file; anything not listed is refused). Each
feature is declared once in `operations/netconf_features.py` as a path plus a config
dict, and one generic engine (`operations/_netconf_config_program.py`) handles all of
them: snapshot the target node, confirmed commit, read-back, confirm, and a typed
single-use restore (replace with the snapshot, or remove only the list entry the change
created; each ancestor is probed separately because devices return empty data for a
filter that names a missing entry).

Guards that apply before anything is sent: interface allowlist, no default route, no
prefix, route or drop-ACL that covers the management address, BGP neighbor not the
management address, strict hostname/name patterns, LAG member cannot be the LAG itself.

| Feature | Nokia SR Linux 26.7 (lab, commit + restore) | Cisco IOS XR (shared sandbox, validate only) |
| --- | --- | --- |
| interface.description | **commit + restore, whole config identical** | validated |
| system.hostname | **commit + restore, whole config identical** | validated |
| system.banner (MOTD) | **commit + restore, whole config identical** | validated |
| system.dns_server | commit + restore of the DNS node; SR Linux keeps an empty native `dns-instance mgmt` binding (see findings) | validated |
| system.ntp_server | not supported (SR Linux needs a network-instance for NTP) | not supported (unknown namespace) |
| interface.ipv4 | **commit + restore, whole config identical** | validated |
| static_route | **commit + restore, whole config identical** | validated |
| vlan, interface.access_vlan | not supported by SR Linux's OpenConfig (this 7220 IXR-D3L switch does layer 2 through MAC-VRFs and bridged subinterfaces; a native profile is needed) | not supported on the router |
| ospf.interface | not supported by this SR Linux OpenConfig release | validated |
| bgp.global | **commit + restore, whole config identical** | rejected (sandbox already runs its own BGP instance) |
| bgp.peer_group | **commit + restore, whole config identical** | validated |
| bgp.neighbor | **commit + restore, whole config identical** | validated |
| lag.member | **commit + restore, whole config identical** | validated |
| acl.entry | **commit + restore, whole config identical** | validated |
| qos.queue, qos.forwarding_group, qos.classifier_term, qos.interface_classifier (OpenConfig) | rejected: SR Linux's OpenConfig QoS translation needs a native queue-index; use the native profile below | not offered (no openconfig-qos) |

**QoS and EVPN-VXLAN on SR Linux (vendor-native profile).** SR Linux marks OpenConfig
EVPN, connection-points and BGP l2vpn-evpn as not-supported, and its OpenConfig QoS cannot
create queues or classes, so these are typed features on Nokia's native models, run by
the same engine (snapshot, confirmed commit, read-back, typed restore). The lab case
chains each feature on its prerequisites and restores them in reverse.

| Feature (SR Linux native) | Settings | Lab result |
| --- | --- | --- |
| srl.qos_queue | queue `unicast-0..7` / `multicast-0..7` (index derived) | **commit + restore, whole config identical** |
| srl.qos_forwarding_class | class `fc0..fc7`, unicast queue | **commit + restore, whole config identical** |
| srl.qos_dscp_rule | policy, DSCP 0–63, class | **commit + restore, whole config identical** |
| srl.qos_interface_policy | allowlisted interface (subinterface 0), policy | **commit + restore, whole config identical** |
| srl.vxlan_interface | `vxlanN`, VNI 1–16777215, bridged | **commit + restore, whole config identical** |
| srl.mac_vrf_evpn | MAC-VRF name (never default/mgmt), VNI, EVI, route target | **commit + restore, whole config identical** |

**Coordinated multi-device change** (`device.config.batch`, 2–4 ordered changes across one
or more devices, each device node changed once): every device gets ONE provisional
confirmed commit holding all its changes, all are read back, then all are confirmed. A
failure before confirming cancels every provisional commit (and discards the cancelled
edits, which SR Linux otherwise keeps in the candidate); a failure while confirming
compensates any device already confirmed by restoring its snapshots in one commit and
reports which were compensated. Each change gets its own typed restore, returned in
reverse order. Accepted with `scripts/accept_netconf_batch.py` on two SR Linux nodes: a
hostname change on both (3/3) and EVPN-VXLAN on both — VXLAN interface then MAC-VRF on
each, 4 changes in one transaction (3/3): applied and verified, every change restored
with both whole configs identical, and a batch the second node rejected left the first
node's whole config unchanged.

Not yet built: wireless mesh via the Meraki/Catalyst controller APIs (needs an API key),
Juniper vJunos (needs the image download). EVPN data-plane traffic between the two lab
nodes is not tested (they have no data links); the evidence covers the control-plane
configuration on both nodes.

## Findings from the lab feature runs

- The first restore design trusted one filtered read to decide which ancestors existed.
  SR Linux answers a filter naming a missing entry with empty data, so undoing a new
  BGP peer group removed the whole default network-instance. Fixed by probing each
  ancestor separately (regression test in `test_netconf_features.py`), and the
  acceptance now compares the device's whole running config before and after.
- Removing BGP on SR Linux can still be in progress when the confirm arrives ("commit
  confirmed in progress"); the worker retries only that exact condition briefly
  (bounded, about 15 s, inside the 60 s timer) and cancels at once if confirming still
  fails. A first version matched any "in progress" text, which also matched SR Linux's
  private-candidate message and silently cost 15 s per change; timing every RPC found it.
- A worker killed between edit and discard (e.g. at its deadline) leaves SR Linux's
  shared candidate "modified". LINxAI then refuses every change on that device rather
  than discarding edits it cannot prove are its own; the owner clears it on the device.
  The batch keeps the project-wide 30 s action bound, so all provisional commits are
  confirmed well inside their 60 s timers.
- After `cancel-commit`, SR Linux keeps the cancelled edits in the shared candidate, which
  blocks every later change; the worker now discards right after every cancel.
- In a two-device EVPN batch the second device answered "commit already in progress"
  while confirming, after the first had confirmed; the first device kept the change. The
  worker now retries that transient answer and, if confirming still fails, compensates
  every already-confirmed device from its snapshots and reports the outcome.
- SR Linux QoS: OpenConfig queues and forwarding groups are rejected at commit (a native
  `queue-index` is required, and both unicast and multicast queues for a class); the
  native chain queue -> forwarding class -> DSCP policy -> subinterface binding works.
- SR Linux's own OpenConfig translation adds a native `dns-instance mgmt` binding the
  first time a DNS server is configured and keeps it after the server is removed. The
  OpenConfig DNS node is restored exactly; the empty native binding is a device-side
  residue that a vendor-neutral restore cannot see, so the whole-config check reports it.

## Findings from the real Cisco IOS XR run

- IOS XR keeps interface configuration in its native models, so the OpenConfig
  *config* tree was empty; the driver now falls back to the OpenConfig
  `admin-status`, which every implementation reports.
- A router across the internet needs about 6 s to log in and read; device actions
  now have a 30 s contract and slow (>= 20 s) actions get a proportional
  observation budget (up to 25 s) instead of the fixed 5 s.
- Password login (sandbox credentials) is supported only with the full pinned host
  key, enforced in the SSH handshake before the password is sent. The sandbox does
  not publish its fingerprint, so the pin was trust-on-first-use. The password is
  kept in a private file written by the owner; LINxAI never logs or returns it.
- IOS XR 25.3.1 names its OpenConfig static-routing instance `DEFAULT`; SR Linux uses
  `static`. An asset may carry `protocol_names` (`{"STATIC": "DEFAULT"}`), which discovery
  proposes for IOS XR and the probe confirms. Requests may still override it.
- XR lists SR-TE tunnels in the interface model without a type; they are not offered as ports.
- The shared sandbox drops sessions under load; discovery repeats its read-only and
  validate-only actions up to three times, each attempt audited.
