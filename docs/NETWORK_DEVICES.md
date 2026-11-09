# Network devices over NETCONF (vendor-neutral extension)

LINxAI manages routers and switches through the same typed device actions it already
uses — `device.inspect`, `device.interface.set`, `device.interface.restore` — with a
new asset platform `netconf`. The AI never sends device commands: it can only propose
one of these typed actions, which the owner previews and confirms.

## Status (9 November 2026)

| Target | Status |
| --- | --- |
| Nokia SR Linux v26.7.2 (free container, WSL2 lab) | **Accepted**: `scripts/accept_netconf.py` 11/11 (`docs/evidence/netconf-lab-2026-11-09/`) |
| Juniper Junos (vJunos, free, needs KVM) | Not yet tested — same NETCONF/OpenConfig path |
| Cisco IOS XR (DevNet always-on sandbox `sandbox-iosxr-1.cisco.com`, shared) | **Validated non-disruptively**: `scripts/validate_netconf_shared.py` 5/5 — inspect, change prerequisites (not executed), wrong host key refused before password auth, exact OpenConfig edit staged under our lock, validated by the router and discarded, running config unchanged (`docs/evidence/netconf-lab-2026-11-09/cisco-iosxr-shared-validation.json`). No commit on the shared router, per Cisco's sandbox rules |
| Cisco IOS-XE / NX-OS | Not yet tested — IOS-XE always-on sandboxes were unreachable; IOS-XE needs the candidate datastore feature |
| Huawei VRP8 / CloudEngine | Not yet tested — same path; university hardware needed (no free emulator confirmed) |
| IoT (MQTT, Modbus), agentless remote machines | Planned next phases |

Rows marked Accepted or Validated are verified claims; IOS XR is validated without committing.

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
