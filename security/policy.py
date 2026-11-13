"""Root policy authority: evidence, independent owner limits, qualification and lifecycle."""
import hashlib
import ipaddress
import json
import time
from uuid import UUID

from operations.response_contracts import NetworkResponse, RevokeResponse, uuid


class Authority:
    def __init__(self, config, store, kernel, evidence, *, clock=None):
        if set(config) != {"owner_uid", "targets", "max_duration", "max_active", "auto_enabled"}:
            raise ValueError("Unknown response configuration")
        if type(config["owner_uid"]) is not int or config["owner_uid"] <= 0 or type(config["auto_enabled"]) is not bool:
            raise ValueError("Invalid owner/automatic response configuration")
        if type(config["max_duration"]) is not int or not 30 <= config["max_duration"] <= 3600:
            raise ValueError("Invalid duration limit")
        if type(config["max_active"]) is not int or not 1 <= config["max_active"] <= 64:
            raise ValueError("Invalid policy capacity")
        if not isinstance(config["targets"], list) or not 1 <= len(config["targets"]) <= 32:
            raise ValueError("Explicit bounded owner targets required")
        self.targets = set()
        for target in config["targets"]:
            if set(target) != {"address", "port"} or type(target["port"]) is not int or not 1 <= target["port"] <= 65535:
                raise ValueError("Invalid target scope")
            self.targets.add((str(ipaddress.IPv4Address(target["address"])), target["port"]))
        self.config, self.store, self.kernel, self.evidence, self.clock = config, store, kernel, evidence, clock or kernel.now
        self.config_hash = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()

    def preview(self, actor_uid, parameters, *, revoke=False):
        if type(actor_uid) is not int or actor_uid != self.config["owner_uid"]:
            raise PermissionError("Response actor differs from independently configured owner")
        if revoke:
            if set(parameters) != {"policy_id"}: raise ValueError("Exact revocation parameters required")
            policy = self.store.get("policy", uuid(parameters["policy_id"]))
            if not policy or policy["uid"] != actor_uid: raise ValueError("Unknown owned policy")
            return {"owner_uid": actor_uid, "config": self.config_hash, "policy_state": policy["state"], "version": policy["version"]}
        if set(parameters) != {"policy_id", "event_id", "address", "port", "duration"}:
            raise ValueError("Exact bounded response parameters required")
        uuid(parameters["policy_id"])
        uuid(parameters["event_id"])
        address = str(ipaddress.IPv4Address(parameters["address"]))
        if not isinstance(parameters["address"], str) or address != parameters["address"]:
            raise ValueError("Canonical address required")
        if type(parameters["port"]) is not int or (address, parameters["port"]) not in self.targets:
            raise PermissionError("Target is outside root-owned owner limits")
        if type(parameters["duration"]) is not int or not 30 <= parameters["duration"] <= self.config["max_duration"]:
            raise PermissionError("Duration exceeds owner limits")
        if self.store.get("policy", parameters["policy_id"]): raise ValueError("Policy ID already consumed")
        active = [row for row in self.store.list("policy", 1000) if row["state"] in {"installed", "active"} and row["expires_ns"] > self.clock()]
        if len(active) >= self.config["max_active"] or any((row["address"], row["port"]) == (address, parameters["port"]) for row in active):
            raise ValueError("Active policy capacity/scope conflict")
        event = self.evidence(parameters["event_id"])
        if (not event or event.get("source") != "kernel" or event.get("identity_quality") != "kernel_start_identity"
                or event.get("id") != parameters["event_id"] or event.get("host") != self.kernel.host or event.get("uid") != actor_uid or event.get("kind") != "network_connect" or event.get("protocol") != "tcp"
                or event.get("target") != {"address": address, "port": parameters["port"]}
                or event.get("boot") != self.kernel.boot or not 0 <= self.clock() - event.get("received_boottime_ns", 0) <= 120_000_000_000):
            raise PermissionError("Recent matching authenticated kernel evidence required")
        if not self.kernel.scope_available(actor_uid, address, parameters["port"]):
            raise PermissionError("Existing kernel policy owns this scope")
        if not self.kernel.qualified(): raise PermissionError("Native kernel qualification required")
        return {"owner_uid": actor_uid, "config": self.config_hash, "event_id": event["id"],
                "event_subject": event["subject"], "kernel": self.kernel.digest, "boot": self.kernel.boot,
                "active": len(active), "scope": [address, parameters["port"]]}

    def automatic(self, actor_uid, parameters, operation_id, digest):
        if self.config["auto_enabled"] is not True:
            raise PermissionError("Root owner configuration disables automatic responses")
        proof = self.preview(actor_uid, parameters)
        return {"authorized": True, "owner_uid": actor_uid, "operation_id": uuid(operation_id),
                "digest": digest, "config": proof["config"], "scope": proof["scope"]}

    def apply(self, actor_uid, parameters, operation_id):
        uuid(operation_id)
        provenance = self.preview(actor_uid, parameters)
        policy = {"schema": 1, "id": parameters["policy_id"], "version": 1, "uid": actor_uid,
                  "address": parameters["address"], "port": parameters["port"], "event_id": parameters["event_id"],
                  "expires_ns": self.clock() + parameters["duration"] * 1_000_000_000,
                  "expires_wall": time.time() + parameters["duration"], "state": "installing",
                  "operation_id": operation_id, "provenance": provenance,
                  "verification_origin": "native_kernel" if self.kernel.real else "simulated",
                  "validation": "owner scope + qualified hook contract"}
        if hasattr(self.store, "retire"):  # finished policies stop counting against the 1000-record cap
            self.store.retire("policy", lambda old: old.get("state") not in {"installing", "installed", "active", "review_required"})
        self.store.put("policy", policy["id"], policy, replace=False)
        try:
            self.kernel.install(policy)
            policy["state"] = "installed"
            self.store.put("policy", policy["id"], policy)
        except Exception:
            policy["state"] = "review_required"
            self.store.put("policy", policy["id"], policy)
            raise
        return policy

    def verify(self, policy_id):
        policy = self.store.get("policy", uuid(policy_id))
        if not policy: raise ValueError("Unknown policy")
        if policy["state"] == "revoked":
            return {"verified": not self.kernel.contains(policy), "policy": policy}
        if policy["state"] not in {"installed", "active"} or self.clock() >= policy["expires_ns"]:
            return {"verified": False, "policy": policy}
        verified = self.kernel.qualified() and self.kernel.contains(policy) and self.kernel.verify_denial(policy)
        if verified:
            policy.update(state="active", containment="kernel denial observed; scoped future connects only")
            self.store.put("policy", policy_id, policy)
        return {"verified": bool(verified), "policy": policy}

    def revoke(self, actor_uid, parameters, operation_id):
        self.preview(actor_uid, parameters, revoke=True)
        policy = self.store.get("policy", parameters["policy_id"])
        self.kernel.remove(policy)
        policy.update(state="revoked", revoked_by_operation=uuid(operation_id))
        self.store.put("policy", policy["id"], policy)
        return policy

    def tick(self):
        for policy in self.store.list("policy", 1000):
            if policy["state"] in {"installed", "active", "installing"}:
                if self.clock() >= policy["expires_ns"] or policy["provenance"].get("boot") != self.kernel.boot:
                    self.kernel.remove(policy)
                    policy["state"] = "expired"
                elif not self.kernel.contains(policy):
                    permitted = (policy["state"] == "active" and self.config["auto_enabled"] is True
                                 and policy["uid"] == self.config["owner_uid"]
                                 and (policy["address"], policy["port"]) in self.targets
                                 and policy["provenance"]["config"] == self.config_hash
                                 and policy["provenance"]["kernel"] == self.kernel.digest
                                 and self.kernel.qualified())
                    if permitted:
                        self.kernel.install(policy)  # Original expiry is retained; no model or UI flag.
                        if not self.kernel.contains(policy): policy["state"] = "review_required"
                    else:
                        policy["state"] = "review_required"
                else:
                    continue
                self.store.put("policy", policy["id"], policy)
