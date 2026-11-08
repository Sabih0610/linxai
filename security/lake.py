"""Local medallion pipeline over monitor evidence, plus a learned behaviour baseline.

Bronze  raw monitor events, unchanged, with source, ingestion time and SHA-256.
Silver  validated, de-duplicated, generalized events; invalid rows are quarantined.
Gold    per-account behaviour baseline trained only from eligible silver rows.

Training eligibility excludes simulated sources, incomplete kernel identity and
events that matched a deterministic incident, so known-suspicious behaviour is
never learned as normal. Model output is an advisory anomaly score: it never
creates incidents, triggers responses, enters approval digests or grants
authority. Everything stays on the host; nothing is sent to a model.
"""
import argparse
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import time

from .events import KINDS, validate

LAYER_LIMIT = 10000          # rows retained per layer (Store retention bound)
MAX_KEYS = 500               # distinct behaviour keys per (uid, kind)
MAX_ACCOUNTS = 64
READY_EVENTS = 200           # per (uid, kind) before the baseline scores anything
ANOMALY_BITS = 6.0           # novelty alert when P(unseen key) < 1/64
MODEL_ID = "gold:baseline"
_TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")


def feature_key(event):
    """Generalized behaviour key; volatile parts (temp names, remote IPs) collapse."""
    target = event.get("target", {})
    if event["kind"] == "network_connect":
        address = ipaddress.ip_address(target["address"])
        scope = "loopback" if address.is_loopback else "private" if address.is_private else "public"
        return f"{event.get('protocol', 'unknown')}/{scope}/{int(target['port'])}"
    path = str(target.get("path", ""))[:256]
    for prefix in _TEMP_PREFIXES:
        if path.startswith(prefix):
            return prefix + "*"
    return path


def empty_model():
    return {"schema": 1, "id": MODEL_ID, "version": 0, "trained_events": 0, "window": [None, None],
            "counts": {}, "eligibility": "kernel identity, not simulated, not deterministic-incident evidence"}


def score(event, model):
    """Advisory rarity of an event's key for its account, or None when not ready/known."""
    try:
        key = feature_key(event)
    except (KeyError, ValueError, TypeError):
        return None
    bucket = model.get("counts", {}).get(str(event.get("uid")), {}).get(event.get("kind"), {})
    total = sum(bucket.values())
    if total < READY_EVENTS:
        return None
    if bucket.get(key, 0):
        return None
    # Good-Turing: probability mass of unseen keys ~ (keys seen once) / total.
    # Accounts with varied behaviour therefore produce fewer novelty alerts.
    singletons = sum(1 for count in bucket.values() if count == 1)
    bits = -math.log2(max(singletons, 1) / (total + 1))
    if bits < ANOMALY_BITS:
        return None
    return {"schema": 1, "id": event["id"], "event_id": event["id"], "kind": event["kind"], "uid": event["uid"],
            "key": key, "score_bits": round(bits, 2), "baseline_events": total, "model_version": model.get("version", 0),
            "severity": "info", "created": time.time(),
            "interpretation": "Learned rarity for this account; advisory only, not an incident or a response trigger"}


class Lake:
    def __init__(self, lake_store, security_store, *, clock=time.time):
        self.lake, self.security, self.clock = lake_store, security_store, clock

    def model(self):
        return self.lake.get("gold", MODEL_ID) or empty_model()

    def run_cycle(self, limit=1000):
        """Ingest new monitor events through bronze -> silver -> gold in one transaction."""
        now = self.clock()
        incident_events = {row.get("event_id") for row in self.security.list("incident", 1000)}
        model = self.model()
        counts = model["counts"]
        writes, stats = [], {"bronze": 0, "silver": 0, "quarantine": 0, "trained": 0, "duplicates": 0}
        seen_ids = set()
        for raw in reversed(self.security.list("event", limit)):
            event_id = str(raw.get("id", ""))[:64] if isinstance(raw, dict) else ""
            if not event_id or event_id in seen_ids or self.lake.get("bronze", event_id):
                stats["duplicates"] += 1
                continue
            seen_ids.add(event_id)
            body = json.dumps(raw, sort_keys=True, separators=(",", ":"), allow_nan=False, default=str)
            writes.append(("bronze", event_id, {"source": "monitor.event", "ingested": now,
                                                "sha256": hashlib.sha256(body.encode()).hexdigest(), "raw": raw},
                           False, LAYER_LIMIT))
            stats["bronze"] += 1
            try:
                event = validate(dict(raw))
                if event["kind"] not in KINDS:
                    raise ValueError("unsupported kind")
                silver = {"id": event_id, "kind": event["kind"], "uid": event["uid"], "key": feature_key(event),
                          "process": str(event.get("process", ""))[:64], "source": event.get("source"),
                          "identity_quality": event.get("identity_quality"),
                          "hour": int(raw.get("received_ns", 0) // 3_600_000_000_000) if isinstance(raw.get("received_ns"), int) else None,
                          "incident": event_id in incident_events}
                silver["eligible"] = (silver["source"] == "kernel" and silver["identity_quality"] == "kernel_start_identity"
                                      and not silver["incident"])
            except (KeyError, ValueError, TypeError) as exc:
                writes.append(("quarantine", event_id, {"reason": type(exc).__name__, "detail": str(exc)[:256],
                                                        "quarantined": now}, False, LAYER_LIMIT))
                stats["quarantine"] += 1
                continue
            writes.append(("silver", event_id, silver, False, LAYER_LIMIT))
            stats["silver"] += 1
            if silver["eligible"]:
                accounts = counts.setdefault(str(silver["uid"]), {}) if (str(silver["uid"]) in counts or len(counts) < MAX_ACCOUNTS) else None
                if accounts is not None:
                    bucket = accounts.setdefault(silver["kind"], {})
                    if silver["key"] in bucket or len(bucket) < MAX_KEYS:
                        bucket[silver["key"]] = bucket.get(silver["key"], 0) + 1
                        stats["trained"] += 1
        if stats["trained"]:
            model.update(version=model["version"] + 1, trained_events=model["trained_events"] + stats["trained"],
                         window=[model["window"][0] or now, now], updated=now)
        status = {"updated": now, "last_cycle": stats, "model_version": model["version"],
                  "trained_events": model["trained_events"],
                  "ready": sorted(f"{uid}:{kind}" for uid, kinds in counts.items() for kind, b in kinds.items()
                                  if sum(b.values()) >= READY_EVENTS)}
        writes += [("gold", MODEL_ID, model, True, 10), ("gold", "status", status, True, 10)]
        prune = {layer: max(0, LAYER_LIMIT - n) for layer, n in
                 (("bronze", stats["bronze"]), ("silver", stats["silver"]), ("quarantine", stats["quarantine"])) if n}
        self.lake.write_batch(writes, prune=prune)
        return status


def main(argv=None):
    from operations.store import Store
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", default=str(Path.home() / ".linxai"))
    args = parser.parse_args(argv)
    state = Path(args.state)
    lake, security = Store(state / "lake.sqlite"), Store(state / "security.sqlite")
    try:
        print(json.dumps(Lake(lake, security).run_cycle(), indent=2))
    finally:
        lake.close()
        security.close()


if __name__ == "__main__":
    main()
