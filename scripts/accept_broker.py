"""Explicit real target service acceptance, never routine tests or provisioning."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main():
    if os.environ.get("LINXAI_TEST_BROKER_LAB") != "1":
        print("PENDING: opt in with LINXAI_TEST_BROKER_LAB=1 on the prepared isolated target")
        return 3
    from operations.broker import BrokerClient
    from operations.registry import normalize_service
    from operations.supervised import SupervisedLinuxAdapter
    system = SupervisedLinuxAdapter()
    if not system.resolve_identity().ordinary():
        raise PermissionError("Run lab client as ordinary owner")
    service = normalize_service("linxai-lab-acceptance")
    prior = system._service_properties(str(uuid4()), service)
    if prior.get("LoadState") != "loaded" or prior.get("ActiveState") not in {"active", "inactive"}:
        raise ValueError("Prepared stable lab fixture required")
    client, results = BrokerClient(), []
    try:
        for action in ("service.start", "service.restart", "service.stop"):
            value = client.run({"action": action, "parameters": {"service": service}})
            results.append(asdict(value))
            if value.status != "succeeded" or not value.verified:
                raise RuntimeError("Target authorization/dispatch acceptance pending or failed")
    finally:
        # Prior state exists and only a validated, allowlisted broker action restores it.
        restore = client.run({"action": "service.start" if prior["ActiveState"] == "active" else "service.stop",
                              "parameters": {"service": service}})
        Path("broker-acceptance.json").write_text(json.dumps({"prior": prior, "results": results, "restoration": asdict(restore)}, indent=2) + "\n")
    return 0 if restore.status == "succeeded" else 1


if __name__ == "__main__":
    raise SystemExit(main())
