"""Ordinary-user typed CLI. Every selected request terminates in this service."""
import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path

from .audit import JsonlAudit
from .registry import ActionRegistry
from .service import LocalPolicy, OperationResult, OperationService
from uuid import uuid4
from .system import LinuxSystemAdapter


def build_service(workspace=None, audit_path=None):
    system = LinuxSystemAdapter()
    uid = os.getuid() if hasattr(os, "getuid") else -1
    ledger = audit_path or str(Path.home() / ".linxai" / "operations.jsonl")
    return OperationService(ActionRegistry(workspace), system, LocalPolicy(uid), JsonlAudit(ledger))


def run_request(action, parameters_json="{}", workspace=None, audit_path=None, *, service_factory=build_service):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON parameter key")
            result[key] = value
        return result
    try:
        parameters = json.loads(parameters_json, object_pairs_hook=unique_object)
    except (TypeError, ValueError):
        parameters = None  # The service records a correlated invalid-request result.
    try:
        service = service_factory(workspace, audit_path)
        result = service.run({"action": action, "parameters": parameters})
    except Exception as exc:
        result = OperationResult(str(uuid4()), "configuration_failed", str(exc), audit_complete=False)
    print(json.dumps(asdict(result), sort_keys=True))
    return 0 if result.status == "succeeded" else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description="LINxAI typed operations (ordinary Linux user)")
    parser.add_argument("action", nargs="?")
    parser.add_argument("--ask", help="Natural-language preview through the running agent; never executes without --confirm")
    parser.add_argument("--confirm", metavar="PREVIEW_ID")
    parser.add_argument("--digest", help="Exact digest returned by preview")
    parser.add_argument("--jobs", action="store_true")
    parser.add_argument("--parameters", default="{}", help="JSON parameter object; no command/identity/approval fields")
    parser.add_argument("--workspace", help="Explicit permitted POSIX workspace for create actions")
    parser.add_argument("--audit-path", help="JSONL path in an owned private directory")
    args = parser.parse_args(argv)
    # Installed entry points refuse elevated startup before opening a user ledger.
    try:
        identity = LinuxSystemAdapter().resolve_identity()
        if not identity.ordinary():
            raise PermissionError("Run as an ordinary Linux account without sudo/root/set-ID")
    except Exception as exc:
        result = OperationResult(str(uuid4()), "identity_denied", str(exc), audit_complete=False)
        print(json.dumps(asdict(result), sort_keys=True))
        return 2
    selected = sum((bool(args.action), args.ask is not None, args.confirm is not None, args.jobs))
    if selected != 1:
        parser.error("Select exactly one action, --ask, --confirm or --jobs")
    if args.ask is not None or args.confirm is not None or args.jobs:
        from .agent import AgentClient
        client = AgentClient()
        try:
            value = (client.call("preview", text=args.ask) if args.ask is not None else
                     client.call("confirm", id=args.confirm, digest=args.digest) if args.confirm else client.call("jobs"))
            print(json.dumps(value, sort_keys=True))
            return 0
        except Exception as exc:
            print(json.dumps({"status": "agent_request_failed", "reason": str(exc)[:512]}))
            return 2
    return run_request(args.action, args.parameters, args.workspace, args.audit_path)


if __name__ == "__main__":
    raise SystemExit(main())
