"""Log viewer and plain-English explain mode (original requirements 61 and 62).

Explanations are deterministic templates over recorded facts (job rows, the
correlated operation audit ledger, incidents and anomalies). No model is used, so
an explanation cannot invent an outcome that was not recorded.
"""
import json
import os
from pathlib import Path

TAIL_BYTES = 262144
MAX_RECORDS = 200


def tail_jsonl(path, limit=50, operation_id=None):
    """Last `limit` parseable records of a JSONL ledger, newest last."""
    path = Path(path)
    if not path.exists():
        return []
    with path.open("rb") as stream:
        size = stream.seek(0, os.SEEK_END)
        stream.seek(max(0, size - TAIL_BYTES))
        lines = stream.read().splitlines()
    if size > TAIL_BYTES:
        lines = lines[1:]                      # first line may be partial
    records = []
    for line in lines:
        try:
            record = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(record, dict) and (operation_id is None or record.get("operation_id") == operation_id):
            records.append(record)
    return records[-max(1, min(int(limit), MAX_RECORDS)):]


def _target(parameters):
    for key in ("service", "path", "asset", "policy_id"):
        if key in parameters:
            return f"{key} {parameters[key]}"
    if "pid" in parameters:
        return f"process {parameters['pid']} (start {parameters.get('start_ticks')})"
    if "port" in parameters and parameters["port"] is not None:
        return f"port {parameters['port']}"
    return "this machine"


def explain_job(row, audit=()):
    request = row.get("request", {})
    action, parameters = request.get("action", "unknown"), request.get("parameters", {})
    lines = []
    if row.get("text"):
        lines.append(f"You asked: \"{row['text'][:200]}\".")
    lines.append(f"LINxAI interpreted this as the typed action {action} on {_target(parameters)}.")
    lines.append("It required your administrator authorization through the protected broker."
                 if row.get("privilege") == "authenticated_admin" else "It ran with your ordinary account permissions.")
    warnings = row.get("security_warnings") or []
    if warnings:
        lines.append(f"The preview carried {len(warnings)} recent security warning(s), first: {warnings[0].get('rule')} on {warnings[0].get('target')}.")
    failed = [r for r in audit if r.get("status") == "failed"]
    passed = [r for r in audit if r.get("phase") == "validation" and r.get("status") == "passed"]
    if passed:
        lines.append(f"{len(passed)} mandatory pre-execution check(s) passed.")
    for record in failed[:3]:
        detail = record.get("details", {})
        lines.append(f"The {record.get('phase')} step failed on {detail.get('requirement', 'a requirement')}: {str(detail.get('reason', ''))[:160]}.")
    state = row.get("state", "unknown")
    result = row.get("result") or {}
    if state == "succeeded":
        lines.append("The operation finished and its postconditions were verified." if result.get("verified")
                     else "The operation finished but verification was not recorded.")
    elif state in {"preview", "queued", "validating", "approved", "dispatching"}:
        lines.append(f"The job is still {state}; nothing final has been recorded yet.")
    elif state == "unknown":
        lines.append("The agent restarted while this operation may have been running; LINxAI does not retry it automatically. Check the current state before acting.")
    else:
        lines.append(f"The job ended as {state}" + (f": {str(result.get('reason'))[:200]}." if result.get("reason") else "."))
    if result.get("restoration"):
        lines.append(f"A validated restoration ({result['restoration'].get('action')}) is available for review; it needs its own preview and confirmation.")
    return lines


def explain_incident(incident):
    evidence = incident.get("evidence", {})
    target = evidence.get("target", {})
    what = target.get("path") or f"{target.get('address')}:{target.get('port')}"
    lines = [f"The independent monitor raised {incident.get('rule')} ({incident.get('severity')}) for account {evidence.get('uid')}, "
             f"process {evidence.get('process') or evidence.get('pid')} touching {what}.",
             "This came from a deterministic rule on kernel evidence. It shows an attempt, not proof of harm: the syscall outcome is unknown."]
    response = incident.get("response", "none")
    lines.append("No response has been taken." if response == "none" else f"Response state: {response}.")
    return lines


def explain_anomaly(anomaly):
    return [f"The learned baseline marked {anomaly.get('key')} as new behaviour for account {anomaly.get('uid')} "
            f"({anomaly.get('score_bits')} bits over {anomaly.get('baseline_events')} trained events).",
            "This is advisory: it is not an incident and cannot trigger any response or approval."]
