"""Security-aware preview warnings (original requirement 41).

Recent incidents from the independent monitor are attached to new previews as
advisory context. Warnings are untrusted evidence rendered as bounded data:
they never block, approve, change privilege, enter the approval digest or reach
the model as instructions.
"""
import time

WINDOW_S = 1800          # incidents from the last 30 minutes
MAX_WARNINGS = 5
_NETWORK_ACTIONS = frozenset({"ports.listen", "service.start", "service.restart", "remote.operation",
                              "response.network.block"})
_WORKSPACE_ACTIONS = frozenset({"file.create", "directory.create", "environment.python", "project.scaffold", "project.node"})
_RELATED = {
    "unusual_connection_attempt": _NETWORK_ACTIONS,
    "temporary_executable_attempt": _WORKSPACE_ACTIONS | {"service.start", "service.restart"},
    "sensitive_file_attempt": frozenset({"service.start", "service.stop", "service.restart",
                                         "auth.face.enroll", "auth.face.revoke"}),
}


def _target(evidence):
    target = evidence.get("target") if isinstance(evidence, dict) else None
    if not isinstance(target, dict):
        return ""
    if "path" in target:
        return str(target["path"])[:256]
    if "address" in target:
        return f"{str(target['address'])[:64]}:{int(target.get('port', 0))}"
    return ""


def preview_warnings(incidents, *, action, privilege, now=None):
    """Return bounded advisory warnings for incidents within WINDOW_S, newest first."""
    now = time.time() if now is None else now
    recent = []
    for incident in incidents or ():
        try:
            created = float(incident["created"])
            rule = str(incident["rule"])[:64]
        except (KeyError, TypeError, ValueError):
            continue
        age = now - created
        if not 0 <= age <= WINDOW_S:
            continue
        recent.append((created, rule, incident))
    recent.sort(key=lambda item: item[0], reverse=True)
    warnings = []
    for created, rule, incident in recent[:MAX_WARNINGS]:
        evidence = incident.get("evidence", {})
        related = action in _RELATED.get(rule, frozenset())
        if privilege == "authenticated_admin":
            message = "Recent security incident on this host; review it before authorizing this privileged operation."
        elif related:
            message = "This operation is related to a recent security incident; review the evidence first."
        else:
            message = "A security incident was recorded recently on this host."
        warnings.append({"incident_id": str(incident.get("id", ""))[:64], "rule": rule,
                         "severity": str(incident.get("severity", "warning"))[:16],
                         "age_s": int(now - created), "target": _target(evidence),
                         "uid": evidence.get("uid") if isinstance(evidence, dict) and type(evidence.get("uid")) is int else None,
                         "related_to_action": related, "message": message,
                         "interpretation": "Advisory evidence only; it does not block or authorize this preview."})
    return warnings
