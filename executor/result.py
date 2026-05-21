# executor/result.py
# Defines the canonical execution result structure used across all of LINxAI.
# Every command execution — local, remote, or face-auth — returns this contract.
# This is the JSON schema that the AI context memory, audit logger, and
# Flask API all consume. Never change field names without updating all consumers.

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
import uuid


@dataclass
class ExecutionResult:
    """
    Canonical result object for every command execution in LINxAI.

    Fields:
        status:       "success" | "error" | "timeout" | "blocked" | "auth_failed"
        return_code:  integer exit code from subprocess (0 = success)
        stdout:       captured standard output, stripped
        stderr:       captured standard error, stripped
        command:      the exact bash string that was issued
        intent:       the AI-classified intent that triggered this command
        duration_ms:  wall-clock time from exec start to result capture
        timestamp:    ISO 8601 UTC timestamp of execution
        session_id:   links this result to an AI context memory session
        exec_id:      unique ID for this specific execution event
        requires_sudo: whether the command ran with elevated privileges
        auth_method:  "none" | "password" | "face" — how sudo was authenticated
        plan:         the full AI plan dict that led to this execution
    """
    status:        str
    return_code:   int
    stdout:        str
    stderr:        str
    command:       str
    intent:        str
    duration_ms:   int
    timestamp:     str        = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id:    str        = field(default_factory=lambda: "")
    exec_id:       str        = field(default_factory=lambda: str(uuid.uuid4()))
    requires_sudo: bool       = False
    auth_method:   str        = "none"
    plan:          dict       = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Returns a plain dict — safe for JSON serialisation."""
        return asdict(self)

    def is_success(self) -> bool:
        return self.status == "success" and self.return_code == 0

    def summary(self) -> str:
        """One-line human-readable summary for terminal display."""
        icon = "✓" if self.is_success() else "✗"
        return (
            f"[{icon}] {self.intent} → {self.status} "
            f"(exit {self.return_code}, {self.duration_ms}ms)"
        )


def make_blocked_result(intent: str, command: str,
                         reason: str, plan: dict = None) -> ExecutionResult:
    """Creates a result representing a CIE-blocked command."""
    return ExecutionResult(
        status="blocked",
        return_code=-1,
        stdout="",
        stderr=reason,
        command=command,
        intent=intent,
        duration_ms=0,
        plan=plan or {},
    )


def make_auth_failed_result(intent: str, command: str,
                             plan: dict = None) -> ExecutionResult:
    """Creates a result representing a failed face authentication."""
    return ExecutionResult(
        status="auth_failed",
        return_code=-2,
        stdout="",
        stderr="Face authentication failed — sudo operation denied.",
        command=command,
        intent=intent,
        duration_ms=0,
        requires_sudo=True,
        auth_method="face",
        plan=plan or {},
    )


def make_timeout_result(intent: str, command: str,
                         timeout_s: int, plan: dict = None) -> ExecutionResult:
    """Creates a result representing a timed-out command."""
    return ExecutionResult(
        status="timeout",
        return_code=-3,
        stdout="",
        stderr=f"Command timed out after {timeout_s} seconds.",
        command=command,
        intent=intent,
        duration_ms=timeout_s * 1000,
        plan=plan or {},
    )