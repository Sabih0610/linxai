# cie/validator.py
# The Command Intelligence Engine — orchestrates all pre-execution checks.
#
# Receives the execution plan dict from the AI Engine.
# Reads the pre_conditions array.
# Tracks a validation budget; slow checks are rejected after returning.
# Returns a final decision: approve / block / warn.
#
# Evaluates declared checks for callers using the validation pipeline.
# Mandatory action checks and alternate execution paths still need consolidation.

import time
import logging
from typing import Dict, List, Any
from cie.checks import (
    check_port_free, check_port_occupied, check_port_range,
    check_service_exists, check_service_running,
    check_service_stopped, check_service_enabled,
    check_process_running, check_process_not_running, check_process_count,
    check_file_exists, check_file_not_exists,
    check_disk_space, check_path_writable,
    check_network_reachable, check_firewall_allows_port,
    check_memory_available, check_cpu_load,
    check_user_exists, check_running_as_root,
    check_package_installed,
    check_destructive_protected_path,
)

logger = logging.getLogger(__name__)

# Maps check type strings (from AI plan) to check functions
CHECK_REGISTRY = {
    "port_free":             check_port_free,
    "port_occupied":         check_port_occupied,
    "port_range":            check_port_range,
    "service_exists":        check_service_exists,
    "service_running":       check_service_running,
    "service_stopped":       check_service_stopped,
    "service_enabled":       check_service_enabled,
    "process_running":       check_process_running,
    "process_not_running":   check_process_not_running,
    "process_count":         check_process_count,
    "file_exists":           check_file_exists,
    "file_not_exists":       check_file_not_exists,
    "disk_space":            check_disk_space,
    "path_writable":         check_path_writable,
    "network_reachable":     check_network_reachable,
    "firewall_allows_port":  check_firewall_allows_port,
    "memory_available":      check_memory_available,
    "cpu_load":              check_cpu_load,
    "user_exists":           check_user_exists,
    "running_as_root":       check_running_as_root,
    "package_installed":     check_package_installed,
    "destructive_protected_path": check_destructive_protected_path,
}

# Status priority: conflict > error > warning > ok
STATUS_PRIORITY = {"conflict": 3, "error": 2, "warning": 1, "ok": 0}


def _extract_args(condition: dict) -> dict:
    """
    Extracts keyword arguments for a check function from the condition dict.
    Strips the 'check' key — everything else is passed as kwargs.
    """
    return {k: v for k, v in condition.items() if k != "check"}


def _check_error(check_type: str, reason: str) -> dict:
    return {"check": check_type, "status": "error", "found": None,
            "reason": reason, "detail": {}}


def _run_single_check(condition: dict) -> dict:
    """Reject malformed, unavailable and failed required checks."""
    if not isinstance(condition, dict):
        return _check_error("invalid_condition", "A precondition must be an object.")
    check_type = condition.get("check")
    if not isinstance(check_type, str) or not check_type.strip():
        return _check_error("invalid_condition", "A precondition needs a check name.")
    fn = CHECK_REGISTRY.get(check_type)
    if fn is None:
        return _check_error(check_type, f"Check type '{check_type}' is not registered.")
    try:
        result = fn(**_extract_args(condition))
        if not isinstance(result, dict):
            return _check_error(check_type, "Check returned an invalid result object.")
        if result.get("status") not in STATUS_PRIORITY:
            return _check_error(check_type, "Check returned an invalid status.")
        if not isinstance(result.get("reason"), str):
            return _check_error(check_type, "Check returned an invalid reason.")
        result = dict(result)
        result["check"] = check_type
        result.setdefault("found", None)
        result.setdefault("detail", {})
        return result
    except Exception as exc:
        logger.error("Check '%s' failed: %s", check_type, exc)
        return _check_error(check_type, f"Check '{check_type}' failed: {exc}")


class CommandIntelligenceEngine:
    """
    Pre-execution validation engine for LINxAI.

    Receives an AI-generated execution plan and runs all declared
    pre_conditions against live system state. Returns a validation
    result that the Execution Controller uses to decide whether to
    proceed, block, or warn the user.

    Usage:
        cie = CommandIntelligenceEngine()
        result = cie.validate(plan)

        if result["decision"] == "approve":
            executor.execute(plan)
        elif result["decision"] == "block":
            print(result["reason"])
        elif result["decision"] == "warn":
            # Show warning but allow user to proceed
            print(result["reason"])

    Decision logic:
        - Any "conflict" check → decision = "block"
        - Any "error" check   → decision = "block" (required state is unverified)
        - Any "warning" check → decision = "warn"
        - All "ok"            → decision = "approve"
    """

    def __init__(self, timeout_ms: int = 500):
        """
        Args:
            timeout_ms: maximum time to spend on ALL checks combined.
                        Default 500ms as per FYP proposal objective.
        """
        self.timeout_ms = timeout_ms
        logger.info(
            f"Command Intelligence Engine ready — "
            f"timeout={timeout_ms}ms, "
            f"registered checks: {len(CHECK_REGISTRY)}"
        )

    def validate(self, plan: dict) -> dict:
        """Run all declared checks; incomplete verification never approves.

        The budget is checked before and after each synchronous check. It does
        not interrupt an in-flight OS query. Operation-derived mandatory checks
        still need to be introduced by the future action registry.
        """
        t_start = time.perf_counter()
        results = []
        checks_run = 0

        def finish(decision, reason):
            return {"decision": decision, "reason": reason,
                    "checks_run": checks_run,
                    "duration_ms": int((time.perf_counter() - t_start) * 1000),
                    "results": results, "plan": plan}

        if not isinstance(plan, dict) or not isinstance(plan.get("command"), str):
            results.append(_check_error("invalid_plan", "Plan needs a string command."))
            return finish("block", "BLOCKED: Invalid execution plan.")
        pre_conditions = plan.get("pre_conditions", [])
        if not isinstance(pre_conditions, list) or len(pre_conditions) > 64:
            results.append(_check_error("invalid_plan", "Preconditions must be a list of at most 64 checks."))
            return finish("block", "BLOCKED: Invalid preconditions.")

        guard_result = _run_single_check({"check": "destructive_protected_path",
                                          "command": plan["command"]})
        if guard_result["status"] != "ok":
            results.append(guard_result)
            return finish("block", "BLOCKED: " + guard_result["reason"])

        if not pre_conditions:
            return finish("approve", "No pre-execution checks declared for this command.")

        for condition in pre_conditions:
            if (time.perf_counter() - t_start) * 1000 >= self.timeout_ms:
                results.append(_check_error("validation_timeout", "Required checks were not completed before the deadline."))
                break
            results.append(_run_single_check(condition))
            checks_run += 1
            if (time.perf_counter() - t_start) * 1000 >= self.timeout_ms:
                results.append(_check_error("validation_timeout", "A check exceeded the validation deadline."))
                break

        decision, reason = self._decide(results, plan)
        return finish(decision, reason)

    def _decide(self, results: List[dict], plan: dict) -> tuple:
        """
        Determines the final decision from all check results.

        Priority: conflict > error > warning > ok

        Returns (decision_str, reason_str).
        """
        if not results:
            return "block", "BLOCKED: No required checks ran."

        # Collect by status
        conflicts = [r for r in results if r["status"] == "conflict"]
        errors    = [r for r in results if r["status"] == "error"]
        warnings  = [r for r in results if r["status"] == "warning"]

        if conflicts:
            # Build a combined reason from all conflicts
            reasons = [r["reason"] for r in conflicts]
            combined = " | ".join(reasons)
            suggestion = self._suggest_alternative(conflicts, plan)
            full_reason = f"BLOCKED: {combined}"
            if suggestion:
                full_reason += f" | Suggestion: {suggestion}"
            return "block", full_reason

        if errors:
            reasons = [r["reason"] for r in errors]
            return "block", (
                "BLOCKED: Could not verify system state: "
                + " | ".join(reasons)
                + " — command will not execute."
            )

        if warnings:
            reasons = [r["reason"] for r in warnings]
            return "warn", "Warning: " + " | ".join(reasons)

        # All ok
        checks_summary = ", ".join(r["check"] for r in results)
        return "approve", f"All checks passed ({checks_summary})."

    def _suggest_alternative(self, conflicts: List[dict],
                              plan: dict) -> str:
        """
        Generates a specific actionable suggestion based on conflict type.
        This is what makes the CIE genuinely helpful, not just a blocker.
        """
        suggestions = []

        for conflict in conflicts:
            check = conflict.get("check", "")
            found = conflict.get("found", {})

            if check == "port_free" and isinstance(found, dict):
                pid = found.get("pid")
                name = found.get("name", "unknown")
                port = found.get("port")
                if pid:
                    suggestions.append(
                        f"Stop '{name}' (PID {pid}) with: kill {pid} "
                        f"or: systemctl stop {name}"
                    )

            elif check == "service_running":
                svc = found.get("service", "") if isinstance(found, dict) else ""
                if svc:
                    suggestions.append(f"Stop {svc} first: systemctl stop {svc}")

            elif check == "service_stopped":
                svc = found.get("service", "") if isinstance(found, dict) else ""
                if svc:
                    suggestions.append(f"Start {svc} first: systemctl start {svc}")

            elif check == "service_exists":
                intent = plan.get("target", "")
                if intent:
                    suggestions.append(
                        f"Install '{intent}' first: apt install {intent}"
                    )

            elif check == "disk_space":
                suggestions.append(
                    "Free disk space: sudo apt autoremove && sudo apt clean"
                )

            elif check == "process_running":
                proc = plan.get("target", "")
                if proc:
                    suggestions.append(
                        f"Start '{proc}' first: systemctl start {proc}"
                    )

        return " | ".join(suggestions) if suggestions else ""

    def validate_batch(self, plans: list) -> list:
        """
        Validates multiple plans at once.
        Used for pre-validating a sequence of commands.
        Returns list of validation results in same order as input.
        """
        return [self.validate(plan) for plan in plans]

    def check_one(self, check_type: str, **kwargs) -> dict:
        """
        Run a single check directly by name.
        Useful for ad-hoc system state queries from other modules.

        Example:
            cie.check_one("port_free", port=80)
            cie.check_one("service_running", service="nginx")
        """
        condition = {"check": check_type, **kwargs}
        return _run_single_check(condition)
