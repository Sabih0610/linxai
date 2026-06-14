# cie/validator.py
# The Command Intelligence Engine — orchestrates all pre-execution checks.
#
# Receives the execution plan dict from the AI Engine.
# Reads the pre_conditions array.
# Runs every check in under 500ms total.
# Returns a final decision: approve / block / warn.
#
# This is the module that makes LINxAI different from every other tool.
# Nothing executes until this says approve.

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
    "service_exists":        check_service_exists,
    "service_running":       check_service_running,
    "service_stopped":       check_service_stopped,
    "service_enabled":       check_service_enabled,
    "process_running":       check_process_running,
    "process_not_running":   check_process_not_running,
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

# Status priority: conflict > warning > error > ok
STATUS_PRIORITY = {"conflict": 3, "warning": 2, "error": 1, "ok": 0}


def _extract_args(condition: dict) -> dict:
    """
    Extracts keyword arguments for a check function from the condition dict.
    Strips the 'check' key — everything else is passed as kwargs.
    """
    return {k: v for k, v in condition.items() if k != "check"}


def _run_single_check(condition: dict) -> dict:
    """
    Dispatches one pre_condition dict to the correct check function.
    Returns the check result dict.

    If the check type is unknown or fails to run, returns an error result.
    """
    check_type = condition.get("check", "")
    fn = CHECK_REGISTRY.get(check_type)

    if fn is None:
        logger.warning(f"Unknown check type: '{check_type}' — skipping")
        return {
            "check": check_type,
            "status": "ok",  # Unknown checks do not block — log only
            "found": None,
            "reason": f"Check type '{check_type}' is not registered — skipped.",
            "detail": {}
        }

    kwargs = _extract_args(condition)
    try:
        result = fn(**kwargs)
        return result
    except TypeError as e:
        logger.error(f"Check '{check_type}' called with wrong args {kwargs}: {e}")
        return {
            "check": check_type,
            "status": "error",
            "found": None,
            "reason": f"Check '{check_type}' configuration error: {e}",
            "detail": {"condition": condition, "error": str(e)}
        }
    except Exception as e:
        logger.error(f"Check '{check_type}' raised unexpected error: {e}")
        return {
            "check": check_type,
            "status": "error",
            "found": None,
            "reason": f"Check '{check_type}' failed unexpectedly: {e}",
            "detail": {"error": str(e)}
        }


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
        - Any "error" check   → decision = "warn"  (system read error, not command error)
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
        """
        Main validation entry point.

        Args:
            plan: execution plan dict from AIEngine.classify()
                  Must contain at minimum: intent, command
                  pre_conditions is optional — empty list = no checks needed

        Returns:
            {
                "decision":    "approve" | "block" | "warn"
                "reason":      str — human-readable explanation
                "checks_run":  int — number of checks executed
                "duration_ms": int — total time taken
                "results":     list — all individual check results
                "plan":        dict — the original plan unchanged
            }
        """
        t_start = time.perf_counter()

        pre_conditions = plan.get("pre_conditions", [])
        intent = plan.get("intent", "unknown")
        command = plan.get("command", "")

        logger.info(
            f"CIE validating: intent='{intent}', "
            f"command='{command}', "
            f"checks={len(pre_conditions)}"
        )

        guard_result = check_destructive_protected_path(command)
        if guard_result["status"] == "conflict":
            duration_ms = int((time.perf_counter() - t_start) * 1000)
            logger.warning(
                f"CIE blocked destructive protected-path command: {command}"
            )
            return {
                "decision":    "block",
                "reason":      guard_result["reason"],
                "checks_run":  1,
                "duration_ms": duration_ms,
                "results":     [guard_result],
                "plan":        plan,
            }

        # No pre-conditions = always approve
        if not pre_conditions:
            duration_ms = int((time.perf_counter() - t_start) * 1000)
            logger.info(f"CIE: no checks required → approve ({duration_ms}ms)")
            return {
                "decision":    "approve",
                "reason":      "No pre-execution checks required for this command.",
                "checks_run":  0,
                "duration_ms": duration_ms,
                "results":     [],
                "plan":        plan,
            }

        # Run all checks
        results = []
        for condition in pre_conditions:
            elapsed_ms = int((time.perf_counter() - t_start) * 1000)
            if elapsed_ms >= self.timeout_ms:
                logger.warning(
                    f"CIE timeout after {elapsed_ms}ms — "
                    f"{len(results)}/{len(pre_conditions)} checks completed"
                )
                break

            result = _run_single_check(condition)
            results.append(result)
            logger.debug(
                f"  Check '{result['check']}': {result['status']} — {result['reason']}"
            )

        duration_ms = int((time.perf_counter() - t_start) * 1000)

        # Determine final decision
        decision, reason = self._decide(results, plan)

        logger.info(
            f"CIE decision: {decision.upper()} — "
            f"{len(results)} checks in {duration_ms}ms"
        )

        return {
            "decision":    decision,
            "reason":      reason,
            "checks_run":  len(results),
            "duration_ms": duration_ms,
            "results":     results,
            "plan":        plan,
        }

    def _decide(self, results: List[dict], plan: dict) -> tuple:
        """
        Determines the final decision from all check results.

        Priority: conflict > error > warning > ok

        Returns (decision_str, reason_str).
        """
        if not results:
            return "approve", "No checks ran."

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
            return "warn", (
                "Could not verify system state: "
                + " | ".join(reasons)
                + " — proceeding with caution."
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
