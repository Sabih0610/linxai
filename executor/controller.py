# executor/controller.py
# System Execution Controller for LINxAI.
#
# Receives a validated AI execution plan from the CIE.
# Handles:
#   - subprocess execution with stdout/stderr capture
#   - 30-second timeout guard
#   - sudo escalation with face authentication gate
#   - structured ExecutionResult output
#   - rollback execution on failure (if plan provides one)
#
# The complete pipeline is:
#   AIEngine → CIE → ExecutionController → ExecutionResult
#
# This module NEVER receives a plan directly from the user.
# It only executes plans that CIE has already approved.

import os
import time
import shlex
import signal
import logging
import subprocess
import sys
import threading
import queue
from typing import Optional

from executor.command_builder import build as build_command
from executor.result import (
    ExecutionResult,
    make_blocked_result,
    make_auth_failed_result,
)
from system.destructive_guard import check_destructive_command

logger = logging.getLogger(__name__)

# Commands that must NEVER be executed regardless of what the AI says.
# This is a hard safety list — belt-and-suspenders after CIE approval.
FORBIDDEN_COMMANDS = {
    ":(){ :|:& };:",   # fork bomb
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "init 0",
    "init 6",
}

COMMAND_TIMEOUT_S = 30   # maximum seconds any single command may run
TIMEOUTS = {
    "package_install": 1200,
    "package_remove": 600,
    "package_update": 1200,
    "env_setup": 1800,
    "default": 30,
}
LONG_RUNNING_INTENTS = {"package_install", "package_remove", "package_update", "env_setup"}
QUERY_PARTIAL_SUCCESS_INTENTS = {"file_find", "grep", "diff"}


class ExecutionController:
    """
    Executes validated AI-generated system commands.

    Usage:
        controller = ExecutionController(use_face_auth=True)
        result = controller.execute(plan)

        if result.is_success():
            print(result.stdout)
        else:
            print(result.stderr)
    """

    def __init__(self,
                 use_face_auth: bool = True,
                 timeout_s: int = COMMAND_TIMEOUT_S,
                 face_auth_server_required: bool = False):
        """
        Args:
            use_face_auth: if True, sudo commands require face authentication.
                           if False, sudo runs without extra auth gate (dev mode).
            timeout_s: maximum seconds a command may run before being killed.
            face_auth_server_required: if True, missing face auth server = hard fail.
                                       if False (default), falls back to password sudo.
        """
        self.use_face_auth = use_face_auth
        self.timeout_s = timeout_s
        self.face_auth_server_required = face_auth_server_required

        logger.info(
            f"ExecutionController ready — "
            f"face_auth={use_face_auth}, timeout={timeout_s}s"
        )

    def _is_forbidden(self, command: str) -> bool:
        """
        Hard safety check — rejects commands that must never run.
        This runs even if CIE approved the command.
        """
        return self._forbidden_reason(command) is not None

    def _forbidden_reason(self, command: str) -> str | None:
        """
        Returns the reason a command is forbidden, or None if it is allowed.
        """
        finding = check_destructive_command(command)
        if finding:
            logger.critical(
                f"FORBIDDEN COMMAND intercepted: '{command}' "
                f"targets protected path '{finding['path']}'"
            )
            return finding["reason"]

        cmd_lower = command.lower().strip()
        for forbidden in FORBIDDEN_COMMANDS:
            if forbidden in cmd_lower:
                logger.critical(
                    f"FORBIDDEN COMMAND intercepted: '{command}' "
                    f"matches pattern '{forbidden}'"
                )
                return (
                    f"Command '{command}' is in the forbidden list and "
                    f"was intercepted by the safety guard."
                )
        return None

    def _build_command(self, plan: dict) -> str:
        """
        Constructs the final shell command string from the plan.
        Prepends sudo if requires_sudo=True and face auth passed.
        """
        command = plan.get("command", "").strip()
        requires_sudo = plan.get("requires_sudo", False)

        if requires_sudo and not command.startswith("sudo "):
            command = "sudo " + command

        return command

    def _authenticate_sudo(self, plan: dict) -> tuple:
        """
        Handles sudo authentication via face auth server.

        Returns (authenticated: bool, auth_method: str, reason: str)
        """
        if not self.use_face_auth:
            return True, "none", "Face auth disabled in dev mode."

        # Try face auth server
        try:
            from executor.face_auth import request_face_auth
            success, reason = request_face_auth(timeout_s=12.0)

            if success:
                return True, "face", reason
            else:
                logger.warning(f"Face auth failed: {reason}")

                if self.face_auth_server_required:
                    return False, "face", reason

                # Graceful fallback — log warning, allow password sudo
                logger.info(
                    "Face auth failed — falling back to password sudo. "
                    "This is acceptable in dev/VM mode."
                )
                return True, "password_fallback", (
                    f"Face auth unavailable ({reason}) — "
                    f"falling back to standard sudo."
                )

        except Exception as e:
            logger.error(f"Face auth exception: {e}")

            if self.face_auth_server_required:
                return False, "face", str(e)

            return True, "password_fallback", (
                f"Face auth server error — falling back to sudo."
            )

    def _intent_timeout(self, intent: str, command: str = "") -> int:
        timeout = TIMEOUTS.get(intent, TIMEOUTS["default"])
        if timeout == TIMEOUTS["default"] and "git clone" in command.lower():
            return TIMEOUTS["env_setup"]
        return timeout

    def _is_long_running(self, intent: str, command: str) -> bool:
        if intent in LONG_RUNNING_INTENTS:
            return True
        lowered = command.lower()
        return (
            "git clone" in lowered
            or "apt install" in lowered
            or "apt-get install" in lowered
            or "apt update" in lowered
            or "apt-get update" in lowered
        )

    def _progress_notice(self, intent: str, command: str):
        if not self._is_long_running(intent, command):
            return
        print(
            "This may take several minutes (downloading/installing). "
            "Please wait…",
            flush=True,
        )

    def _reader_thread(self, stream, name: str, output_queue):
        try:
            for line in iter(stream.readline, ""):
                output_queue.put((name, line))
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def _capture_output_line(self, name: str, line: str, stdout_lines: list,
                             stderr_lines: list, echo: bool):
        if name == "stdout":
            stdout_lines.append(line)
        else:
            stderr_lines.append(line)
        if echo:
            stream = sys.stderr if name == "stderr" else sys.stdout
            print(line, end="", file=stream, flush=True)

    def _drain_output_queue(self, output_queue, stdout_lines: list,
                            stderr_lines: list, echo: bool):
        while True:
            try:
                name, line = output_queue.get_nowait()
            except queue.Empty:
                break
            self._capture_output_line(
                name, line, stdout_lines, stderr_lines, echo
            )

    def _recover_package_timeout_hint(self, intent: str, message: str) -> str:
        if intent in {"package_install", "package_remove", "package_update"}:
            return (
                f"{message} Package operations can leave dpkg half-configured; "
                f"run `sudo dpkg --configure -a` before retrying."
            )
        return message

    def _run_subprocess(self, command: str, intent: str,
                         plan: dict, auth_method: str,
                         timeout_s: int) -> ExecutionResult:
        """
        Executes the command string as a subprocess.
        Captures stdout, stderr, return code, and duration.
        Kills the process if it exceeds timeout_s.
        """
        t_start = time.perf_counter()
        self._progress_notice(intent, command)

        try:
            popen_kwargs = {
                "shell": True,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
            }
            if hasattr(os, "setsid"):
                # Linux/POSIX: create a process group for clean timeout kills.
                popen_kwargs["preexec_fn"] = os.setsid
            proc = subprocess.Popen(command, **popen_kwargs)

            stdout_lines = []
            stderr_lines = []
            output_queue = queue.Queue()
            threads = [
                threading.Thread(
                    target=self._reader_thread,
                    args=(proc.stdout, "stdout", output_queue),
                    daemon=True,
                ),
                threading.Thread(
                    target=self._reader_thread,
                    args=(proc.stderr, "stderr", output_queue),
                    daemon=True,
                ),
            ]
            for thread in threads:
                thread.start()

            timed_out = False
            echo_output = self._is_long_running(intent, command)
            while True:
                try:
                    name, line = output_queue.get(timeout=0.1)
                    self._capture_output_line(
                        name, line, stdout_lines, stderr_lines, echo_output
                    )
                except queue.Empty:
                    pass

                if proc.poll() is not None:
                    break
                if time.perf_counter() - t_start > timeout_s:
                    timed_out = True
                    break

            self._drain_output_queue(
                output_queue, stdout_lines, stderr_lines, echo_output
            )

            if timed_out:
                if intent in {"package_install", "package_remove", "package_update"}:
                    try:
                        proc.terminate()
                    except ProcessLookupError:
                        pass
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        pass
                else:
                    self._kill_process(proc)
                    proc.wait()
                for thread in threads:
                    thread.join(timeout=1)
                self._drain_output_queue(
                    output_queue, stdout_lines, stderr_lines, echo_output
                )

                duration_ms = int((time.perf_counter() - t_start) * 1000)
                message = f"Command timed out after {timeout_s} seconds."
                message = self._recover_package_timeout_hint(intent, message)
                logger.error(f"{message} Command: '{command}'")
                return ExecutionResult(
                    status="timeout",
                    return_code=-3,
                    stdout="".join(stdout_lines).strip(),
                    stderr=message,
                    command=command,
                    intent=intent,
                    duration_ms=duration_ms,
                    requires_sudo=plan.get("requires_sudo", False),
                    auth_method=auth_method,
                    plan=plan,
                )

            for thread in threads:
                thread.join(timeout=1)
            self._drain_output_queue(
                output_queue, stdout_lines, stderr_lines, echo_output
            )

            stdout = "".join(stdout_lines)
            stderr = "".join(stderr_lines)
            duration_ms = int((time.perf_counter() - t_start) * 1000)

            try:
                status = "success" if proc.returncode == 0 else "error"
                return_code = proc.returncode
                if intent in QUERY_PARTIAL_SUCCESS_INTENTS and proc.returncode == 1:
                    status = "success"
                    return_code = 0
                    note = "No results or partial results."
                    stderr = f"{stderr.strip()}\n{note}".strip()

                logger.info(
                    f"Executed: '{command}' → "
                    f"exit={proc.returncode}, {duration_ms}ms"
                )

                return ExecutionResult(
                    status=status,
                    return_code=return_code,
                    stdout=stdout.strip(),
                    stderr=stderr.strip(),
                    command=command,
                    intent=intent,
                    duration_ms=duration_ms,
                    requires_sudo=plan.get("requires_sudo", False),
                    auth_method=auth_method,
                    plan=plan,
                )

            except Exception as e:
                duration_ms = int((time.perf_counter() - t_start) * 1000)
                logger.error(f"Subprocess result error for '{command}': {e}")
                return ExecutionResult(
                    status="error",
                    return_code=-99,
                    stdout="".join(stdout_lines).strip(),
                    stderr=str(e),
                    command=command,
                    intent=intent,
                    duration_ms=duration_ms,
                    plan=plan,
                )

        except Exception as e:
            duration_ms = int((time.perf_counter() - t_start) * 1000)
            logger.error(f"Subprocess error for '{command}': {e}")
            return ExecutionResult(
                status="error",
                return_code=-99,
                stdout="",
                stderr=str(e),
                command=command,
                intent=intent,
                duration_ms=duration_ms,
                plan=plan,
            )

    def _kill_process(self, proc):
        try:
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except ProcessLookupError:
            pass
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _execute_rollback(self, plan: dict):
        """
        Runs the rollback command if a command failed and a rollback exists.
        Rollback errors are logged but never raised — best effort only.
        """
        rollback = plan.get("rollback", "").strip()
        if not rollback:
            return

        logger.warning(f"Executing rollback: '{rollback}'")
        try:
            result = subprocess.run(
                rollback,
                shell=True,
                capture_output=True,
                text=True,
                timeout=15
            )
            if result.returncode == 0:
                logger.info(f"Rollback succeeded: '{rollback}'")
            else:
                logger.error(
                    f"Rollback failed (exit {result.returncode}): "
                    f"{result.stderr.strip()}"
                )
        except Exception as e:
            logger.error(f"Rollback exception for '{rollback}': {e}")

    def execute(self, plan: dict) -> ExecutionResult:
        """
        Main execution entry point.

        Args:
            plan: validated execution plan from AIEngine + approved by CIE.
                  Must contain: intent, command, requires_sudo, rollback.

        Returns:
            ExecutionResult with status, stdout, stderr, duration_ms, etc.
        """
        intent  = plan.get("intent", "unknown")
        command = build_command(intent, plan).strip()
        if command:
            plan["command"] = command
        requires_sudo = plan.get("requires_sudo", False)

        if command.startswith("df -h") and "--exclude-type" not in command:
            command = command + " --exclude-type=fuse.sshfs"
            plan["command"] = command

        if not command:
            return ExecutionResult(
                status="error",
                return_code=-1,
                stdout="",
                stderr="No command in execution plan.",
                command="",
                intent=intent,
                duration_ms=0,
                plan=plan,
            )

        # Hard safety check — even after CIE approval
        forbidden_reason = self._forbidden_reason(command)
        if forbidden_reason:
            return make_blocked_result(
                intent, command,
                forbidden_reason,
                plan
            )

        # Face authentication gate for sudo commands
        auth_method = "none"
        if requires_sudo:
            authenticated, auth_method, auth_reason = self._authenticate_sudo(plan)
            if not authenticated:
                logger.warning(
                    f"Sudo command blocked by face auth: "
                    f"'{command}' — {auth_reason}"
                )
                return make_auth_failed_result(intent, command, plan)

            if auth_method != "none":
                logger.info(f"Sudo auth method: {auth_method} — {auth_reason}")

        # Build final command string
        final_command = self._build_command(plan)

        timeout_s = self._intent_timeout(intent, final_command)

        logger.info(
            f"Executing: intent='{intent}', "
            f"command='{final_command}', "
            f"sudo={requires_sudo}, auth={auth_method}"
        )

        # Run the command
        result = self._run_subprocess(
            final_command,
            intent,
            plan,
            auth_method,
            timeout_s,
        )

        # Rollback on error for medium/high risk commands
        risk = plan.get("risk_level", "low")
        if not result.is_success() and risk in ("medium", "high"):
            self._execute_rollback(plan)

        return result

    def execute_raw(self, command: str, intent: str = "raw",
                    requires_sudo: bool = False) -> ExecutionResult:
        """
        Executes a raw command string without a full plan dict.
        Used for quick ad-hoc commands from other modules (resource manager, etc.)

        Args:
            command: bash command string
            intent: label for logging
            requires_sudo: whether to prepend sudo

        Returns:
            ExecutionResult
        """
        plan = {
            "intent": intent,
            "command": command,
            "requires_sudo": requires_sudo,
            "risk_level": "low",
            "rollback": "",
            "pre_conditions": [],
        }
        return self.execute(plan)
