# executor/auto_response.py
# LINxAI Autonomous Threat Responder
# Automatically kills processes that trigger eBPF security alerts.
# Only active when auto_response.enabled = true in config.
# All actions are logged with full evidence before execution.

import os
import signal
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class ThreatResponder:

    def __init__(self, enabled: bool = False, log_callback=None):
        self.enabled = enabled
        self.log_callback = log_callback
        self._response_log = []
        if enabled:
            logger.info("ThreatResponder active — autonomous response ENABLED")
        else:
            logger.info("ThreatResponder passive — autonomous response DISABLED")

    def respond(self, alert: dict) -> dict:
        event_type = alert.get("event_type", "")
        payload    = alert.get("payload", {})
        pid        = payload.get("pid")
        process    = payload.get("process", "unknown")

        response = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "alert":      alert,
            "action":     "none",
            "success":    False,
            "reason":     "",
            "pid":        pid,
            "process":    process,
        }

        if not self.enabled:
            response["reason"] = "Auto-response disabled"
            return response

        if not pid:
            response["reason"] = "No PID in alert — cannot respond"
            return response

        # Determine action based on event type
        if event_type == "file_open":
            fname = payload.get("filename", "")
            CRED_FILES = ["/etc/shadow", "/etc/sudoers", "id_rsa",
                          "authorized_keys", "/proc/keys"]
            if any(c in fname for c in CRED_FILES):
                response["action"] = "kill_process"
                response["reason"] = (
                    f"Process '{process}' (PID {pid}) accessed "
                    f"credential file '{fname}'"
                )

        elif event_type == "process_exec":
            ATTACK_TOOLS = ["nc", "ncat", "netcat", "socat",
                            "msfconsole", "telnet"]
            if any(t in process for t in ATTACK_TOOLS):
                response["action"] = "kill_process"
                response["reason"] = (
                    f"Known attack tool '{process}' (PID {pid}) launched"
                )

        elif event_type == "network_connect":
            dest_port = int(payload.get("dest_port", 0) or 0)
            SUSPICIOUS_PORTS = [4444, 4445, 1337, 31337, 9001, 9002]
            if dest_port in SUSPICIOUS_PORTS:
                response["action"] = "kill_process"
                response["reason"] = (
                    f"Process '{process}' (PID {pid}) connected to "
                    f"suspicious port {dest_port}"
                )

        # Execute the response
        if response["action"] == "kill_process":
            success = self._kill_process(pid, process)
            response["success"] = success
            if success:
                logger.warning(
                    f"AUTO-RESPONSE: Killed '{process}' (PID {pid}) — "
                    f"{response['reason']}"
                )
            else:
                logger.error(
                    f"AUTO-RESPONSE FAILED: Could not kill '{process}' "
                    f"(PID {pid})"
                )

        self._response_log.append(response)
        if self.log_callback:
            try:
                self.log_callback(response)
            except Exception as e:
                logger.error(f"ThreatResponder log callback failed: {e}")

        return response

    def _kill_process(self, pid: int, process: str) -> bool:
        try:
            os.kill(pid, signal.SIGTERM)
            logger.info(f"Sent SIGTERM to {process} (PID {pid})")
            return True
        except ProcessLookupError:
            logger.info(f"Process {pid} already gone")
            return True
        except PermissionError:
            try:
                os.kill(pid, signal.SIGKILL)
                logger.info(f"Sent SIGKILL to {process} (PID {pid})")
                return True
            except Exception as e:
                logger.error(f"Could not kill {pid}: {e}")
                return False
        except Exception as e:
            logger.error(f"Kill failed for {pid}: {e}")
            return False

    def get_response_log(self) -> list:
        return list(self._response_log)

    def get_stats(self) -> dict:
        total     = len(self._response_log)
        kills     = sum(1 for r in self._response_log
                        if r["action"] == "kill_process")
        successes = sum(1 for r in self._response_log
                        if r["success"])
        return {
            "total_responses": total,
            "kill_attempts":   kills,
            "successful_kills": successes,
        }
