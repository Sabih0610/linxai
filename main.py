# main.py
# LINxAI — Main pipeline entry point.
# Legacy terminal entry point; shared desktop services are planned.
# AI Engine → CIE → Executor → Audit Logger
# Optional: eBPF daemon, Resource Manager, VPS Manager

import os
import sys
import time
import logging
import argparse
import signal
import threading
import traceback

from ui.safe_paths import safe_cwd

logging.basicConfig(level=logging.ERROR,
                    format="%(levelname)s [%(name)s] %(message)s")

logger = logging.getLogger(__name__)

SERVICE_ALIASES = {
    "apache": "apache2",
    "httpd": "apache2",
}


def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

def green(t):   return _c("32", t)
def yellow(t):  return _c("33", t)
def cyan(t):    return _c("36", t)
def red(t):     return _c("31", t)
def dim(t):     return _c("2",  t)
def bold(t):    return _c("1",  t)
def magenta(t): return _c("35", t)


def _read_config() -> dict:
    """Read /etc/linxai/config.yaml if available, else use defaults."""
    defaults = {
        "ebpf":     {"enabled": True,  "filter_noise": True},
        "resource": {"cpu_threshold_pct": 80.0, "poll_interval_s": 5.0},
        "modules":  {"voice_enabled": False, "vps_enabled": True,
                     "resource_enabled": True},
        "execution":{"command_timeout_s": 30, "face_auth_enabled": False},
        "logging":  {"log_path": "/var/log/linxai/audit.jsonl"},
    }
    try:
        import yaml
        cfg_path = os.environ.get("LINXAI_CONFIG", "/etc/linxai/config.yaml")
        if os.path.exists(cfg_path):
            with open(cfg_path) as f:
                loaded = yaml.safe_load(f) or {}
            for key, val in loaded.items():
                if key in defaults and isinstance(val, dict):
                    defaults[key].update(val)
                else:
                    defaults[key] = val
    except Exception:
        pass
    return defaults


class LINxAIPipeline:

    def __init__(self, use_face_auth: bool = False, quiet: bool = False,
                 enable_ebpf: bool = True, enable_resource: bool = True):
        safe_cwd()
        self.quiet = quiet
        self.cfg   = _read_config()
        self._ebpf_daemon    = None
        self._resource_mgr   = None
        self._interactive    = True
        self._classifying    = False

        if not quiet:
            print()
            print(bold("  LINxAI — Intelligent Linux Administration Layer"))
            print(dim("  Initialising modules..."))
            print()

        # ── Core modules ──────────────────────────────────────────────────────
        from ai.engine import AIEngine
        from ai.context import ContextMemory
        from cie.validator import CommandIntelligenceEngine
        from executor.controller import ExecutionController
        from executor.failure_advisor import diagnose
        from executor.output_analyzer import analyze
        from executor.task_planner import (
            fix_command as fix_task_capability,
            plan as plan_task,
        )
        from logger.audit import AuditLogger
        from logger.integration import LoggingHub
        from ui.output_queue import OutputQueue

        log_path      = self.cfg["logging"]["log_path"]
        self.hub      = LoggingHub(log_path=log_path)
        self.audit    = self.hub.audit
        self.memory   = ContextMemory(max_context=5)
        from ai.cache import CommandCache
        self.cache    = CommandCache()
        self.ai       = AIEngine(cache=self.cache)
        from system.state import SystemStateRegistry
        self.state    = SystemStateRegistry()
        from ai.chat import ChatResponder
        self.chat     = ChatResponder(state_registry=self.state)
        self.last_output = ""
        self._last_output = ""
        self._last_service = ""
        self._last_port = None
        self._recent_service_ports = self.memory.recent_service_ports(5)
        if self._recent_service_ports:
            latest_service_port = self._recent_service_ports[0]
            self._last_service = latest_service_port.get("service", "") or ""
            self._last_port = latest_service_port.get("port")
        self._analyze_output = analyze
        self._diagnose_failure = diagnose
        self._plan_task = plan_task
        self._fix_task_capability = fix_task_capability
        self.alert_queue = OutputQueue()
        self._alert_seen = {}
        self._alert_lock = threading.Lock()
        auto_response_enabled = self.cfg.get("auto_response", {}).get("enabled", False)
        from executor.auto_response import ThreatResponder
        self.threat_responder = ThreatResponder(enabled=auto_response_enabled)
        self._shown_alerts = set()
        self._alert_thread = threading.Thread(
            target=self._proactive_alert_loop,
            daemon=True,
            name="linxai-alerts"
        )
        self._alert_thread.start()
        self.cie      = CommandIntelligenceEngine(timeout_ms=500)
        timeout_s     = self.cfg["execution"]["command_timeout_s"]
        face_auth     = use_face_auth or self.cfg["execution"]["face_auth_enabled"]
        self.executor = ExecutionController(
            use_face_auth=face_auth,
            timeout_s=timeout_s
        )
        self.audit.log_system_start()

        if not quiet:
            print(f"  {green('✓')} AI Engine    — Qwen2.5:1.5b via Ollama")
            if getattr(self.ai, "cpu_only", False):
                print(f"  {yellow('⚠')} Ollama       — CPU-only; novel commands may take longer")
            print(f"  {green('✓')} CIE          — 20 system state checks")
            print(f"  {green('✓')} Executor     — subprocess + safety guard")
            print(f"  {green('✓')} Audit Logger — {log_path}")

        # ── eBPF daemon ───────────────────────────────────────────────────────
        ebpf_cfg = self.cfg.get("ebpf", {})
        if enable_ebpf and ebpf_cfg.get("enabled", True):
            try:
                if os.geteuid() == 0:
                    from ebpf.daemon import eBPFDaemon

                    def _ebpf_event_handler(record: dict):
                        self.hub.ebpf_callback(record)

                        event_type = record.get("event_type", "")
                        payload    = record.get("payload", {})
                        proc       = payload.get("process", "")
                        proc_base  = proc.split("/")[-1]
                        dest_or_file = ""
                        is_suspicious = False

                        # Credential access by untrusted processes
                        if event_type == "file_open":
                            fname = payload.get("filename", "")
                            dest_or_file = fname
                            TRUSTED_PROCS = {
                                "sshd", "sudo", "su", "login",
                                "systemd", "pam_unix", "passwd",
                                "polkit", "polkitd", "polkit-agent",
                                "polkit-agent-helper-1", "polkit-agent-he",
                                "pkexec", "cron", "crond", "CRON",
                                "systemd-logind", "systemd-userdbd",
                                "systemd-machine", "systemd-tmpfiles",
                                "systemd-tmpfile",
                                "systemd-journal", "accounts-daemon",
                                "unattended-upgr", "packagekitd", "snapd",
                                "dbus-daemon", "gdm", "gdm-session",
                                "dpkg", "dpkg-preconfigure",
                                "dpkg-preconfigu", "apt", "apt-get",
                                "apt-config", "frontend", "debconf",
                                "needrestart", "update-alternat",
                                "ucf", "adduser", "useradd",
                            }
                            TRUSTED_PATH_PREFIXES = {
                                "/run/credentials/",
                            }

                            def _trusted_proc_name(name: str) -> bool:
                                base = (name or "").split("/")[-1].lower()
                                for trusted in TRUSTED_PROCS:
                                    trusted = trusted.lower()
                                    if base == trusted:
                                        return True
                                    if len(trusted) >= 8 and (
                                        base.startswith(trusted)
                                        or trusted.startswith(base)
                                    ):
                                        return True
                                    if min(len(base), len(trusted)) >= 8 and (
                                        trusted in base or base in trusted
                                    ):
                                        return True
                                return False

                            def _systemd_helper(name: str) -> bool:
                                base = (name or "").split("/")[-1].lower()
                                return base == "systemd" or base.startswith("systemd-")

                            sensitive_path = any(s in fname for s in [
                                "/etc/shadow", "/etc/sudoers", "/root/.ssh",
                                "/proc/keys", "id_rsa", "authorized_keys"
                            ])
                            trusted_credential_path = any(
                                fname.startswith(prefix)
                                for prefix in TRUSTED_PATH_PREFIXES
                            )

                            if (
                                sensitive_path
                                and trusted_credential_path
                                and _systemd_helper(proc_base)
                            ):
                                return

                            if sensitive_path and not _trusted_proc_name(proc_base):
                                is_suspicious = True

                        # Outbound connection to unusual port
                        elif event_type == "network_connect":
                            dest_ip = str(payload.get("dest_ip", "") or "")
                            if dest_ip.startswith("127.") or dest_ip == "::1":
                                return

                            NET_TRUSTED = {
                                "ollama", "apt", "apt-get", "dpkg", "snapd",
                                "systemd-timesyncd", "systemd-resolved",
                                "curl", "wget", "chrome", "firefox",
                                "python3",
                            }
                            if proc_base.lower() in NET_TRUSTED:
                                return

                            try:
                                port = int(payload.get("dest_port", 0) or 0)
                            except Exception:
                                port = 0
                            dest_or_file = f"{dest_ip}:{port}"

                            # Whitelist: common ports + Ollama (11434)
                            if port not in (
                                80, 443, 53, 22, 8080, 8443, 11434
                            ):
                                is_suspicious = True

                        # Known attack tools spawned
                        elif event_type == "process_exec":
                            dest_or_file = payload.get("filename", proc_base)
                            # Only flag genuinely suspicious tools
                            ATTACK_TOOLS = {
                                "nc", "ncat", "netcat", "socat", "msfconsole"
                            }
                            if proc_base in ATTACK_TOOLS:
                                is_suspicious = True

                        if is_suspicious:
                            key = (event_type, proc_base, dest_or_file)
                            now = time.time()
                            with self._alert_lock:
                                last_seen = self._alert_seen.get(key, 0)
                                if now - last_seen < 30:
                                    if not self.quiet:
                                        self.alert_queue.bump(key)
                                    return

                                self._alert_seen[key] = now
                                if len(self._alert_seen) > 200:
                                    oldest = min(
                                        self._alert_seen,
                                        key=self._alert_seen.get
                                    )
                                    self._alert_seen.pop(oldest, None)

                            self.memory.save_security_alert(record)
                            self._queue_security_alert(record, key)
                            response = self.threat_responder.respond(record)
                            if response.get("action") == "kill_process":
                                pid     = response.get("pid")
                                process = response.get("process", "?")
                                success = response.get("success", False)
                                if success and not self.quiet:
                                    self.alert_queue.push(
                                        f"\n  \033[33m⚡ AUTO-RESPONSE\033[0m: "
                                        f"{process} (PID {pid}) terminated\n"
                                        f"  \033[2mReason: {response.get('reason','')}\033[0m\n",
                                        key=("auto_response",) + key,
                                    )

                    self._ebpf_daemon = eBPFDaemon(
                        log_path=log_path,
                        event_callback=_ebpf_event_handler,
                        filter_noise=ebpf_cfg.get("filter_noise", True),
                    )
                    self._ebpf_daemon.start_async()
                    if not quiet:
                        print(f"  {green('✓')} eBPF Daemon  — execve, connect, openat")
                else:
                    if not quiet:
                        print(f"  {yellow('⚠')} eBPF Daemon  — skipped (needs root)")
            except Exception as e:
                if not quiet:
                    print(f"  {yellow('⚠')} eBPF Daemon  — unavailable ({e})")

        # ── Resource Manager ─────────────────────────────────────────────────
        res_cfg = self.cfg.get("resource", {})
        if enable_resource and self.cfg["modules"].get("resource_enabled", True):
            try:
                from resources.monitor import ResourceManager
                self._resource_mgr = ResourceManager(
                    cpu_threshold=res_cfg.get("cpu_threshold_pct", 80.0),
                    poll_interval=res_cfg.get("poll_interval_s", 5.0),
                    log_callback=self.hub.resource_callback,
                    pause_callback=lambda: self._classifying,
                )
                self._resource_mgr.start()
                if not quiet:
                    print(f"  {green('✓')} Resources    — CPU monitor active")
            except Exception as e:
                if not quiet:
                    print(f"  {yellow('⚠')} Resources    — unavailable ({e})")

        if not quiet:
            print(f"  {green('✓')} System State — port registry, health monitor active")
            print(f"  {green('✓')} Chat         — conversational AI ready")

        if not quiet:
            print()
            print(dim("  Type a Linux command in plain English. "
                      "Type 'exit' to quit."))
            print(dim("  Special: logs | stats | status | explain | help | exit"))
            print()

    def _security_alert_id(self, alert: dict) -> str:
        import hashlib as _hashlib
        return _hashlib.md5(str(alert).encode()).hexdigest()[:8]

    def _security_alert_key(self, alert: dict):
        event_type = alert.get("event_type", "")
        payload = alert.get("payload", {})
        proc = payload.get("process", "")
        proc_base = proc.split("/")[-1]

        if event_type == "network_connect":
            dest_or_file = (
                f"{payload.get('dest_ip','?')}:"
                f"{payload.get('dest_port','?')}"
            )
        elif event_type == "file_open":
            dest_or_file = payload.get("filename", "")
        elif event_type == "process_exec":
            dest_or_file = payload.get("filename", proc_base)
        else:
            dest_or_file = ""

        return (event_type, proc_base, dest_or_file)

    def _format_security_alert(self, alert: dict) -> str:
        et = alert.get("event_type", "?")
        p  = alert.get("payload", {})
        if et == "file_open":
            fname = p.get("filename", "?")
            proc  = p.get("process", "?")
            pid   = p.get("pid", "?")
            return (
                f"\n  {chr(27)}[33m⚠ THREAT DETECTED{chr(27)}[0m — "
                f"Sensitive file accessed\n"
                f"  {chr(27)}[2m→{chr(27)}[0m "
                f"{fname} by {proc} (PID {pid})\n"
                f"  {chr(27)}[2mClassification: "
                f"CREDENTIAL ACCESS ATTEMPT{chr(27)}[0m\n"
                f"  {chr(27)}[2mMeaning: a process read a credential file; "
                f"review if you did not expect this.{chr(27)}[0m\n"
            )
        if et == "network_connect":
            dest = f"{p.get('dest_ip','?')}:{p.get('dest_port','?')}"
            proc = p.get("process", "?")
            pid  = p.get("pid", "?")
            return (
                f"\n  {chr(27)}[33m⚠ THREAT DETECTED{chr(27)}[0m — "
                f"Suspicious outbound connection\n"
                f"  {chr(27)}[2m→{chr(27)}[0m "
                f"{proc} (PID {pid}) → {dest}\n"
                f"  {chr(27)}[2mClassification: "
                f"SUSPICIOUS NETWORK ACTIVITY{chr(27)}[0m\n"
            )
        if et == "process_exec":
            proc = p.get("process", "?")
            pid  = p.get("pid", "?")
            return (
                f"\n  {chr(27)}[33m⚠ THREAT DETECTED{chr(27)}[0m — "
                f"Suspicious process launched\n"
                f"  {chr(27)}[2m→{chr(27)}[0m "
                f"{proc} (PID {pid})\n"
                f"  {chr(27)}[2mClassification: "
                f"SUSPICIOUS PROCESS EXECUTION{chr(27)}[0m\n"
            )
        return ""

    def _queue_security_alert(self, alert: dict, key=None):
        if self.quiet:
            return
        alert_id = self._security_alert_id(alert)
        if alert_id in self._shown_alerts:
            return

        msg = self._format_security_alert(alert)
        if not msg:
            return

        self._shown_alerts.add(alert_id)
        self.alert_queue.push(msg, key=key or self._security_alert_key(alert))

    def _proactive_alert_loop(self):
        import time as _time
        while True:
            try:
                alerts = self.memory.get_security_alerts(last_n=10)
                for alert in alerts:
                    self._queue_security_alert(
                        alert,
                        self._security_alert_key(alert)
                    )
            except Exception:
                pass
            _time.sleep(2)

    def _service_name_from_plan(self, plan: dict) -> str:
        target = str(plan.get("target", "")).strip()
        if target:
            return self._normalize_service_name(target)

        import re
        command = str(plan.get("command", ""))
        match = re.search(
            r"\bsystemctl\s+(?:start|restart|stop)\s+(?P<service>[\w@.-]+)",
            command,
        )
        return self._normalize_service_name(match.group("service")) if match else ""

    def _normalize_service_name(self, service: str) -> str:
        service = (service or "").strip()
        if not service:
            return ""
        suffix = ".service" if service.endswith(".service") else ""
        base = service[:-8] if suffix else service
        mapped = SERVICE_ALIASES.get(base.lower(), base)
        return f"{mapped}{suffix}" if suffix else mapped

    def _package_for_service(self, service: str) -> str:
        base = self._normalize_service_name(service)
        if base.endswith(".service"):
            base = base[:-8]
        return {
            "apache2": "apache2",
            "nginx": "nginx",
        }.get(base.lower(), base)

    def _service_unit_exists(self, service: str) -> bool:
        import subprocess

        unit = self._normalize_service_name(service)
        if not unit:
            return False
        candidates = [unit]
        if not unit.endswith(".service"):
            candidates.append(f"{unit}.service")

        for candidate in candidates:
            try:
                result = subprocess.run(
                    ["systemctl", "cat", candidate],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=8,
                )
            except Exception:
                continue
            if result.returncode == 0:
                return True
        return False

    def _handle_missing_service_install(
        self,
        user_input: str,
        plan: dict,
        service: str,
        t_start: float,
    ) -> dict:
        unit = self._normalize_service_name(service)
        package = self._package_for_service(unit)
        if not self.quiet:
            print(f"  {dim('│')}  {yellow(f'{unit} is not installed.')} "
                  "Install it? [y/N]")

        stdin = getattr(sys, "stdin", None)
        if (
            not getattr(self, "_interactive", True)
            or not stdin
            or not stdin.isatty()
        ):
            if not self.quiet:
                print(f"  {dim('└─')} {dim('No command was run.')}")
            self.memory.save(
                user_input,
                plan,
                {"skipped": True, "missing_service": unit},
            )
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "missing_service",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        if not self.quiet and hasattr(self, "alert_queue"):
            self.alert_queue.flush()

        try:
            answer = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""

        if answer not in {"y", "yes"}:
            if not self.quiet:
                print(f"  {dim('└─')} {yellow('Cancelled - nothing changed.')}")
            self.memory.save(
                user_input,
                plan,
                {"cancelled": True, "missing_service": unit},
            )
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "cancelled",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        return self.process(f"install {package}")

    def _port_from_plan(self, plan: dict) -> int | None:
        raw = str(plan.get("port", "")).strip()
        if not raw:
            return None
        try:
            port = int(raw)
        except ValueError:
            return None
        if 1 <= port <= 65535:
            return port
        return None

    def _detect_service_port(self, service: str) -> int | None:
        service_key = (service or "").lower()
        if service_key.endswith(".service"):
            service_key = service_key[:-8]

        if service_key == "nginx":
            ports = self._nginx_configured_ports()
            if ports:
                return ports[0]

        try:
            import subprocess
            show = subprocess.run(
                ["systemctl", "show", "-p", "MainPID", "--value", service],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if show.returncode != 0:
                return None
            pid = show.stdout.strip()
            if not pid or pid == "0":
                return None

            ss = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if ss.returncode != 0:
                return None

            import re
            for line in ss.stdout.splitlines():
                if f"pid={pid}" not in line:
                    continue
                parts = line.split()
                if len(parts) < 5:
                    continue
                local_idx = (
                    4 if parts[0].lower() in {"tcp", "udp", "tcp6", "udp6"}
                    else 3
                )
                if len(parts) <= local_idx:
                    continue
                match = re.search(r":(?P<port>\d{1,5})$", parts[local_idx])
                if match:
                    port = int(match.group("port"))
                    if 1 <= port <= 65535:
                        return port
        except Exception:
            return None
        return None

    def _remember_service_port(
        self,
        service: str,
        port: int | None,
        action: str = "",
    ):
        service = (service or "").strip()
        if not service and port is None:
            return

        if port is not None:
            try:
                port = int(port)
            except (TypeError, ValueError):
                port = None
        if port is not None and not 1 <= port <= 65535:
            port = None

        self._last_service = service
        self._last_port = port
        item = {"service": service, "port": port, "action": action or ""}
        self._recent_service_ports = [
            existing for existing in getattr(self, "_recent_service_ports", [])
            if not (
                existing.get("service") == service
                and existing.get("port") == port
            )
        ]
        self._recent_service_ports.insert(0, item)
        self._recent_service_ports = self._recent_service_ports[:5]

        if hasattr(self.memory, "remember_service_port"):
            self.memory.remember_service_port(service, port, action)

    def _record_successful_service_context(self, plan: dict, result):
        if plan.get("intent") not in {
            "service_start", "service_stop", "service_restart",
        }:
            return
        if not (hasattr(result, "is_success") and result.is_success()):
            return

        if hasattr(self, "state"):
            try:
                self.state.refresh()
            except Exception:
                pass

        service = self._service_name_from_plan(plan)
        if not service:
            return
        port = self._port_from_plan(plan)
        if port is None:
            port = self._detect_service_port(service)
        self._remember_service_port(service, port, plan.get("intent", ""))

    def _is_contextual_port_query(self, user_input: str) -> bool:
        import re
        text = re.sub(r"\s+", " ", user_input.lower().strip())
        if not text or "ports" in text:
            return False
        if re.search(r"\bport\s+\d{1,5}\b", text):
            return False
        exact = {
            "show port", "show the port", "show that port",
            "check port", "check the port", "check that port",
            "the port", "that port", "what port", "which port",
            "what is the port", "what's the port",
        }
        if text in exact:
            return True
        return bool(
            re.search(
                r"\b(?:show|check|display|what(?:'s| is)|which)\s+"
                r"(?:the\s+|that\s+)?port\b",
                text,
            )
            or re.search(r"\b(?:the|that)\s+port\b", text)
        )

    def _port_context_note(self, item: dict) -> str:
        action = item.get("action", "")
        if action == "service_start":
            return "the service you just started"
        if action == "service_restart":
            return "the service you just restarted"
        if action == "service_stop":
            return "the service you just stopped"
        return "the service you just worked with"

    def _handle_contextual_port_query(
        self,
        user_input: str,
        t_start: float,
    ) -> dict | None:
        if not self._is_contextual_port_query(user_input):
            return None

        item = (
            self._recent_service_ports[0]
            if getattr(self, "_recent_service_ports", [])
            else {}
        )
        service = item.get("service") or self._last_service
        port = item.get("port") if item else self._last_port

        if port is None:
            if not self.quiet:
                print(f"  {dim('│')}  {yellow('[context]')} Which port?")
                print(f"  {dim('└─')} {dim('No command was run.')}")
            plan = {
                "intent": "port_check",
                "target": "",
                "port": "",
                "pre_conditions": [],
                "command": "",
                "requires_sudo": False,
                "risk_level": "low",
                "rollback": "",
                "explanation": "Asked for a port but no recent port is known.",
            }
            self.memory.save(user_input, plan, {"skipped": True})
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "need_input",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        plan = {
            "intent": "port_check",
            "target": str(port),
            "port": str(port),
            "pre_conditions": [],
            "command": f'ss -tlnp "sport = :{port}"',
            "requires_sudo": False,
            "risk_level": "low",
            "rollback": "",
            "explanation": "Checks the port from recent context.",
        }

        if not self.quiet:
            print(
                f"  {dim('│')}  {dim('[context] using recent port ')}"
                f"{port}"
            )
            print(f"  {dim('│')}  {dim('[3/3] Executing...')}",
                  end="", flush=True)

        t_exec = time.perf_counter()
        result = self.executor.execute(plan)
        exec_ms = int((time.perf_counter() - t_exec) * 1000)
        self.hub.execution(result.to_dict() if hasattr(result, "to_dict")
                           else result)
        self.memory.save(
            user_input,
            plan,
            result.to_dict() if hasattr(result, "to_dict") else result,
        )
        self._last_output = getattr(result, "stdout", "") or ""
        self.last_output = self._last_output

        if not self.quiet:
            if hasattr(result, "is_success") and result.is_success():
                print(f"\r  {dim('│')}  {green('[3/3] SUCCESS')}  "
                      f"exit={result.return_code}  {dim(f'{exec_ms}ms')}")
                summary = self._analyze_output(
                    "port_check",
                    getattr(result, "command", plan["command"]),
                    result.stdout or "",
                    result.stderr or "",
                    result.return_code,
                )
                note = self._port_context_note(item)
                if summary and summary.startswith("Nothing is listening"):
                    subject = service or "The recent service"
                    print(
                        f"  {dim('│')}    {subject} is not listening on "
                        f"port {port} ({note})."
                    )
                elif service:
                    print(
                        f"  {dim('│')}    {service} is listening on port "
                        f"{port} ({note})."
                    )
                    if summary:
                        print(f"  {dim('│')}    {dim(summary)}")
                elif summary:
                    print(f"  {dim('│')}    {summary}")
            else:
                self._print_failure_result(plan, result)
            total_ms = int((time.perf_counter() - t_start) * 1000)
            print(f"  {dim('└─')} port_check complete  total={dim(f'{total_ms}ms')}")

        return {
            "input": user_input,
            "plan": plan,
            "result": (
                result.to_dict() if hasattr(result, "to_dict") else result
            ),
            "outcome": getattr(result, "status", "unknown"),
            "total_ms": int((time.perf_counter() - t_start) * 1000),
        }

    def find_free_port(self, start: int) -> int | None:
        from cie.checks import check_port_free

        try:
            start = int(start)
        except (TypeError, ValueError):
            start = 8000

        base = start + 1 if 1024 <= start < 65535 else 8000
        for candidate in range(base, 65536):
            if check_port_free(candidate).get("status") == "ok":
                return candidate
        return None

    def _port_free_check(self, port: int) -> dict:
        from cie.checks import check_port_free

        return check_port_free(int(port))

    def _print_port_conflict_options(
        self,
        service: str,
        port: int,
        owner_name: str,
        owner_pid,
    ):
        service_name = service or "the service"
        pid_text = owner_pid if owner_pid is not None else "unknown"
        print(
            f"  {dim('│')}  Port {port} is already in use by "
            f"'{owner_name}' (PID {pid_text})."
        )
        print(
            f"  {dim('│')}  A port can only be used by one service at a "
            f"time, so I won't start {service_name} there."
        )
        print(f"  {dim('│')}  What would you like to do?")
        print(
            f"  {dim('│')}    [1] Use a different port for {service_name} "
            f"(I'll pick the next free one)"
        )
        print(f"  {dim('│')}    [2] Choose a specific port yourself")
        print(
            f"  {dim('│')}    [3] Stop '{owner_name}' first, then start "
            f"{service_name} on {port}"
        )
        print(f"  {dim('│')}    [4] Cancel")

    def _port_conflict_result(
        self,
        user_input: str,
        plan: dict,
        port: int,
        owner_name: str,
        owner_pid,
        t_start: float,
        outcome: str = "conflict",
    ) -> dict:
        self.memory.save(
            user_input,
            plan,
            {
                "skipped": True,
                "port_conflict": True,
                "port": port,
                "owner": owner_name,
                "pid": owner_pid,
            },
        )
        return {
            "input": user_input,
            "plan": plan,
            "outcome": outcome,
            "total_ms": int((time.perf_counter() - t_start) * 1000),
        }

    def _protected_owner_reason(self, owner_name: str, owner_pid) -> str:
        name = (owner_name or "").lower()
        if name in {"sshd", "ssh"}:
            return "ssh is critical; stopping it could lock you out."
        if name == "ollama":
            return "ollama is LINxAI's model backend; stopping it would break classification."
        if name == "systemd" or name.startswith("systemd-"):
            return "systemd is critical system infrastructure; stopping it would destabilize the machine."

        try:
            pid = int(owner_pid)
        except (TypeError, ValueError):
            pid = None

        if pid and pid == os.getpid():
            return "that process is LINxAI itself; stopping it would interrupt this session."

        if pid:
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmdline = f.read().replace(b"\x00", b" ").decode(
                        "utf-8", errors="ignore"
                    ).lower()
            except Exception:
                cmdline = ""
            cwd = safe_cwd().replace("\\", "/").lower()
            if "linxai" in cmdline or (cwd and cwd in cmdline):
                return "that process appears to belong to LINxAI; stopping it would interrupt this session."

        return ""

    def _managed_service_unit(self, owner_name: str) -> str:
        import subprocess

        name = (owner_name or "").strip()
        candidates = [name]
        if name and not name.endswith(".service"):
            candidates.append(f"{name}.service")

        for candidate in candidates:
            if not candidate:
                continue
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", "--quiet", candidate],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                )
            except Exception:
                continue
            if result.returncode == 0:
                return candidate
        return ""

    def _stop_port_owner(self, owner_name: str, owner_pid) -> tuple[bool, str]:
        import signal as _signal
        import time as _time

        unit = self._managed_service_unit(owner_name)
        if unit:
            result = self._run_root_command(["systemctl", "stop", unit], timeout=30)
            if result.returncode == 0:
                return True, f"Stopped {unit}."
            return False, self._command_failure(f"stop {unit}", result)

        try:
            pid = int(owner_pid)
        except (TypeError, ValueError):
            return False, "I could not identify a process to stop cleanly."

        try:
            os.kill(pid, _signal.SIGTERM)
        except ProcessLookupError:
            return True, "The process was already gone."
        except PermissionError:
            return False, "Permission denied while trying to stop the process."
        except Exception as e:
            return False, f"Could not stop the process: {e}"

        for _ in range(20):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True, f"Stopped {owner_name} (PID {pid})."
            except Exception:
                break
            _time.sleep(0.25)
        return True, f"Sent a clean stop signal to {owner_name} (PID {pid})."

    def _execute_service_start_plan(
        self,
        user_input: str,
        plan: dict,
        service: str,
        port: int,
        t_start: float,
    ) -> dict:
        start_plan = dict(plan)
        service = self._normalize_service_name(service)
        start_plan["intent"] = "service_start"
        start_plan["target"] = service
        start_plan["port"] = str(port)
        import shlex
        start_plan["command"] = f"systemctl start {shlex.quote(service)}"
        start_plan["requires_sudo"] = True

        result = self.executor.execute(start_plan)
        self.hub.execution(result.to_dict() if hasattr(result, "to_dict") else result)
        self._record_successful_service_context(start_plan, result)
        self.memory.save(
            user_input,
            start_plan,
            result.to_dict() if hasattr(result, "to_dict") else result,
        )

        if not self.quiet:
            if hasattr(result, "is_success") and result.is_success():
                print(f"  {dim('│')}  {green(f'Started {service} on port {port}.')}")
            else:
                self._print_failure_result(start_plan, result)
            print(f"  {dim('└─')} {dim('port conflict handling finished.')}")

        return {
            "input": user_input,
            "plan": start_plan,
            "result": result.to_dict() if hasattr(result, "to_dict") else result,
            "outcome": getattr(result, "status", "unknown"),
            "total_ms": int((time.perf_counter() - t_start) * 1000),
        }

    def _service_key(self, service: str) -> str:
        service_key = self._normalize_service_name(service).lower()
        if service_key.endswith(".service"):
            service_key = service_key[:-8]
        return service_key

    def _execute_service_start_default(
        self,
        user_input: str,
        plan: dict,
        service: str,
        t_start: float,
    ) -> dict:
        service = self._normalize_service_name(service)
        start_plan = dict(plan)
        start_plan["intent"] = "service_start"
        start_plan["target"] = service
        start_plan["port"] = ""
        import shlex
        start_plan["command"] = f"systemctl start {shlex.quote(service)}"
        start_plan["requires_sudo"] = True

        result = self.executor.execute(start_plan)
        self.hub.execution(result.to_dict() if hasattr(result, "to_dict") else result)
        self._record_successful_service_context(start_plan, result)
        self.memory.save(
            user_input,
            start_plan,
            result.to_dict() if hasattr(result, "to_dict") else result,
        )

        if not self.quiet:
            if hasattr(result, "is_success") and result.is_success():
                print(
                    f"  {dim('│')}  "
                    f"{green(f'Started {service} on its default configured port.')}"
                )
            else:
                self._print_failure_result(start_plan, result)
            print(f"  {dim('└─')} {dim('service start finished.')}")

        return {
            "input": user_input,
            "plan": start_plan,
            "result": result.to_dict() if hasattr(result, "to_dict") else result,
            "outcome": getattr(result, "status", "unknown"),
            "total_ms": int((time.perf_counter() - t_start) * 1000),
        }

    def _handle_non_nginx_port_options(
        self,
        user_input: str,
        plan: dict,
        service: str,
        port: int,
        t_start: float,
        conflict: dict | None = None,
    ) -> dict:
        service = self._normalize_service_name(service)
        found = (conflict or {}).get("found") or {}
        owner_name = found.get("name") or "unknown"
        owner_pid = found.get("pid")

        if not self.quiet:
            print(
                f"  {dim('│')}  I can only auto-configure nginx's port. "
                f"For {service} I can:"
            )
            print(f"  {dim('│')}    [1] start it on its default port")
            print(f"  {dim('│')}    [2] stop the conflicting service")
            print(f"  {dim('│')}    [3] cancel")

        stdin = getattr(sys, "stdin", None)
        if (
            not getattr(self, "_interactive", True)
            or not stdin
            or not stdin.isatty()
        ):
            if not self.quiet:
                print(f"  {dim('└─')} {dim('No command was run.')}")
            self.memory.save(
                user_input,
                plan,
                {"skipped": True, "port": port, "service": service},
            )
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "cancelled",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        if not self.quiet and hasattr(self, "alert_queue"):
            self.alert_queue.flush()

        try:
            choice = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            choice = "3"

        if choice == "1":
            return self._execute_service_start_default(
                user_input, plan, service, t_start
            )

        if choice == "2":
            if not conflict:
                if not self.quiet:
                    print(
                        f"  {dim('└─')} "
                        f"{yellow('No conflicting service was identified.')}"
                    )
                self.memory.save(
                    user_input,
                    plan,
                    {"skipped": True, "port": port, "service": service},
                )
                return {
                    "input": user_input,
                    "plan": plan,
                    "outcome": "cancelled",
                    "total_ms": int((time.perf_counter() - t_start) * 1000),
                }

            reason = self._protected_owner_reason(owner_name, owner_pid)
            if reason:
                if not self.quiet:
                    print(f"  {dim('└─')} {yellow(reason)}")
                self.memory.save(
                    user_input,
                    plan,
                    {"skipped": True, "protected_owner": owner_name},
                )
                return {
                    "input": user_input,
                    "plan": plan,
                    "outcome": "cancelled",
                    "total_ms": int((time.perf_counter() - t_start) * 1000),
                }

            stopped, message = self._stop_port_owner(owner_name, owner_pid)
            if not self.quiet:
                colour = green if stopped else red
                print(f"  {dim('│')}  {colour(message)}")
                print(f"  {dim('└─')} {dim('conflicting service handling finished.')}")
            self.memory.save(
                user_input,
                plan,
                {
                    "stopped_conflict": stopped,
                    "owner": owner_name,
                    "pid": owner_pid,
                    "message": message,
                },
            )
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "success" if stopped else "error",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        if not self.quiet:
            print(f"  {dim('└─')} {yellow('Cancelled - nothing changed.')}")
        self.memory.save(user_input, plan, {"cancelled": True})
        return {
            "input": user_input,
            "plan": plan,
            "outcome": "cancelled",
            "total_ms": int((time.perf_counter() - t_start) * 1000),
        }

    def _start_service_on_checked_port(
        self,
        user_input: str,
        plan: dict,
        service: str,
        port: int,
        t_start: float,
    ) -> dict:
        service = self._normalize_service_name(service)
        service_key = self._service_key(service)
        selected_plan = dict(plan)
        selected_plan["target"] = service
        selected_plan["port"] = str(port)

        if service_key != "nginx":
            return self._handle_non_nginx_port_options(
                user_input, selected_plan, service, port, t_start
            )

        configured_ports = self._nginx_configured_ports()
        if port in configured_ports:
            return self._execute_service_start_plan(
                user_input, selected_plan, service, port, t_start
            )

        ok, message = self._configure_nginx_port(port)
        if ok:
            if hasattr(self, "state"):
                try:
                    self.state.refresh()
                except Exception:
                    pass
            self._remember_service_port(service, port, "service_start")

        if not self.quiet:
            colour = green if ok else red
            print(f"  {dim('│')}  {colour(message)}")
            if ok:
                print(f"  {dim('│')}  {green(f'Started {service} on port {port}.')}")
            print(f"  {dim('└─')} {dim('port conflict handling finished.')}")

        self.memory.save(
            user_input,
            selected_plan,
            {"nginx_port_configured": ok, "port": port, "message": message},
        )
        return {
            "input": user_input,
            "plan": selected_plan,
            "outcome": "success" if ok else "error",
            "total_ms": int((time.perf_counter() - t_start) * 1000),
        }

    def _handle_port_conflict(
        self,
        user_input: str,
        plan: dict,
        service: str,
        port: int,
        conflict: dict,
        t_start: float,
    ) -> dict:
        while True:
            found = conflict.get("found") or {}
            owner_name = found.get("name") or "unknown"
            owner_pid = found.get("pid")

            if not self.quiet:
                self._print_port_conflict_options(
                    service, port, owner_name, owner_pid
                )

            stdin = getattr(sys, "stdin", None)
            if (
                not getattr(self, "_interactive", True)
                or not stdin
                or not stdin.isatty()
            ):
                if not self.quiet:
                    print(f"  {dim('└─')} {dim('No command was run.')}")
                return self._port_conflict_result(
                    user_input, plan, port, owner_name, owner_pid, t_start
                )

            if not self.quiet and hasattr(self, "alert_queue"):
                self.alert_queue.flush()

            try:
                choice = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                choice = "4"

            if choice == "1":
                free_port = self.find_free_port(port)
                if free_port is None:
                    if not self.quiet:
                        print(f"  {dim('│')}  {red('No free port was found above the requested port.')}")
                    return self._port_conflict_result(
                        user_input, plan, port, owner_name, owner_pid,
                        t_start, outcome="error"
                    )
                if not self.quiet:
                    print(f"  {dim('│')}  {green(f'Using next free port {free_port}.')}")
                return self._start_service_on_checked_port(
                    user_input, plan, service, free_port, t_start
                )

            if choice == "2":
                if not self.quiet and hasattr(self, "alert_queue"):
                    self.alert_queue.flush()
                try:
                    if not self.quiet:
                        print(f"  {dim('│')}  Enter a port:")
                    raw_port = input("> ").strip()
                except (EOFError, KeyboardInterrupt):
                    raw_port = ""
                try:
                    selected_port = int(raw_port)
                except ValueError:
                    if not self.quiet:
                        print(f"  {dim('│')}  {yellow('Please enter a number from 1 to 65535.')}")
                    continue
                if not 1 <= selected_port <= 65535:
                    if not self.quiet:
                        print(f"  {dim('│')}  {yellow('Please enter a number from 1 to 65535.')}")
                    continue
                selected_check = self._port_free_check(selected_port)
                if selected_check.get("status") == "ok":
                    return self._start_service_on_checked_port(
                        user_input, plan, service, selected_port, t_start
                    )
                if selected_check.get("status") == "conflict":
                    port = selected_port
                    conflict = selected_check
                    continue
                if not self.quiet:
                    print(f"  {dim('│')}  {red('I could not verify that port, so nothing changed.')}")
                return self._port_conflict_result(
                    user_input, plan, selected_port, owner_name, owner_pid,
                    t_start, outcome="error"
                )

            if choice == "3":
                reason = self._protected_owner_reason(owner_name, owner_pid)
                if reason:
                    if not self.quiet:
                        print(f"  {dim('│')}  {yellow(reason)}")
                    continue

                if not self.quiet and hasattr(self, "alert_queue"):
                    self.alert_queue.flush()
                try:
                    if not self.quiet:
                        print(
                            f"  {dim('│')}  Stop {owner_name} "
                            f"(PID {owner_pid})? [y/N]"
                        )
                    answer = input("> ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    answer = ""
                if answer not in {"y", "yes"}:
                    if not self.quiet:
                        print(f"  {dim('│')}  {yellow('Cancelled stop request.')}")
                    continue

                stopped, message = self._stop_port_owner(owner_name, owner_pid)
                if not self.quiet:
                    colour = green if stopped else red
                    print(f"  {dim('│')}  {colour(message)}")
                if not stopped:
                    continue

                recheck = self._port_free_check(port)
                if recheck.get("status") == "ok":
                    if self._service_key(service) != "nginx":
                        return self._execute_service_start_default(
                            user_input, plan, service, t_start
                        )
                    return self._start_service_on_checked_port(
                        user_input, plan, service, port, t_start
                    )
                if recheck.get("status") == "conflict":
                    conflict = recheck
                    if not self.quiet:
                        print(f"  {dim('│')}  {yellow(f'Port {port} is still occupied.')}")
                    continue
                if not self.quiet:
                    print(f"  {dim('│')}  {red('I could not verify that the port is free.')}")
                return self._port_conflict_result(
                    user_input, plan, port, owner_name, owner_pid,
                    t_start, outcome="error"
                )

            if choice in {"4", "", "n", "no", "cancel"}:
                if not self.quiet:
                    print(f"  {dim('└─')} {yellow('Cancelled — nothing changed.')}")
                self.memory.save(
                    user_input,
                    plan,
                    {"cancelled": True, "port_conflict": True, "port": port},
                )
                return {
                    "input": user_input,
                    "plan": plan,
                    "outcome": "cancelled",
                    "total_ms": int((time.perf_counter() - t_start) * 1000),
                }

            if not self.quiet:
                print(f"  {dim('│')}  {yellow('Choose 1, 2, 3, or 4.')}")

    def _looks_like_listener_without_service(self, user_input: str) -> bool:
        import re
        text = re.sub(r"\s+", " ", user_input.lower().strip())
        patterns = (
            r"\b(?:start|run|create|open)\s+(?:a\s+)?(?:test\s+)?"
            r"(?:listener|listening|server|something)\s+(?:on|o)?\s*port\s+\d{1,5}\b",
            r"\b(?:start|run|create|open)\s+(?:any\s+service|a\s+service|service)\s+"
            r"(?:on|o|at|using)?\s*port\s+\d{1,5}\b",
            r"\b(?:start|run)\s+(?:on|o)?\s*port\s+\d{1,5}\b",
        )
        return any(re.search(pattern, text) for pattern in patterns)

    def _handle_unspecified_service_port_request(
        self,
        user_input: str,
        plan: dict,
        port: int,
        t_start: float,
    ) -> dict:
        if not self.quiet:
            print(
                f"  {dim('│')}  A port by itself does not identify which "
                f"service should listen on it."
            )
            print(f"  {dim('│')}  What would you like to do?")
            print(
                f"  {dim('│')}    [1] Configure nginx to listen on port {port}"
            )
            print(
                f"  {dim('│')}    [2] Use a temporary Python listener on "
                f"port {port}"
            )
            print(f"  {dim('│')}    [3] Cancel")

        stdin = getattr(sys, "stdin", None)
        if (
            not getattr(self, "_interactive", True)
            or not stdin
            or not stdin.isatty()
        ):
            if not self.quiet:
                print(f"  {dim('└─')} {dim('No command was run.')}")
            self.memory.save(user_input, plan, {"skipped": True, "port": port})
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "cancelled",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        if not self.quiet and hasattr(self, "alert_queue"):
            self.alert_queue.flush()

        try:
            choice = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            choice = "3"

        if choice == "1":
            nginx_plan = dict(plan)
            nginx_plan["intent"] = "service_start"
            nginx_plan["target"] = "nginx"
            nginx_plan["port"] = str(port)
            nginx_plan["command"] = "systemctl start nginx"
            nginx_plan["requires_sudo"] = True
            nginx_plan["pre_conditions"] = [
                {"check": "service_exists", "service": "nginx"}
            ]

            port_check = self._port_free_check(port)
            if port_check.get("status") == "conflict":
                return self._handle_port_conflict(
                    user_input, nginx_plan, "nginx", port, port_check, t_start
                )
            if port_check.get("status") != "ok":
                if not self.quiet:
                    message = f"Could not verify port {port}; nothing changed."
                    print(
                        f"  {dim('└─')} {red(message)}"
                    )
                self.memory.save(
                    user_input,
                    nginx_plan,
                    {"skipped": True, "port_check": port_check},
                )
                return {
                    "input": user_input,
                    "plan": nginx_plan,
                    "outcome": "error",
                    "total_ms": int((time.perf_counter() - t_start) * 1000),
                }
            return self._start_service_on_checked_port(
                user_input, nginx_plan, "nginx", port, t_start
            )

        if choice == "2":
            temp_plan = dict(plan)
            log_path = f"/tmp/linxai-http-{port}.log"
            temp_plan["intent"] = "process_background"
            temp_plan["target"] = f"python-http-{port}"
            temp_plan["port"] = str(port)
            temp_plan["command"] = (
                f"nohup python3 -m http.server {port} --bind 0.0.0.0 "
                f">{log_path} 2>&1 &"
            )
            temp_plan["requires_sudo"] = port < 1024
            temp_plan["risk_level"] = "medium" if port < 1024 else "low"
            temp_plan["rollback"] = ""
            temp_plan["explanation"] = (
                f"Starts a temporary Python HTTP listener on port {port}."
            )

            port_check = self._port_free_check(port)
            if port_check.get("status") == "conflict":
                found = port_check.get("found") or {}
                if not self.quiet:
                    owner = found.get("name", "unknown")
                    message = (
                        f"Port {port} is already in use by {owner}; "
                        "nothing changed."
                    )
                    print(
                        f"  {dim('└─')} {yellow(message)}"
                    )
                self.memory.save(
                    user_input,
                    temp_plan,
                    {"skipped": True, "port_conflict": True, "port": port},
                )
                return {
                    "input": user_input,
                    "plan": temp_plan,
                    "outcome": "conflict",
                    "total_ms": int((time.perf_counter() - t_start) * 1000),
                }

            result = self.executor.execute(temp_plan)
            self.hub.execution(
                result.to_dict() if hasattr(result, "to_dict") else result
            )
            time.sleep(1)
            listening = self._port_is_listening(port)
            if not self.quiet:
                if hasattr(result, "is_success") and result.is_success() and listening:
                    message = (
                        f"Temporary listener is running on port {port}. "
                        f"Log: {log_path}"
                    )
                    print(
                        f"  {dim('│')}  {green(message)}"
                    )
                elif hasattr(result, "is_success") and result.is_success():
                    message = (
                        f"The command started, but port {port} was not "
                        f"visible in ss yet. Log: {log_path}"
                    )
                    print(
                        f"  {dim('│')}  {yellow(message)}"
                    )
                else:
                    self._print_failure_result(temp_plan, result)
                print(f"  {dim('└─')} {dim('temporary listener flow finished.')}")

            self.memory.save(
                user_input,
                temp_plan,
                result.to_dict() if hasattr(result, "to_dict") else result,
            )
            return {
                "input": user_input,
                "plan": temp_plan,
                "result": result.to_dict() if hasattr(result, "to_dict") else result,
                "outcome": "success" if listening else getattr(result, "status", "error"),
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        if not self.quiet:
            print(f"  {dim('└─')} {yellow('Cancelled - nothing changed.')}")
        self.memory.save(user_input, plan, {"cancelled": True, "port": port})
        return {
            "input": user_input,
            "plan": plan,
            "outcome": "cancelled",
            "total_ms": int((time.perf_counter() - t_start) * 1000),
        }

    def _handle_service_port_request(self, user_input: str, plan: dict,
                                     t_start: float) -> dict | None:
        if plan.get("intent") not in {
            "service_start", "service_restart", "service_stop",
        }:
            return None

        port = self._port_from_plan(plan)
        if port is None:
            return None

        service = self._normalize_service_name(self._service_name_from_plan(plan))
        service_key = self._service_key(service)
        if service:
            plan["target"] = service

        if (
            not service
            or service_key in {
                "any", "service", "listener", "listening", "server", "something"
            }
            or self._looks_like_listener_without_service(user_input)
        ):
            return self._handle_unspecified_service_port_request(
                user_input, plan, port, t_start
            )

        if not self._service_unit_exists(service):
            return self._handle_missing_service_install(
                user_input, plan, service, t_start
            )

        if plan.get("intent") == "service_start":
            port_check = self._port_free_check(port)
            if port_check.get("status") == "conflict":
                if service_key != "nginx":
                    return self._handle_non_nginx_port_options(
                        user_input, plan, service, port, t_start, port_check
                    )
                return self._handle_port_conflict(
                    user_input, plan, service, port, port_check, t_start
                )
            if port_check.get("status") != "ok":
                if not self.quiet:
                    print(
                        f"  {dim('│')}  {red('[service port]')} "
                        f"I could not verify whether port {port} is free, "
                        "so I will not start anything there."
                    )
                    print(f"  {dim('└─')} {dim('No command was run.')}")
                self.memory.save(
                    user_input,
                    plan,
                    {"skipped": True, "port_check": port_check},
                )
                return {
                    "input": user_input,
                    "plan": plan,
                    "outcome": "error",
                    "total_ms": int((time.perf_counter() - t_start) * 1000),
                }

        if plan.get("intent") == "service_stop":
            if not self.quiet:
                print(
                    f"  {dim('│')}  {yellow('[service port]')} "
                    f"`systemctl stop {service}` stops the whole service; "
                    f"it cannot stop only port {port}."
                )
                print(
                    f"  {dim('│')}  To remove a listening port, edit the "
                    f"service config and reload it."
                )
                print(f"  {dim('└─')} {dim('No command was run.')}")
            self.memory.save(user_input, plan, {"skipped": True})
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "not_applicable",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        if service_key != "nginx":
            return self._handle_non_nginx_port_options(
                user_input, plan, service, port, t_start
            )

        configured_ports = self._nginx_configured_ports()
        if port in configured_ports:
            return None

        return self._confirm_nginx_port_change(
            user_input, plan, port, configured_ports, t_start
        )

    def _nginx_configured_ports(self) -> list[int]:
        import glob
        import re

        paths = []
        for pattern in (
            "/etc/nginx/sites-enabled/*",
            "/etc/nginx/conf.d/*.conf",
        ):
            paths.extend(glob.glob(pattern))

        ports = set()
        for path in paths:
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            for match in re.finditer(
                r"^\s*listen\s+(?P<value>[^;#]+)",
                content,
                re.MULTILINE,
            ):
                value = match.group("value")
                for token in value.split():
                    token = token.strip()
                    found = re.search(
                        r"(?:(?:\[[^\]]+\]|[\d.]+):)?(?P<port>\d{1,5})$",
                        token,
                    )
                    if found:
                        port = int(found.group("port"))
                        if 1 <= port <= 65535:
                            ports.add(port)

        return sorted(ports) or [80]

    def _format_ports(self, ports: list[int]) -> str:
        if not ports:
            return "unknown"
        if len(ports) == 1:
            return str(ports[0])
        return ", ".join(str(p) for p in ports)

    def _confirm_nginx_port_change(self, user_input: str, plan: dict,
                                   port: int, configured_ports: list[int],
                                   t_start: float) -> dict:
        ports_text = self._format_ports(configured_ports)
        if not self.quiet:
            print(
                f"  {dim('│')}  nginx's port is set in its config, "
                f"not via systemctl."
            )
            print(
                f"  {dim('│')}  It is currently configured for port "
                f"{ports_text}. To run it on {port} I'd need to add "
                f"`listen {port};` in nginx config and reload."
            )
            print(
                f"  {dim('│')}  nginx can listen on many ports; if `ss` "
                f"shows two entries for one port, that is often IPv4 and "
                f"IPv6 sockets for one server."
            )

        if not getattr(self, "_interactive", True):
            if not self.quiet:
                print(f"  {dim('└─')} {dim('No command was run.')}")
            self.memory.save(user_input, plan, {"skipped": True})
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "cancelled",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        stdin = getattr(sys, "stdin", None)
        if not stdin or not stdin.isatty():
            if not self.quiet:
                print(f"  {dim('└─')} {dim('No command was run.')}")
            self.memory.save(user_input, plan, {"skipped": True})
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "cancelled",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        if not self.quiet and hasattr(self, "alert_queue"):
            self.alert_queue.flush()

        try:
            print(
                f"  {dim('│')}  Do you want me to configure nginx for "
                f"port {port}? [y/N]"
            )
            answer = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""

        if answer not in {"y", "yes"}:
            if not self.quiet:
                print(f"  {dim('└─')} {yellow('Cancelled.')}")
            self.memory.save(user_input, plan, {"cancelled": True})
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "cancelled",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        ok, message = self._configure_nginx_port(port)
        if ok:
            if hasattr(self, "state"):
                try:
                    self.state.refresh()
                except Exception:
                    pass
            self._remember_service_port("nginx", port, "service_start")
        if not self.quiet:
            colour = green if ok else red
            print(f"  {dim('│')}  {colour(message)}")
            print(f"  {dim('└─')} {dim('nginx port configuration finished.')}")

        self.memory.save(
            user_input,
            plan,
            {"nginx_port_configured": ok, "port": port, "message": message},
        )
        return {
            "input": user_input,
            "plan": plan,
            "outcome": "success" if ok else "error",
            "total_ms": int((time.perf_counter() - t_start) * 1000),
        }

    def _configure_nginx_port(self, port: int) -> tuple[bool, str]:
        conf_dir = "/etc/nginx/conf.d"
        conf_path = f"{conf_dir}/linxai-{port}.conf"
        content = (
            "# Managed by LINxAI.\n"
            "server {\n"
            f"    listen {port};\n"
            f"    listen [::]:{port};\n"
            "    server_name _;\n"
            "    location / {\n"
            f"        return 200 \"LINxAI nginx listener on port {port}\\n\";\n"
            "        add_header Content-Type text/plain;\n"
            "    }\n"
            "}\n"
        )

        mkdir = self._run_root_command(["mkdir", "-p", conf_dir])
        if mkdir.returncode != 0:
            return False, self._command_failure("create nginx conf.d", mkdir)

        write = self._run_root_command(["tee", conf_path], input_text=content)
        if write.returncode != 0:
            return False, self._command_failure("write nginx drop-in", write)

        test = self._run_root_command(["nginx", "-t"])
        if test.returncode != 0:
            self._rollback_nginx_dropin(conf_path)
            return False, (
                "nginx config test failed; rolled back the drop-in. "
                f"{self._command_output(test)}"
            )

        was_active = self._service_is_active("nginx")
        action = "reload" if was_active else "start"
        action_result = self._run_root_command(["systemctl", action, "nginx"])
        if action_result.returncode != 0:
            self._rollback_nginx_dropin(conf_path)
            return False, (
                f"nginx {action} failed; rolled back the drop-in. "
                f"{self._command_output(action_result)}"
            )

        if not self._port_is_listening(port):
            self._rollback_nginx_dropin(conf_path)
            if not was_active:
                self._run_root_command(["systemctl", "stop", "nginx"])
            return False, (
                f"nginx {action}ed, but port {port} was not visible in ss; "
                "rolled back the drop-in."
            )

        return True, (
            f"Configured nginx to listen on port {port} and {action}ed it."
        )

    def _service_is_active(self, service: str) -> bool:
        result = self._run_root_command(
            ["systemctl", "is-active", "--quiet", service],
            timeout=5,
        )
        return result.returncode == 0

    def _run_root_command(self, args: list[str], input_text: str | None = None,
                          timeout: int = 20):
        import subprocess
        from types import SimpleNamespace

        command = list(args)
        geteuid = getattr(os, "geteuid", None)
        if callable(geteuid) and geteuid() != 0:
            command = ["sudo"] + command

        try:
            return subprocess.run(
                command,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except Exception as e:
            return SimpleNamespace(returncode=1, stdout="", stderr=str(e))

    def _rollback_nginx_dropin(self, conf_path: str):
        self._run_root_command(["rm", "-f", conf_path])
        test = self._run_root_command(["nginx", "-t"])
        if test.returncode == 0 and self._service_is_active("nginx"):
            self._run_root_command(["systemctl", "reload", "nginx"])

    def _port_is_listening(self, port: int) -> bool:
        import re
        import subprocess

        try:
            result = subprocess.run(
                ["ss", "-tln"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except Exception:
            return False
        if result.returncode != 0:
            return False
        return re.search(rf":{port}\b", result.stdout) is not None

    def _command_output(self, result) -> str:
        text = (getattr(result, "stderr", "") or getattr(result, "stdout", ""))
        return " ".join(text.strip().split())[:180]

    def _command_failure(self, action: str, result) -> str:
        detail = self._command_output(result)
        if detail:
            return f"Could not {action}: {detail}"
        return f"Could not {action}."

    def _verify_file_create_result(self, plan: dict) -> str | None:
        if plan.get("intent") != "file_create":
            return None

        path = str(plan.get("target", "")).strip()
        kind = str(plan.get("file_create_kind", "")).strip()
        if not path:
            kind, path = self._infer_file_create_target(
                str(plan.get("command", ""))
            )
        if not path:
            return "File create command completed, but I could not determine the path to verify."

        if kind != "directory":
            kind = "file"

        flag = "-d" if kind == "directory" else "-f"
        if not self._test_created_path(flag, path):
            return f"Could not confirm that {kind} {path} was created."

        if kind == "directory":
            summary = f"Created directory {path}."
            note = str(plan.get("file_create_location_note", "") or "").strip()
            return f"{note} {summary}".strip()

        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        summary = f"Created file {path} ({size} bytes)."
        note = str(plan.get("file_create_location_note", "") or "").strip()
        return f"{note} {summary}".strip()

    def _resolve_file_create_location(self, user_input: str, plan: dict,
                                      t_start: float) -> dict | None:
        if plan.get("intent") != "file_create":
            return None

        from executor.command_builder import resolve_file_create_location

        resolution = resolve_file_create_location(plan)
        if resolution.get("status") != "ambiguous":
            return None

        choices = resolution.get("choices", []) or []
        if not getattr(self, "_interactive", True):
            if not self.quiet:
                print(f"  {dim('│')}  {yellow('[needs input]')} "
                      "Multiple matching folders were found:")
                for idx, choice in enumerate(choices, start=1):
                    print(f"  {dim('│')}    [{idx}] {choice}")
                print(f"  {dim('└─')} No file was created.")
            self.memory.save(user_input, plan, {"skipped": True})
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "error",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        stdin = getattr(sys, "stdin", None)
        if not stdin or not stdin.isatty():
            self.memory.save(user_input, plan, {"skipped": True})
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "error",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        if not self.quiet and hasattr(self, "alert_queue"):
            self.alert_queue.flush()

        if not self.quiet:
            print(f"  {dim('│')}  Multiple folders named "
                  f"{plan.get('location', 'that')} were found:")
            for idx, choice in enumerate(choices, start=1):
                print(f"  {dim('│')}    [{idx}] {choice}")
            print(f"  {dim('│')}    [0] Cancel")

        try:
            answer = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "0"

        if answer in {"0", "c", "cancel", ""}:
            if not self.quiet:
                print(f"  {dim('└─')} Cancelled - no file was created.")
            self.memory.save(user_input, plan, {"skipped": True})
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "cancelled",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        try:
            selected = choices[int(answer) - 1]
        except (ValueError, IndexError):
            if not self.quiet:
                print(f"  {dim('└─')} Invalid choice - no file was created.")
            self.memory.save(user_input, plan, {"skipped": True})
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "error",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        plan["location"] = selected
        plan["file_create_location_note"] = f"Using existing folder {selected}."
        plan.pop("file_create_location_ambiguous", None)
        plan.pop("file_create_location_choices", None)
        return None

    def _test_created_path(self, flag: str, path: str) -> bool:
        import subprocess

        try:
            result = subprocess.run(
                ["test", flag, path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            return result.returncode == 0
        except Exception:
            if flag == "-d":
                return os.path.isdir(path)
            return os.path.isfile(path)

    def _infer_file_create_target(self, command: str) -> tuple[str, str]:
        import re
        import shlex

        try:
            parts = shlex.split(command or "", posix=True)
        except ValueError:
            parts = (command or "").split()

        for idx, part in enumerate(parts[:-1]):
            if part in {">", ">>", "1>", "1>>"}:
                return "file", parts[idx + 1]

        for part in parts:
            match = re.match(r"^(?:1?>|1?>>)(.+)$", part)
            if match:
                return "file", match.group(1)

        if "touch" in parts:
            idx = parts.index("touch")
            candidates = [p for p in parts[idx + 1:] if not p.startswith("-")]
            if candidates:
                return "file", candidates[-1]

        if "mkdir" in parts:
            idx = parts.index("mkdir")
            candidates = [p for p in parts[idx + 1:] if not p.startswith("-")]
            if candidates:
                return "directory", candidates[-1]

        return "", ""

    def _env_setup_step_plan(self, step: dict, intent: str = "env_setup") -> dict:
        return {
            "intent": intent,
            "target": "",
            "pre_conditions": [],
            "command": step.get("command", ""),
            "requires_sudo": False,
            "risk_level": "medium" if intent == "env_setup" else "low",
            "rollback": "",
            "explanation": step.get("description", "Environment setup step."),
        }

    def _result_success(self, result) -> bool:
        return hasattr(result, "is_success") and result.is_success()

    def _short_result_failure(self, result) -> str:
        stderr = getattr(result, "stderr", "") or ""
        stdout = getattr(result, "stdout", "") or ""
        for text in (stderr, stdout):
            for line in text.splitlines():
                line = line.strip()
                if line:
                    return line
        status = getattr(result, "status", "error")
        rc = getattr(result, "return_code", -1)
        return f"{status} (exit {rc})"

    def _record_env_setup_output(self, outputs: list[str], result):
        command = getattr(result, "command", "")
        stdout = getattr(result, "stdout", "") or ""
        stderr = getattr(result, "stderr", "") or ""
        chunk = [f"$ {command}"] if command else []
        if stdout:
            chunk.append(stdout)
        if stderr:
            chunk.append(stderr)
        if chunk:
            outputs.append("\n".join(chunk))
            raw = "\n\n".join(outputs)
            self.last_output = raw
            self._last_output = raw

    def _env_step_produces(self, step: dict) -> set:
        produces = step.get("produces", "")
        if isinstance(produces, (list, tuple, set)):
            return {str(item) for item in produces if str(item)}
        return {str(produces)} if produces else set()

    def _env_step_requires(self, step: dict) -> set:
        requires = step.get("requires", [])
        if isinstance(requires, str):
            return {requires} if requires else set()
        return {str(item) for item in requires if str(item)}

    def _env_step_record(self, result, step: dict, phase: str) -> dict:
        record = result.to_dict() if hasattr(result, "to_dict") else dict(result)
        record["step_id"] = step.get("id", "")
        record["step_description"] = step.get("description", "")
        record["phase"] = phase
        return record

    def _run_env_check(self, step: dict, outputs: list[str], step_records: list):
        check = (step.get("check") or "").strip()
        if not check:
            return True, None
        check_step = {
            "id": f"{step.get('id', 'step')}_check",
            "description": f"Check: {step.get('description', '')}",
            "command": check,
            "produces": "",
            "requires": [],
            "check": "",
            "on_fail": step.get("on_fail", ""),
        }
        check_result = self.executor.execute(
            self._env_setup_step_plan(check_step, intent="raw")
        )
        self._record_env_setup_output(outputs, check_result)
        if hasattr(self, "hub"):
            self.hub.execution(
                check_result.to_dict()
                if hasattr(check_result, "to_dict")
                else check_result
            )
        step_records.append(self._env_step_record(check_result, step, "check"))
        return self._result_success(check_result), check_result

    def _known_env_fix_capability(self, step: dict, result) -> str:
        stderr = getattr(result, "stderr", "") or ""
        stdout = getattr(result, "stdout", "") or ""
        text = " ".join([
            step.get("id", ""),
            step.get("description", ""),
            " ".join(self._env_step_produces(step)),
            stderr,
            stdout,
        ]).lower()

        if any(token in text for token in (
            "npm: not found", "npx: not found", "node: not found",
            "npm: command not found", "npx: command not found",
            "node: command not found",
        )):
            return "npm"
        if any(token in text for token in (
            "git: not found", "git: command not found",
        )):
            return "git"
        if any(token in text for token in (
            "pip3: not found", "pip3: command not found",
        )):
            return "pip3"
        if "python3 -m venv" in text or "ensure_python_venv" in text:
            return "python_venv_tool"

        for cap in self._env_step_produces(step):
            if self._fix_task_capability(cap):
                return cap
        return ""

    def _env_fix_check(self, capability: str) -> str:
        return {
            "npm": "node -v >/dev/null 2>&1 && npm -v >/dev/null 2>&1",
            "node": "node -v >/dev/null 2>&1",
            "nodejs": "node -v >/dev/null 2>&1",
            "npx": "npx --version >/dev/null 2>&1",
            "git": "which git >/dev/null 2>&1",
            "pip3": "which pip3 >/dev/null 2>&1",
            "python_venv_tool": "python3 -m venv --help >/dev/null 2>&1",
        }.get(capability, "")

    def _run_env_fix(self, capability: str, outputs: list[str],
                     step_records: list) -> bool:
        command = self._fix_task_capability(capability)
        if not command:
            return False
        if not self.quiet:
            print(f"  {dim('│')}    Attempting prerequisite fix: {capability}")

        fix_step = {
            "id": f"fix_{capability}",
            "description": f"Fix prerequisite: {capability}",
            "command": command,
            "check": self._env_fix_check(capability),
            "produces": capability,
            "requires": [],
            "on_fail": f"Install or repair {capability}, then retry setup.",
        }
        result = self.executor.execute(self._env_setup_step_plan(fix_step))
        self._record_env_setup_output(outputs, result)
        if hasattr(self, "hub"):
            self.hub.execution(
                result.to_dict() if hasattr(result, "to_dict") else result
            )
        step_records.append(self._env_step_record(result, fix_step, "fix"))
        if not self._result_success(result):
            if not self.quiet:
                print(f"  {dim('│')}    {red('Fix failed:')} "
                      f"{self._short_result_failure(result)}")
            return False

        ok, check_result = self._run_env_check(fix_step, outputs, step_records)
        if not ok and not self.quiet:
            print(f"  {dim('│')}    {red('Fix did not verify:')} "
                  f"{self._short_result_failure(check_result)}")
        return ok

    def _dependent_step_numbers(self, steps: list, start_idx: int,
                                capabilities: set) -> list[int]:
        deps = []
        for offset, later in enumerate(steps[start_idx:], start=start_idx + 1):
            if self._env_step_requires(later) & capabilities:
                deps.append(offset)
        return deps

    def _ask_env_failure_action(self, idx: int, steps: list, step: dict,
                                result, failed_caps: set,
                                fix_capability: str) -> str:
        dependents = self._dependent_step_numbers(steps, idx, failed_caps)
        if not self.quiet:
            print(f"  {dim('│')}    {red('Step failed:')} "
                  f"{self._short_result_failure(result)}")
            if dependents:
                nums = ", ".join(str(num) for num in dependents)
                print(
                    f"  {dim('│')}    Step {idx} failed; dependent steps "
                    f"({nums}) cannot succeed until this is fixed."
                )
            suggestion = step.get("on_fail", "")
            if suggestion:
                print(f"  {dim('│')}    {suggestion}")

        if not getattr(self, "_interactive", True):
            return "abort"
        stdin = getattr(sys, "stdin", None)
        if not stdin or not stdin.isatty():
            return "abort"
        if not self.quiet and hasattr(self, "alert_queue"):
            self.alert_queue.flush()

        try:
            if fix_capability:
                print(f"  {dim('│')}    Options:")
                print(f"  {dim('│')}      [1] Retry this step")
                print(
                    f"  {dim('│')}      [2] Let me fix the prerequisite "
                    f"({fix_capability}) and continue"
                )
                print(f"  {dim('│')}      [3] Abort")
                answer = input("> ").strip().lower()
                return {
                    "1": "retry",
                    "retry": "retry",
                    "2": "fix",
                    "fix": "fix",
                    "3": "abort",
                    "abort": "abort",
                }.get(answer, "abort")

            print(f"  {dim('│')}    Options:")
            print(f"  {dim('│')}      [1] Retry this step")
            print(f"  {dim('│')}      [2] Abort")
            answer = input("> ").strip().lower()
            return {
                "1": "retry",
                "retry": "retry",
                "2": "abort",
                "abort": "abort",
            }.get(answer, "abort")
        except (EOFError, KeyboardInterrupt):
            return "abort"

    def _env_probe(self, command: str) -> str:
        import subprocess

        try:
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
        except Exception:
            return "unknown"
        value = (result.stdout or "").strip().splitlines()
        return value[0].strip() if result.returncode == 0 and value else "unknown"

    def _env_path_hint(self, plan: dict, steps: list) -> str:
        path = str(plan.get("path", "") or "").strip()
        if path:
            return path
        for step in steps:
            desc = step.get("description", "")
            if " under " in desc:
                return desc.rsplit(" under ", 1)[-1]
            if " into " in desc:
                return desc.rsplit(" into ", 1)[-1]
            if " at " in desc:
                return desc.rsplit(" at ", 1)[-1]
        return "."

    def _env_python_venv_path(self, plan: dict, steps: list) -> str:
        path = str(plan.get("path", "") or "").strip()
        if path:
            return f"{path.rstrip('/') or '.'}/venv"
        for step in steps:
            if step.get("id") == "create_python_venv":
                desc = step.get("description", "")
                if " at " in desc:
                    return desc.rsplit(" at ", 1)[-1]
        return "./venv"

    def _env_cap_label(self, capability: str) -> str:
        return {
            "npm": "node/npm verification",
            "mern_dirs": "MERN directories",
            "server_deps": "server dependencies",
            "client_scaffold": "React client scaffold",
            "git": "git installation",
            "repo": "repository clone",
            "repo_deps": "repository dependencies",
            "python_venv_tool": "python3-venv",
            "python_venv": "Python virtual environment",
            "pip_ready": "pip in the virtual environment",
        }.get(capability, capability)

    def _env_final_message(self, plan: dict, steps: list,
                           satisfied: set, failures: list[str]) -> tuple[bool, str]:
        required = set()
        for step in steps:
            required |= self._env_step_produces(step)
        missing = sorted(required - satisfied)
        path = self._env_path_hint(plan, steps)

        if not missing and not failures:
            if {"npm", "server_deps", "client_scaffold"} <= satisfied:
                node_ver = self._env_probe("node -v")
                npm_ver = self._env_probe("npm -v")
                return True, (
                    f"Environment ready at {path}: node {node_ver}, "
                    f"npm {npm_ver}, server deps installed, client scaffolded."
                )
            if {"repo", "repo_deps"} <= satisfied:
                return True, (
                    f"Environment ready at {path}: repository cloned and "
                    f"dependencies verified."
                )
            if {"python_venv", "pip_ready"} <= satisfied:
                venv_path = self._env_python_venv_path(plan, steps)
                pip_ver = self._env_probe(f"{venv_path}/bin/python -m pip --version")
                return True, (
                    f"Environment ready at {venv_path}: Python virtual environment "
                    f"created, {pip_ver}."
                )
            return True, f"Environment ready at {path}."

        failed_labels = [self._env_cap_label(cap) for cap in missing]
        failed_labels.extend(failures)
        if not failed_labels:
            failed_labels = ["one or more verification checks"]
        next_step = "Fix the failed prerequisite, then rerun this setup."
        return False, (
            "Setup INCOMPLETE - the following did not succeed: "
            f"{', '.join(dict.fromkeys(failed_labels))}. {next_step}"
        )

    def _run_env_setup(self, user_input: str, plan: dict, t_start: float) -> dict:
        steps = self._plan_task("env_setup", plan)
        if not steps:
            if not self.quiet:
                print(f"  {dim('│')}  {yellow('[planner]')} "
                      "No deterministic setup recipe matched this request.")
                print(f"  {dim('└─')} {dim('No command was run.')}")
            self.memory.save(user_input, plan, {"skipped": True})
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "unknown",
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        outputs: list[str] = []
        step_records = []
        satisfied = set()
        failures: list[str] = []
        if not self.quiet:
            print(f"  {dim('│')}  {green('[2/3] PLANNED')} "
                  f"{len(steps)} ordered step(s)")

        for idx, step in enumerate(steps, start=1):
            required = self._env_step_requires(step)
            missing_required = required - satisfied
            if missing_required:
                labels = ", ".join(
                    self._env_cap_label(cap) for cap in sorted(missing_required)
                )
                failures.append(
                    f"{step.get('description', 'setup step')} skipped "
                    f"(missing {labels})"
                )
                if not self.quiet:
                    print(f"  {dim('│')}  [step {idx}/{len(steps)}] "
                          f"{step.get('description', 'Run setup step')}")
                    print(f"  {dim('│')}    {red('Skipped:')} "
                          f"missing prerequisite {labels}")
                break

            auto_fix_tried = False
            while True:
                if not self.quiet:
                    print(f"  {dim('│')}  [step {idx}/{len(steps)}] "
                          f"{step.get('description', 'Run setup step')}")

                step_plan = self._env_setup_step_plan(step)
                result = self.executor.execute(step_plan)
                self._record_env_setup_output(outputs, result)
                if hasattr(self, "hub"):
                    self.hub.execution(
                        result.to_dict()
                        if hasattr(result, "to_dict")
                        else result
                    )
                step_records.append(self._env_step_record(result, step, "command"))

                step_ok = self._result_success(result)
                check_result = None
                if step_ok:
                    step_ok, check_result = self._run_env_check(
                        step, outputs, step_records
                    )

                if step_ok:
                    satisfied |= self._env_step_produces(step)
                    if not self.quiet:
                        print(f"  {dim('│')}    {green('ok')}")
                    break

                failure_result = check_result or result
                produced = self._env_step_produces(step)
                failed_caps = produced or {step.get("id", "step")}
                fix_cap = self._known_env_fix_capability(step, failure_result)

                if fix_cap and not auto_fix_tried:
                    auto_fix_tried = True
                    fixed = self._run_env_fix(fix_cap, outputs, step_records)
                    if fixed:
                        if not self.quiet:
                            print(f"  {dim('│')}    Retrying step after fix.")
                        continue

                action = self._ask_env_failure_action(
                    idx, steps, step, failure_result, failed_caps, fix_cap
                )
                if action == "retry":
                    continue
                if action == "fix" and fix_cap:
                    fixed = self._run_env_fix(fix_cap, outputs, step_records)
                    if fixed:
                        continue

                failures.append(
                    f"{step.get('description', 'setup step')} failed"
                )
                final_ok, final_message = self._env_final_message(
                    plan, steps, satisfied, failures
                )
                total_ms = int((time.perf_counter() - t_start) * 1000)
                self.memory.save(
                    user_input,
                    plan,
                    {
                        "env_setup": True,
                        "steps": step_records,
                        "satisfied": sorted(satisfied),
                        "status": "success" if final_ok else "incomplete",
                    },
                )
                if not self.quiet:
                    print(f"  {dim('└─')} {yellow(final_message)} "
                          f"{dim(f'total={total_ms}ms')}")
                return {
                    "input": user_input,
                    "plan": plan,
                    "result": {"steps": step_records, "satisfied": sorted(satisfied)},
                    "outcome": "success" if final_ok else "error",
                    "total_ms": total_ms,
                }

        total_ms = int((time.perf_counter() - t_start) * 1000)
        final_ok, final_message = self._env_final_message(
            plan, steps, satisfied, failures
        )
        self.memory.save(
            user_input,
            plan,
            {
                "env_setup": True,
                "steps": step_records,
                "satisfied": sorted(satisfied),
                "status": "success" if final_ok else "incomplete",
            },
        )
        if not self.quiet:
            colour = green if final_ok else yellow
            print(f"  {dim('└─')} {colour(final_message)} "
                  f"{dim(f'total={total_ms}ms')}")
        return {
            "input": user_input,
            "plan": plan,
            "result": {"steps": step_records, "satisfied": sorted(satisfied)},
            "outcome": "success" if final_ok else "error",
            "total_ms": total_ms,
        }

    def _print_success_result(self, plan: dict, result, exec_ms: int):
        print(f"\r  {dim('│')}  {green('[3/3] SUCCESS')}  "
              f"exit={result.return_code}  {dim(f'{exec_ms}ms')}")

        raw_output = result.stdout or ""
        self.last_output = raw_output
        self._last_output = raw_output

        file_create_summary = self._verify_file_create_result(plan)
        if file_create_summary is not None:
            print(f"  {dim('│')}    {file_create_summary}")
            return

        output_summary = self._analyze_output(
            plan.get("intent", ""),
            getattr(result, "command", plan.get("command", "")),
            raw_output,
            result.stderr or "",
            result.return_code,
        )
        if output_summary is not None:
            print(f"  {dim('│')}    {output_summary}")
            return

        if not raw_output:
            note = (result.stderr or "").splitlines()
            if note:
                print(f"  {dim('│')}    {note[-1]}")
            return

        lines = raw_output.split("\n")
        shown = min(8, len(lines))
        for line in lines[:shown]:
            print(f"  {dim('│')}    {line}")
        indicator = (
            f"(showing {shown} of {len(lines)} lines — "
            f"type 'details' for full output)"
        )
        print(f"  {dim('│')}    {dim(indicator)}")

    def _print_failure_result(self, plan: dict, result):
        status = getattr(result, "status", "error")
        rc = getattr(result, "return_code", -1)
        stderr = getattr(result, "stderr", "") or ""
        stdout = getattr(result, "stdout", "") or ""
        raw_detail = "\n".join(part for part in (stdout, stderr) if part)
        self.last_output = raw_detail
        self._last_output = raw_detail

        colour_fn = red if status != "warn" else yellow
        print(f"\r  {dim('│')}  {colour_fn(f'[3/3] {status.upper()}')}  "
              f"exit={rc}")

        command = getattr(result, "command", plan.get("command", ""))
        advice = self._diagnose_failure(
            plan.get("intent", ""),
            command,
            stderr,
            rc,
            self.state,
        )
        if advice:
            print(f"  {dim('│')}    {advice['explanation']}")
            print(f"  {dim('│')}    {advice['suggestion']}")
            suggested = advice.get("suggested_command")
            if suggested and advice.get("needs_confirit"):
                if not getattr(self, "_interactive", True):
                    return
                stdin = getattr(sys, "stdin", None)
                if not stdin or not stdin.isatty():
                    return
                if not self.quiet and hasattr(self, "alert_queue"):
                    self.alert_queue.flush()
                try:
                    print(f"  {dim('│')}    Run this instead? [y/N]: {suggested}")
                    answer = input("> ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    answer = ""
                if answer in ("y", "yes"):
                    self._run_suggested_command(plan, suggested)
                else:
                    print(f"  {dim('│')}    Cancelled.")
            return

        first_line = stderr.splitlines()[0] if stderr.splitlines() else ""
        if first_line:
            print(f"  {dim('│')}    Command failed: {first_line}")
        else:
            print(f"  {dim('│')}    Command failed.")
        details_hint = "Type 'details' for full output."
        print(f"  {dim('│')}    {dim(details_hint)}")

    def _run_suggested_command(self, original_plan: dict, suggested_command: str):
        retry_plan = dict(original_plan)
        retry_plan["command"] = suggested_command
        if suggested_command.strip().startswith("sudo "):
            retry_plan["requires_sudo"] = True

        t_start = time.perf_counter()
        n_checks = len(retry_plan.get("pre_conditions", []))
        print(f"  {dim('│')}    {dim(f'[retry] Validating {n_checks} checks...')}",
              end="", flush=True)

        validation = self.cie.validate(retry_plan)
        self.hub.validation(retry_plan, validation)
        decision = validation.get("decision") or validation.get("result", "block")
        if decision not in {"approve", "warn"}:
            print(f"\r  {dim('│')}    {red('[retry] BLOCKED')}  "
                  f"{validation.get('reason', 'Validation did not approve this operation.')[:80]}")
            self.memory.save(suggested_command, retry_plan, {"blocked": True})
            return

        print(f"\r  {dim('│')}    {green('[retry] APPROVED')}  "
              f"{validation['reason'][:60]}")
        print(f"  {dim('│')}    {dim('[retry] Executing...')}",
              end="", flush=True)

        result = self.executor.execute(retry_plan)
        exec_ms = int((time.perf_counter() - t_start) * 1000)
        self.hub.execution(result.to_dict() if hasattr(result, "to_dict")
                           else result)
        self._record_successful_service_context(retry_plan, result)
        self.memory.save(
            suggested_command,
            retry_plan,
            result.to_dict() if hasattr(result, "to_dict") else result,
        )

        if hasattr(result, "is_success") and result.is_success():
            self._print_success_result(retry_plan, result, exec_ms)
        else:
            self._print_failure_result(retry_plan, result)

    def process(self, user_input: str) -> dict:
        t_start = time.perf_counter()
        user_input = user_input.strip()

        if not self.quiet:
            print(f"\n  {dim('┌─')} {cyan(user_input)}")

        if self.chat.is_social(user_input):
            response = self.chat.respond(user_input)
            should_exit = self.chat.should_exit(user_input)
            plan = {
                "intent": "chat",
                "target": "",
                "pre_conditions": [],
                "command": "",
                "requires_sudo": False,
                "risk_level": "low",
                "rollback": "",
                "explanation": "Social response.",
            }
            if not self.quiet:
                print(f"  {dim('│')}")
                for line in response.split("\n"):
                    print(f"  {dim('│')}  {line}")
                print(f"  {dim('└─')} {dim('─────────────────────────────────────────')}")
            self.memory.save(user_input, plan, {"skipped": True, "intent": "chat"})
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "exit" if should_exit else "chat",
                "should_exit": should_exit,
                "total_ms": int((time.perf_counter() - t_start) * 1000),
            }

        contextual_port = self._handle_contextual_port_query(user_input, t_start)
        if contextual_port is not None:
            return contextual_port

        # ── Step 1: AI Engine ─────────────────────────────────────────────────
        t1 = time.perf_counter()
        if not self.quiet:
            print(f"  {dim('│')}  {dim('[1/3] Classifying...')}",
                  end="", flush=True)
        try:
            context = self.memory.get_recent()
            self._classifying = True
            try:
                plan = self.ai.classify(user_input, context)
            finally:
                self._classifying = False
        except Exception as e:
            if not self.quiet:
                print(f"\r  {dim('│')}  {red('[1/3] AI Engine failed:')} {e}")
            return {"input": user_input, "plan": {}, "validation": {},
                    "result": None, "total_ms": 0, "outcome": "error"}

        ai_ms = int((time.perf_counter() - t1) * 1000)
        self.hub.ai(user_input, plan)

        if not self.quiet:
            print(f"\r  {dim('│')}  {green('[1/3]')} "
                  f"intent={bold(plan.get('intent','?'))}  "
                  f"cmd={dim(plan.get('command','?')[:50])}  "
                  f"{dim(f'{ai_ms}ms')}")

        if plan.get("intent") == "not_applicable":
            if not self.quiet:
                msg = self.chat.not_applicable_response(
                    plan.get("explanation", ""),
                    plan.get("suggestion", ""),
                )
                print(f"  {dim('│')}  {yellow('[not applicable]')} {msg}")
                print(f"  {dim('└─')} {dim('No command was run.')}")
            self.memory.save(user_input, plan, {"skipped": True})
            return {
                "input": user_input,
                "plan": plan,
                "outcome": "not_applicable",
            }

        # ── eBPF feedback loop ────────────────────────────────────────────────
        if hasattr(self, "memory") and self.memory.has_recent_security_alerts():
            alerts = self.memory.get_security_alerts(last_n=3)
            if not self.quiet:
                print(f"  {dim('│')}  {yellow('⚠ SECURITY CONTEXT:')} "
                      f"eBPF detected {len(alerts)} suspicious kernel "
                      f"event(s) this session")
                for alert in alerts[:2]:
                    et = alert.get("event_type", "?")
                    p  = alert.get("payload", {})
                    if et == "network_connect":
                        print(f"  {dim('│')}    {dim('→')} outbound connect: "
                              f"{p.get('dest_ip','?')}:{p.get('dest_port','?')} "
                              f"by {p.get('process','?')}")
                    elif et == "file_open":
                        print(f"  {dim('│')}    {dim('→')} sensitive file: "
                              f"{p.get('filename','?')} "
                              f"by {p.get('process','?')}")
                    elif et == "process_exec":
                        print(f"  {dim('│')}    {dim('→')} suspicious process: "
                              f"{p.get('process','?')} "
                              f"pid={p.get('pid','?')}")

        # ── Chat + Unknown intent handlers ────────────────────────────────────
        if plan.get("intent") == "unknown":
            if not self.quiet:
                msg = plan.get("explanation", "I did not understand that as a Linux admin command.")
                print(f"  {dim('│')}  {yellow('[?]')} {msg}")
                print(f"  {dim('└─')} {dim('Try: restart nginx | check disk | show memory | list processes')}")
            self.memory.save(user_input, plan, {"skipped": True})
            return {"input": user_input, "plan": plan, "outcome": "unknown"}

        if plan.get("intent") == "chat":
            if not self.quiet:
                response = self.chat.respond(user_input)
                print(f"  {dim('│')}")
                for line in response.split("\n"):
                    print(f"  {dim('│')}  {line}")
                print(f"  {dim('└─')} {dim('─────────────────────────────────────────')}")
            self.memory.save(user_input, plan, {"skipped": True})
            return {"input": user_input, "plan": plan, "outcome": "chat"}

        if plan.get("intent") == "env_setup":
            return self._run_env_setup(user_input, plan, t_start)

        service_port_result = self._handle_service_port_request(
            user_input, plan, t_start
        )
        if service_port_result is not None:
            return service_port_result

        file_create_resolution = self._resolve_file_create_location(
            user_input, plan, t_start
        )
        if file_create_resolution is not None:
            return file_create_resolution

        # ── Step 2: CIE ───────────────────────────────────────────────────────
        t2 = time.perf_counter()
        n_checks = len(plan.get("pre_conditions", []))
        if not self.quiet:
            print(f"  {dim('│')}  {dim(f'[2/3] Validating {n_checks} checks...')}",
                  end="", flush=True)

        validation = self.cie.validate(plan)
        cie_ms     = int((time.perf_counter() - t2) * 1000)
        self.hub.validation(plan, validation)
        decision   = validation.get("decision") or validation.get("result", "block")

        if decision not in {"approve", "warn"}:
            if not self.quiet:
                print(f"\r  {dim('│')}  {red('[2/3] BLOCKED')}  "
                      f"{validation.get('reason', 'Validation did not approve this operation.')[:80]}  {dim(f'{cie_ms}ms')}")
                print(f"  {dim('└─')} {red('BLOCKED — command will not execute')}")
            self.memory.save(user_input, plan, {"blocked": True})
            return {"input": user_input, "plan": plan,
                    "validation": validation, "result": None,
                    "total_ms": int((time.perf_counter() - t_start) * 1000),
                    "outcome": "blocked"}
        else:
            colour = yellow if decision == "warn" else green
            label  = "WARNING" if decision == "warn" else "APPROVED"
            if not self.quiet:
                print(f"\r  {dim('│')}  {colour(f'[2/3] {label}')}  "
                      f"{validation['reason'][:60]}  {dim(f'{cie_ms}ms')}")

        # ── Sensitive path authentication ─────────────────────────────────────
        SENSITIVE_PATHS = ("/etc/", "/etc ", "/etc'", "/var/", "/bin/",
                           "/usr/", "/root/", "/boot/", "/lib/", "/sbin/")
        cmd_str = plan.get("command", "")
        is_sensitive = any(p in cmd_str for p in SENSITIVE_PATHS)
        if is_sensitive and not plan.get("requires_sudo", False):
            if not self.quiet:
                print(f"  {dim('│')}")
                print(f"  {dim('│')}  {yellow('⚠ SENSITIVE PATH DETECTED')}")
                print(f"  {dim('│')}  This command targets a protected system path.")
                print(f"  {dim('│')}  Enter sudo password to continue or press Enter to cancel:")
            import getpass
            try:
                pwd = getpass.getpass(f"  {dim('│')}  Password: ")
            except (KeyboardInterrupt, EOFError):
                pwd = ""
            if not pwd.strip():
                if not self.quiet:
                    print(f"  {dim('└─')} {yellow('Cancelled — no password provided.')}")
                self.memory.save(user_input, plan, {"cancelled": True})
                return {"input": user_input, "plan": plan, "outcome": "cancelled"}
            import subprocess as _sp
            check = _sp.run(
                ["sudo", "-S", "-v"],
                input=pwd + "\n",
                capture_output=True,
                text=True
            )
            if check.returncode != 0:
                if not self.quiet:
                    print(f"  {dim('└─')} {red('Authentication failed — command blocked.')}")
                self.memory.save(user_input, plan, {"auth_failed": True})
                return {"input": user_input, "plan": plan, "outcome": "auth_failed"}
            if not self.quiet:
                print(f"  {dim('│')}  {green('✓ Authenticated')}")

        # ── Step 3: Execute ───────────────────────────────────────────────────
        t3 = time.perf_counter()
        if not self.quiet:
            print(f"  {dim('│')}  {dim('[3/3] Executing...')}",
                  end="", flush=True)

        result  = self.executor.execute(plan)
        exec_ms = int((time.perf_counter() - t3) * 1000)
        self.hub.execution(result.to_dict() if hasattr(result, "to_dict")
                           else result)
        self._record_successful_service_context(plan, result)
        self.memory.save(user_input, plan,
                         result.to_dict() if hasattr(result, "to_dict")
                         else result)
        total_ms = int((time.perf_counter() - t_start) * 1000)

        if not self.quiet:
            if hasattr(result, "is_success") and result.is_success():
                self._print_success_result(plan, result, exec_ms)
            else:
                self._print_failure_result(plan, result)

            speed = (green if total_ms < 5000
                     else yellow if total_ms < 10000 else red)
            summary = (result.summary() if hasattr(result, "summary")
                       else str(getattr(result, "status", "unknown")))
            print(f"  {dim('└─')} {summary}  total={speed(f'{total_ms}ms')}")

        return {"input": user_input, "plan": plan,
                "validation": validation,
                "result": (result.to_dict() if hasattr(result, "to_dict")
                           else result),
                "total_ms": total_ms,
                "outcome": getattr(result, "status", "unknown")}

    def _show_status(self):
        """Show current status of all modules."""
        print()
        print(bold("  LINxAI Module Status"))
        print()

        if self._ebpf_daemon:
            stats = self._ebpf_daemon.get_stats()
            total = sum(stats.values())
            print(f"  {green('●')} eBPF Daemon   running  "
                  f"events={total} "
                  f"(exec:{stats['execve']} "
                  f"net:{stats['connect']} "
                  f"file:{stats['openat']})")
        else:
            print(f"  {dim('○')} eBPF Daemon   not running")

        if self._resource_mgr:
            s = self._resource_mgr.get_stats()
            print(f"  {green('●')} Resources     running  "
                  f"CPU:{s['cpu_pct']:.1f}%  "
                  f"RAM:{s['memory_pct']:.1f}%  "
                  f"reniced:{s['renice_count']}")
        else:
            print(f"  {dim('○')} Resources     not running")

        stats = self.audit.get_stats()
        print(f"  {green('●')} Audit Log     "
              f"{stats['total_records']} records  "
              f"{stats['file_size_kb']}KB  "
              f"{stats['log_path']}")

        alerts = self.memory.get_security_alerts(last_n=10)
        if alerts:
            print(f"  {yellow('⚠')} Security      "
                  f"{len(alerts)} kernel alert(s) this session")
        else:
            print(f"  {green('●')} Security      no alerts this session")
        if hasattr(self, 'threat_responder'):
            stats = self.threat_responder.get_stats()
            if stats["total_responses"] > 0:
                print(f"  {yellow('⚡')} Auto-Response  "
                      f"{stats['successful_kills']} process(es) terminated "
                      f"this session")
        print()

    def run_interactive(self):
        if not getattr(self, "_readline_configured", False):
            self._readline_configured = True
            try:
                import atexit
                import readline

                histfile = os.path.expanduser("~/.linxai_history")
                try:
                    readline.read_history_file(histfile)
                except FileNotFoundError:
                    pass
                readline.set_history_length(1000)
                atexit.register(readline.write_history_file, histfile)
            except ImportError:
                pass

        try:
            while True:
                try:
                    if not self.quiet:
                        self.alert_queue.flush()
                    user_input = input("\n  linxai> ").strip()
                except EOFError:
                    break

                if not user_input:
                    continue

                if user_input.lower() in ("exit", "quit", "q"):
                    break

                if user_input.lower() in ("details", "more"):
                    if not self._last_output:
                        print(f"\n  {yellow('⚠')} No command output to show yet.")
                    else:
                        print()
                        for line in self._last_output.split("\n"):
                            print(f"  {line}")
                    continue

                if user_input.lower() == "logs":
                    records = self.audit.query_session(last_n=10)
                    print(f"\n  {bold('Recent audit records:')}")
                    for r in records:
                        ts = r["timestamp"][11:19]
                        print(f"  {dim(ts)}  "
                              f"[{r['module']:<12}]  "
                              f"{r['event_type']}")
                    continue

                if user_input.lower() == "stats":
                    stats = self.audit.get_stats()
                    print(f"\n  Records: {stats['total_records']}  "
                          f"Size: {stats['file_size_kb']}KB")
                    if stats.get("by_module"):
                        for mod, cnt in sorted(
                            stats["by_module"].items(),
                            key=lambda x: x[1], reverse=True
                        ):
                            print(f"    {mod:<16} {cnt}")
                    continue

                if user_input.lower() == "status":
                    self._show_status()
                    continue

                if user_input.lower() == "help":
                    print(dim("\n  Commands: any Linux task in plain English"))
                    print(dim("  Special:  logs | stats | status | details | explain | exit"))
                    continue

                # ── Output saver ──────────────────────────────────────────────
                import re as _re
                _save_match = _re.match(
                    r'^save\s+(?:that|this|last\s+output|output|it)?\s*to\s+(.+)$',
                    user_input.lower().strip()
                )
                if not _save_match:
                    _save_match = _re.match(
                        r'^save\s+to\s+(.+)$',
                        user_input.lower().strip()
                    )
                if _save_match:
                    raw_path = user_input.strip()
                    raw_path = _re.sub(
                        r'^save\s+(?:that|this|last\s+output|output|it)?\s*to\s+',
                        '', raw_path, flags=_re.IGNORECASE
                    ).strip()
                    raw_path = _re.sub(
                        r'^save\s+to\s+', '', raw_path, flags=_re.IGNORECASE
                    ).strip()
                    save_path = os.path.expanduser(raw_path)
                    if not self.last_output:
                        print(f"\n  {yellow('⚠')} No output to save yet. Run a command first.")
                    else:
                        try:
                            os.makedirs(os.path.dirname(save_path) if os.path.dirname(save_path) else '.', exist_ok=True)
                            with open(save_path, 'w') as _f:
                                _f.write(self.last_output)
                            size = len(self.last_output.encode())
                            print(f"\n  {green('✓')} Saved to {save_path} ({size} bytes)")
                        except Exception as _e:
                            print(f"\n  {red('✗')} Could not save: {_e}")
                    continue

                # ── Explain mode ──────────────────────────────────────────────
                if any(phrase in user_input.lower() for phrase in (
                    "what just happened", "what happened", "explain logs",
                    "what did you do", "show me what happened", "explain"
                )):
                    print(f"\n  {dim('Reading audit log...')}", flush=True)
                    records = self.audit.tail(20)
                    print(f"  {dim('Asking AI to explain...')}", flush=True)
                    explanation = self.ai.explain_audit_log(records)
                    print()
                    print(f"  {bold('LINxAI explains:')}")
                    print()
                    for line in explanation.split("\n"):
                        print(f"  {line}")
                    print()
                    continue

                try:
                    result = self.process(user_input)
                except Exception as e:
                    tb = traceback.format_exc()
                    if hasattr(self, "audit"):
                        try:
                            self.audit.log(
                                "ui",
                                "process_exception",
                                {
                                    "input": user_input,
                                    "error": str(e),
                                    "traceback": tb,
                                },
                                level="ERROR",
                            )
                        except Exception:
                            logger.error(
                                "Unhandled interactive command error: %s",
                                e,
                            )
                    else:
                        logger.error("Unhandled interactive command error: %s", e)
                    print(
                        "Something went wrong handling that command — "
                        "I'm still running. Try again or rephrase."
                    )
                    continue
                if result.get("should_exit"):
                    break

        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def shutdown(self):
        self.audit.log_system_stop()
        if self._ebpf_daemon:
            self._ebpf_daemon.stop()
        if self._resource_mgr:
            self._resource_mgr.stop()
        self.memory.close()
        self.cache.close()
        # state registry has no persistent connection to close
        if not self.quiet:
            print(f"\n  {dim('Session ended. Logs:')} "
                  f"{self.audit.log_path}\n")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="LINxAI — Intelligent Linux Administration Layer")
    parser.add_argument("--daemon",       action="store_true")
    parser.add_argument("--command",      type=str)
    parser.add_argument("--quiet",        action="store_true")
    parser.add_argument("--no-ebpf",      action="store_true")
    parser.add_argument("--no-resource",  action="store_true")
    parser.add_argument("--operation", type=str, help="Typed action through the shared operations service")
    parser.add_argument("--operation-params", type=str, help="JSON parameter object (default {})")
    parser.add_argument("--operations-workspace", type=str, help="Explicit permitted POSIX workspace")
    parser.add_argument("--operations-audit", type=str, help="Audit JSONL in an owned private directory")
    args = parser.parse_args(argv)
    if args.operation is not None and (args.command is not None or args.daemon):
        parser.error("--operation cannot be combined with --command or --daemon")
    if args.operation is None and any(value is not None for value in
            (args.operation_params, args.operations_workspace, args.operations_audit)):
        parser.error("operation options require --operation")
    return args


def main(argv=None):
    args = parse_args(argv)
    if args.operation is not None:
        from operations.cli import run_request
        return run_request(args.operation, args.operation_params if args.operation_params is not None else "{}",
                           args.operations_workspace, args.operations_audit)
    if sys.platform == "linux" and (os.getuid() == 0 or os.geteuid() != os.getuid()):
        print("Run LINxAI as an ordinary user without sudo or setuid identity.", file=sys.stderr)
        return 2
    pipeline = LINxAIPipeline(
        use_face_auth=False,
        quiet=args.quiet or args.daemon,
        enable_ebpf=not args.no_ebpf,
        enable_resource=not args.no_resource,
    )

    if args.command:
        pipeline._interactive = False
        result = pipeline.process(args.command)
        print(result.get("outcome", "unknown"))
        pipeline.shutdown()

    elif args.daemon:
        print(f"[LINxAI] Daemon running. PID={os.getpid()}")
        print("[LINxAI] For interactive use: python3 main.py")
        try:
            signal.pause()
        except KeyboardInterrupt:
            pipeline.shutdown()

    else:
        pipeline.run_interactive()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
