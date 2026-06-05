# main.py
# LINxAI — Main pipeline entry point.
# Terminal interface only. No web app. No GUI.
# AI Engine → CIE → Executor → Audit Logger
# Optional: eBPF daemon, Resource Manager, VPS Manager

import os
import sys
import time
import logging
import argparse
import signal
import threading

logging.basicConfig(level=logging.ERROR,
                    format="%(levelname)s [%(name)s] %(message)s")

logger = logging.getLogger(__name__)


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
        "resource": {"cpu_threshold_pct": 80.0, "poll_interval_s": 1.0},
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
        self.quiet = quiet
        self.cfg   = _read_config()
        self._ebpf_daemon    = None
        self._resource_mgr   = None

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
        from logger.audit import AuditLogger
        from logger.integration import LoggingHub

        log_path      = self.cfg["logging"]["log_path"]
        self.hub      = LoggingHub(log_path=log_path)
        self.audit    = self.hub.audit
        self.memory   = ContextMemory(max_context=5)
        from ai.cache import CommandCache
        self.cache    = CommandCache()
        self.ai       = AIEngine(cache=self.cache)
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
                        is_suspicious = False

                        # Credential access — always suspicious
                        if event_type == "file_open":
                            fname = payload.get("filename", "")
                            if any(s in fname for s in [
                                "/etc/shadow", "/etc/sudoers", "/root/.ssh",
                                "/proc/keys", "id_rsa", "authorized_keys"
                            ]):
                                is_suspicious = True

                        # Outbound connection to unusual port
                        elif event_type == "network_connect":
                            try:
                                port = int(payload.get("dest_port", 0) or 0)
                            except Exception:
                                port = 0
                            # Whitelist: common ports + Ollama (11434)
                            if port not in (
                                80, 443, 53, 22, 8080, 8443, 11434
                            ):
                                is_suspicious = True

                        # Known attack tools spawned
                        elif event_type == "process_exec":
                            proc = payload.get("process", "")
                            # Only flag genuinely suspicious tools
                            if any(s in proc for s in [
                                "nc", "ncat", "netcat",
                                "perl", "ruby", "socat",
                                "telnet", "msfconsole",
                            ]):
                                is_suspicious = True

                        if is_suspicious:
                            self.memory.save_security_alert(record)

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
                    poll_interval=res_cfg.get("poll_interval_s", 1.0),
                    log_callback=self.hub.resource_callback,
                )
                self._resource_mgr.start()
                if not quiet:
                    print(f"  {green('✓')} Resources    — CPU monitor active")
            except Exception as e:
                if not quiet:
                    print(f"  {yellow('⚠')} Resources    — unavailable ({e})")

        if not quiet:
            print()
            print(dim("  Type a Linux command in plain English. "
                      "Type 'exit' to quit."))
            print(dim("  Special: logs | stats | status | explain | help | exit"))
            print()

    def process(self, user_input: str) -> dict:
        t_start = time.perf_counter()
        user_input = user_input.strip()

        if not self.quiet:
            print(f"\n  {dim('┌─')} {cyan(user_input)}")

        # ── Step 1: AI Engine ─────────────────────────────────────────────────
        t1 = time.perf_counter()
        if not self.quiet:
            print(f"  {dim('│')}  {dim('[1/3] Classifying...')}",
                  end="", flush=True)
        try:
            context = self.memory.get_recent()
            plan    = self.ai.classify(user_input, context)
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
                print(f"  {dim('│')}  {yellow('[chat]')} {plan.get('explanation', 'How can I help?')}")
                print(f"  {dim('└─')} {dim('Chat mode coming soon — for now try a Linux command')}")
            self.memory.save(user_input, plan, {"skipped": True})
            return {"input": user_input, "plan": plan, "outcome": "chat"}

        # ── Step 2: CIE ───────────────────────────────────────────────────────
        t2 = time.perf_counter()
        n_checks = len(plan.get("pre_conditions", []))
        if not self.quiet:
            print(f"  {dim('│')}  {dim(f'[2/3] Validating {n_checks} checks...')}",
                  end="", flush=True)

        validation = self.cie.validate(plan)
        cie_ms     = int((time.perf_counter() - t2) * 1000)
        self.hub.validation(plan, validation)
        decision   = validation.get("decision") or validation.get("result", "approve")

        if decision == "block":
            if not self.quiet:
                print(f"\r  {dim('│')}  {red('[2/3] BLOCKED')}  "
                      f"{validation['reason'][:80]}  {dim(f'{cie_ms}ms')}")
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

        # ── Step 3: Execute ───────────────────────────────────────────────────
        t3 = time.perf_counter()
        if not self.quiet:
            print(f"  {dim('│')}  {dim('[3/3] Executing...')}",
                  end="", flush=True)

        result  = self.executor.execute(plan)
        exec_ms = int((time.perf_counter() - t3) * 1000)
        self.hub.execution(result.to_dict() if hasattr(result, "to_dict")
                           else result)
        self.memory.save(user_input, plan,
                         result.to_dict() if hasattr(result, "to_dict")
                         else result)
        total_ms = int((time.perf_counter() - t_start) * 1000)

        if not self.quiet:
            if hasattr(result, "is_success") and result.is_success():
                print(f"\r  {dim('│')}  {green('[3/3] SUCCESS')}  "
                      f"exit={result.return_code}  {dim(f'{exec_ms}ms')}")
                if result.stdout:
                    for line in result.stdout.split("\n")[:8]:
                        print(f"  {dim('│')}    {line}")
            else:
                status = getattr(result, "status", "error")
                rc     = getattr(result, "return_code", -1)
                err    = getattr(result, "stderr", "")[:80]
                colour_fn = red if status != "warn" else yellow
                print(f"\r  {dim('│')}  {colour_fn(f'[3/3] {status.upper()}')}  "
                      f"exit={rc}  {err}")

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
        print()

    def run_interactive(self):
        try:
            while True:
                try:
                    user_input = input(
                        f"\n  {bold('linxai>')} "
                    ).strip()
                except EOFError:
                    break

                if not user_input:
                    continue

                if user_input.lower() in ("exit", "quit", "q"):
                    break

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
                    print(dim("  Special:  logs | stats | status | explain | exit"))
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

                self.process(user_input)

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
        if not self.quiet:
            print(f"\n  {dim('Session ended. Logs:')} "
                  f"{self.audit.log_path}\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="LINxAI — Intelligent Linux Administration Layer")
    parser.add_argument("--daemon",       action="store_true")
    parser.add_argument("--command",      type=str)
    parser.add_argument("--quiet",        action="store_true")
    parser.add_argument("--no-ebpf",      action="store_true")
    parser.add_argument("--no-resource",  action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    args     = parse_args()
    pipeline = LINxAIPipeline(
        use_face_auth=False,
        quiet=args.quiet or args.daemon,
        enable_ebpf=not args.no_ebpf,
        enable_resource=not args.no_resource,
    )

    if args.command:
        result = pipeline.process(args.command)
        print(result.get("outcome", "unknown"))
        pipeline.shutdown()

    elif args.daemon:
        print(f"[LINxAI] Daemon running. PID={os.getpid()}")
        print("[LINxAI] For interactive use: sudo python3 main.py")
        try:
            signal.pause()
        except KeyboardInterrupt:
            pipeline.shutdown()

    else:
        pipeline.run_interactive()