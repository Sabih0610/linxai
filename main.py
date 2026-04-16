# main.py
# LINxAI — Main pipeline entry point.
# Terminal interface only. No web app. No GUI.
# AI Engine → CIE → Executor → Audit Logger

import os
import sys
import time
import logging
import argparse
import signal

logging.basicConfig(level=logging.WARNING,
                    format="%(levelname)s [%(name)s] %(message)s")


def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

def green(t):   return _c("32", t)
def yellow(t):  return _c("33", t)
def cyan(t):    return _c("36", t)
def red(t):     return _c("31", t)
def dim(t):     return _c("2",  t)
def bold(t):    return _c("1",  t)


class LINxAIPipeline:

    def __init__(self, use_face_auth: bool = False, quiet: bool = False):
        self.quiet = quiet

        if not quiet:
            print()
            print(bold("  LINxAI — Intelligent Linux Administration Layer"))
            print(dim("  Initialising modules..."))
            print()

        from ai.engine import AIEngine
        from ai.context import ContextMemory
        from cie.validator import CommandIntelligenceEngine
        from executor.controller import ExecutionController
        from logger.audit import AuditLogger

        self.audit    = AuditLogger()
        self.memory   = ContextMemory(max_context=5)
        self.ai       = AIEngine()
        self.cie      = CommandIntelligenceEngine(timeout_ms=500)
        self.executor = ExecutionController(use_face_auth=use_face_auth, timeout_s=30)

        self.audit.log_system_start()

        if not quiet:
            print(f"  {green('✓')} AI Engine    — Qwen2.5:1.5b via Ollama")
            print(f"  {green('✓')} CIE          — 20 system state checks")
            print(f"  {green('✓')} Executor     — subprocess + safety guard")
            print(f"  {green('✓')} Audit Logger — {self.audit.log_path}")
            print()
            print(dim("  Type a Linux command in plain English. Type 'exit' to quit."))
            print(dim("  Special commands: logs | stats | help | exit"))
            print()

    def process(self, user_input: str) -> dict:
        t_start = time.perf_counter()
        user_input = user_input.strip()

        if not self.quiet:
            print(f"\n  {dim('┌─')} {cyan(user_input)}")

        # Step 1: AI Engine
        t1 = time.perf_counter()
        if not self.quiet:
            print(f"  {dim('│')}  {dim('[1/3] Classifying...')}",
                  end="", flush=True)
        try:
            context = self.memory.get_recent()
            plan = self.ai.classify(user_input, context)
        except Exception as e:
            if not self.quiet:
                print(f"\r  {dim('│')}  {red('[1/3] AI Engine failed:')} {e}")
            return {"input": user_input, "plan": {}, "validation": {},
                    "result": None, "total_ms": 0, "outcome": "error"}

        ai_ms = int((time.perf_counter() - t1) * 1000)
        self.audit.log_ai_classification(user_input, plan, len(context))

        if not self.quiet:
            print(f"\r  {dim('│')}  {green('[1/3]')} "
                  f"intent={bold(plan.get('intent','?'))}  "
                  f"cmd={dim(plan.get('command','?')[:50])}  "
                  f"{dim(f'{ai_ms}ms')}")

        # Step 2: CIE
        t2 = time.perf_counter()
        n_checks = len(plan.get("pre_conditions", []))
        if not self.quiet:
            print(f"  {dim('│')}  {dim(f'[2/3] Validating {n_checks} checks...')}",
                  end="", flush=True)

        validation = self.cie.validate(plan)
        cie_ms = int((time.perf_counter() - t2) * 1000)
        self.audit.log_cie_result(validation)
        decision = validation["decision"]

        if decision == "block":
            if not self.quiet:
                print(f"\r  {dim('│')}  {red('[2/3] BLOCKED')}  "
                      f"{validation['reason'][:80]}  {dim(f'{cie_ms}ms')}")
                print(f"  {dim('└─')} {red('BLOCKED — command will not execute')}")
            self.memory.save(user_input, plan, {"blocked": True})
            return {"input": user_input, "plan": plan, "validation": validation,
                    "result": None,
                    "total_ms": int((time.perf_counter() - t_start) * 1000),
                    "outcome": "blocked"}
        else:
            colour = yellow if decision == "warn" else green
            label = "WARNING" if decision == "warn" else "APPROVED"
            if not self.quiet:
                print(f"\r  {dim('│')}  {colour(f'[2/3] {label}')}  "
                      f"{validation['reason'][:60]}  {dim(f'{cie_ms}ms')}")

        # Step 3: Execute
        t3 = time.perf_counter()
        if not self.quiet:
            print(f"  {dim('│')}  {dim('[3/3] Executing...')}",
                  end="", flush=True)

        result = self.executor.execute(plan)
        exec_ms = int((time.perf_counter() - t3) * 1000)
        self.audit.log_execution(result)
        self.memory.save(user_input, plan, result.to_dict())
        total_ms = int((time.perf_counter() - t_start) * 1000)

        if not self.quiet:
            if result.is_success():
                print(f"\r  {dim('│')}  {green('[3/3] SUCCESS')}  "
                      f"exit={result.return_code}  {dim(f'{exec_ms}ms')}")
                if result.stdout:
                    for line in result.stdout.split("\n")[:8]:
                        print(f"  {dim('│')}    {line}")
            elif result.status == "timeout":
                print(f"\r  {dim('│')}  {red('[3/3] TIMEOUT')}  exceeded 30s limit")
            else:
                print(f"\r  {dim('│')}  {red('[3/3] ERROR')}  "
                      f"exit={result.return_code}  {result.stderr[:80]}")

            speed = green if total_ms < 5000 else yellow if total_ms < 10000 else red
            print(f"  {dim('└─')} {result.summary()}  "
                  f"total={speed(f'{total_ms}ms')}")

        return {"input": user_input, "plan": plan, "validation": validation,
                "result": result.to_dict(), "total_ms": total_ms,
                "outcome": result.status}

    def run_interactive(self):
        try:
            while True:
                try:
                    user_input = input(f"\n  {bold('linxai>')} ").strip()
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
                        print(f"  {dim(ts)}  [{r['module']:<10}]  {r['event_type']}")
                    continue
                if user_input.lower() == "stats":
                    stats = self.audit.get_stats()
                    print(f"\n  Total records: {stats['total_records']} | "
                          f"Size: {stats['file_size_kb']}KB")
                    continue
                if user_input.lower() == "help":
                    print(dim("\n  Commands: any Linux task in plain English"))
                    print(dim("  Special:  logs | stats | exit"))
                    continue
                self.process(user_input)
        except KeyboardInterrupt:
            pass
        finally:
            self.audit.log_system_stop()
            if not self.quiet:
                print(f"\n  {dim('Session ended. Logs:')} {self.audit.log_path}\n")

    def shutdown(self):
        self.audit.log_system_stop()
        self.memory.close()


def parse_args():
    parser = argparse.ArgumentParser(
        description="LINxAI — Intelligent Linux Administration Layer")
    parser.add_argument("--daemon",  action="store_true",
                        help="Run as background daemon")
    parser.add_argument("--command", type=str,
                        help="Run a single command and exit")
    parser.add_argument("--quiet",   action="store_true",
                        help="Suppress pipeline output")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    pipeline = LINxAIPipeline(use_face_auth=False,
                               quiet=args.quiet or args.daemon)

    if args.command:
        result = pipeline.process(args.command)
        print(result.get("outcome", "unknown"))

    elif args.daemon:
        print(f"[LINxAI] Daemon running. PID={os.getpid()}")
        print("[LINxAI] For interactive use: sudo python3 main.py")
        signal.pause()

    else:
        pipeline.run_interactive()