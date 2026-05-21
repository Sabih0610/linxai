# logger/cli.py
import sys
import os
import json
import time
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from logger.audit import AuditLogger, LOG_PATH_DEFAULT


def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

def green(t):  return _c("32", t)
def yellow(t): return _c("33", t)
def cyan(t):   return _c("36", t)
def dim(t):    return _c("2",  t)
def bold(t):   return _c("1",  t)

MODULE_COLOURS = {
    "ai_engine": cyan,
    "cie":       yellow,
    "executor":  green,
    "ebpf":      lambda t: _c("35", t),
    "system":    dim,
}


def format_record(record: dict) -> str:
    ts       = record.get("timestamp", "")[:19].replace("T", " ")
    module   = record.get("module", "?")
    event    = record.get("event_type", "?")
    payload  = record.get("payload", {})
    session  = record.get("session_id", "")[:8]
    colour_fn = MODULE_COLOURS.get(module, lambda t: t)
    mod_str  = colour_fn(f"[{module:<10}]")
    summary_parts = []
    for key in ["intent", "decision", "status", "command", "text", "user_input", "reason"]:
        val = payload.get(key)
        if val:
            summary_parts.append(f"{dim(key)}={str(val)[:50]}")
            if len(summary_parts) >= 2:
                break
    summary = "  ".join(summary_parts)
    lines = [f"  {dim(ts)}  {dim('['+session+']')}  {mod_str}  {bold(event)}"]
    if summary:
        lines.append(f"    {summary}")
    return "\n".join(lines)


def cmd_show(args):
    audit = AuditLogger()
    records = audit.query(module=args.module, event_type=args.event,
                          session_id=args.session, last_n=args.last)
    if not records:
        print(dim("  No records found."))
        return
    print()
    print(bold(f"  LINxAI Audit Log — {len(records)} records"))
    print()
    for record in records:
        print(format_record(record))
    print()


def cmd_stats(args):
    audit = AuditLogger()
    stats = audit.get_stats()
    print()
    print(bold("  LINxAI Audit Log — Statistics"))
    print(f"  File:          {stats['log_path']}")
    print(f"  Total records: {bold(str(stats['total_records']))}")
    print(f"  File size:     {stats['file_size_kb']} KB")
    if stats.get("by_module"):
        print()
        for module, count in sorted(stats["by_module"].items(),
                                     key=lambda x: x[1], reverse=True):
            fn = MODULE_COLOURS.get(module, lambda t: t)
            print(f"    {fn(f'{module:<12}')}  {'█' * min(count, 30)}  {count}")
    print()


def cmd_follow(args):
    print(bold("  LINxAI Audit Log — Live Feed"))
    print(dim(f"  Following {LOG_PATH_DEFAULT}"))
    print(dim("  Press Ctrl+C to stop\n"))
    last_size = 0
    try:
        while True:
            if os.path.exists(LOG_PATH_DEFAULT):
                current_size = os.path.getsize(LOG_PATH_DEFAULT)
                if current_size > last_size:
                    with open(LOG_PATH_DEFAULT, "r", encoding="utf-8") as f:
                        f.seek(last_size)
                        for line in f.readlines():
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                record = json.loads(line)
                                if args.module and record.get("module") != args.module:
                                    continue
                                print(format_record(record))
                            except Exception:
                                pass
                    last_size = current_size
            time.sleep(0.25)
    except KeyboardInterrupt:
        print(dim("\n  Stopped."))


def main():
    parser = argparse.ArgumentParser(description="LINxAI audit log viewer")
    parser.add_argument("--module",  help="filter by module")
    parser.add_argument("--event",   help="filter by event type")
    parser.add_argument("--session", help="filter by session UUID")
    parser.add_argument("--last",    type=int, default=20)
    parser.add_argument("--stats",   action="store_true")
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--follow",  action="store_true")
    args = parser.parse_args()

    if args.stats or args.summary:
        cmd_stats(args)
    elif args.follow:
        cmd_follow(args)
    else:
        cmd_show(args)


if __name__ == "__main__":
    main()