# ai/cache.py
# LINxAI Command Cache — stores AI classification results to avoid
# repeated Ollama calls for the same input. CIE validation and
# security checks always run live regardless of cache hits.

import sqlite3
import json
import os
import re
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# 30 pre-warmed common commands — instant from day one
PREWARMED = [
    ("check disk space",       {"intent":"disk_usage","target":"","pre_conditions":[],"command":"df -h --exclude-type=fuse.sshfs","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows disk usage."}),
    ("show disk usage",        {"intent":"disk_usage","target":"","pre_conditions":[],"command":"df -h --exclude-type=fuse.sshfs","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows disk usage."}),
    ("how much disk space",    {"intent":"disk_usage","target":"","pre_conditions":[],"command":"df -h --exclude-type=fuse.sshfs","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows disk usage."}),
    ("show memory usage",      {"intent":"memory_usage","target":"","pre_conditions":[],"command":"free -m","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows memory usage."}),
    ("check memory",           {"intent":"memory_usage","target":"","pre_conditions":[],"command":"free -m","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows memory usage."}),
    ("how much memory",        {"intent":"memory_usage","target":"","pre_conditions":[],"command":"free -m","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows memory usage."}),
    ("show cpu usage",         {"intent":"cpu_usage","target":"","pre_conditions":[],"command":"top -bn1 | grep Cpu","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows CPU usage."}),
    ("check cpu",              {"intent":"cpu_usage","target":"","pre_conditions":[],"command":"top -bn1 | grep Cpu","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows CPU usage."}),
    ("list processes",         {"intent":"process_list","target":"","pre_conditions":[],"command":"ps aux","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Lists running processes."}),
    ("show running processes", {"intent":"process_list","target":"","pre_conditions":[],"command":"ps aux","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Lists running processes."}),
    ("list open ports",        {"intent":"port_list","target":"","pre_conditions":[],"command":"ss -tlnp","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Lists listening ports."}),
    ("show open ports",        {"intent":"port_list","target":"","pre_conditions":[],"command":"ss -tlnp","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Lists listening ports."}),
    ("check open ports",       {"intent":"port_list","target":"","pre_conditions":[],"command":"ss -tlnp","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Lists listening ports."}),
    ("show system uptime",     {"intent":"system_uptime","target":"","pre_conditions":[],"command":"uptime -p","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows system uptime."}),
    ("how long running",       {"intent":"system_uptime","target":"","pre_conditions":[],"command":"uptime -p","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows system uptime."}),
    ("show system info",       {"intent":"system_info","target":"","pre_conditions":[],"command":"uname -a","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows system information."}),
    ("show kernel version",    {"intent":"kernel_info","target":"","pre_conditions":[],"command":"uname -r","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows kernel version."}),
    ("list users",             {"intent":"user_list","target":"","pre_conditions":[],"command":"cat /etc/passwd","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Lists system users."}),
    ("show users",             {"intent":"user_list","target":"","pre_conditions":[],"command":"cat /etc/passwd","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Lists system users."}),
    ("show firewall rules",    {"intent":"firewall_list","target":"","pre_conditions":[],"command":"ufw status verbose","requires_sudo":True,"risk_level":"low","rollback":"","explanation":"Shows firewall rules."}),
    ("check firewall",         {"intent":"firewall_list","target":"","pre_conditions":[],"command":"ufw status verbose","requires_sudo":True,"risk_level":"low","rollback":"","explanation":"Shows firewall rules."}),
    ("show network interfaces",{"intent":"network_interfaces","target":"","pre_conditions":[],"command":"ip addr show","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows network interfaces."}),
    ("what is my ip",          {"intent":"network_interfaces","target":"","pre_conditions":[],"command":"ip addr show","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows IP addresses."}),
    ("show ip address",        {"intent":"network_interfaces","target":"","pre_conditions":[],"command":"ip addr show","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows IP addresses."}),
    ("restart nginx",          {"intent":"service_restart","target":"nginx","pre_conditions":[{"check":"service_exists","service":"nginx"}],"command":"systemctl restart nginx","requires_sudo":True,"risk_level":"medium","rollback":"systemctl stop nginx","explanation":"Restarts nginx."}),
    ("stop nginx",             {"intent":"service_stop","target":"nginx","pre_conditions":[{"check":"service_exists","service":"nginx"}],"command":"systemctl stop nginx","requires_sudo":True,"risk_level":"medium","rollback":"systemctl start nginx","explanation":"Stops nginx."}),
    ("start nginx",            {"intent":"service_start","target":"nginx","pre_conditions":[{"check":"port_free","port":80},{"check":"service_exists","service":"nginx"}],"command":"systemctl start nginx","requires_sudo":True,"risk_level":"medium","rollback":"systemctl stop nginx","explanation":"Starts nginx."}),
    ("nginx status",           {"intent":"service_status","target":"nginx","pre_conditions":[{"check":"service_exists","service":"nginx"}],"command":"systemctl status nginx","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows nginx status."}),
    ("show nginx status",      {"intent":"service_status","target":"nginx","pre_conditions":[{"check":"service_exists","service":"nginx"}],"command":"systemctl status nginx","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Shows nginx status."}),
    ("list installed packages",{"intent":"package_list","target":"","pre_conditions":[],"command":"dpkg --list","requires_sudo":False,"risk_level":"low","rollback":"","explanation":"Lists installed packages."}),
]

# Never cache inputs containing these — they are context-dependent
SKIP_CACHE_PATTERNS = [
    r'\d+',          # contains numbers (PIDs, ports)
    r'\bit\b',       # pronoun "it"
    r'\bthat\b',     # pronoun "that"
    r'\bthis\b',     # pronoun "this"
    r'\bhim\b',      # pronoun
    r'\bher\b',      # pronoun
    r'\bthem\b',     # pronoun
]


class CommandCache:

    def __init__(self, db_path: str = "~/.linxai/context.db"):
        self.db_path = os.path.expanduser(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_schema()
        self._prewarm()
        logger.info("Command cache ready")

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS command_cache (
                input_normalized TEXT PRIMARY KEY,
                plan             TEXT NOT NULL,
                hit_count        INTEGER DEFAULT 0,
                created_at       TEXT NOT NULL,
                last_used        TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def _prewarm(self):
        now = datetime.utcnow().isoformat() + "Z"
        inserted = 0
        for raw_input, plan in PREWARMED:
            normalized = self.normalize(raw_input)
            try:
                self.conn.execute(
                    """INSERT OR IGNORE INTO command_cache
                       (input_normalized, plan, hit_count, created_at, last_used)
                       VALUES (?, ?, 0, ?, ?)""",
                    (normalized, json.dumps(plan), now, now)
                )
                inserted += 1
            except Exception as e:
                logger.error(f"Prewarm insert failed for '{raw_input}': {e}")
        self.conn.commit()
        logger.info(f"Cache prewarm complete — {inserted} entries ready")

    def normalize(self, user_input: str) -> str:
        text = user_input.lower().strip()
        text = re.sub(r'\s+', ' ', text)
        return text

    def should_cache(self, normalized: str) -> bool:
        for pattern in SKIP_CACHE_PATTERNS:
            if re.search(pattern, normalized):
                return False
        return True

    def get(self, user_input: str):
        normalized = self.normalize(user_input)
        if not self.should_cache(normalized):
            return None
        try:
            cur = self.conn.execute(
                "SELECT plan FROM command_cache WHERE input_normalized = ?",
                (normalized,)
            )
            row = cur.fetchone()
            if row:
                self.conn.execute(
                    """UPDATE command_cache
                       SET hit_count = hit_count + 1,
                           last_used = ?
                       WHERE input_normalized = ?""",
                    (datetime.utcnow().isoformat() + "Z", normalized)
                )
                self.conn.commit()
                return json.loads(row[0])
        except Exception as e:
            logger.error(f"Cache get failed: {e}")
        return None

    def store(self, user_input: str, plan: dict):
        normalized = self.normalize(user_input)
        if not self.should_cache(normalized):
            return
        if plan.get("intent") in ("unknown", "chat"):
            return
        try:
            now = datetime.utcnow().isoformat() + "Z"
            self.conn.execute(
                """INSERT OR REPLACE INTO command_cache
                   (input_normalized, plan, hit_count, created_at, last_used)
                   VALUES (?, ?, 0, ?, ?)""",
                (normalized, json.dumps(plan), now, now)
            )
            self.conn.commit()
            logger.info(f"Cached: '{normalized}'")
        except Exception as e:
            logger.error(f"Cache store failed: {e}")

    def stats(self) -> dict:
        try:
            cur = self.conn.execute(
                "SELECT COUNT(*), SUM(hit_count) FROM command_cache"
            )
            row = cur.fetchone()
            return {
                "total_cached": row[0] or 0,
                "total_hits": row[1] or 0
            }
        except Exception:
            return {"total_cached": 0, "total_hits": 0}

    def close(self):
        self.conn.close()
