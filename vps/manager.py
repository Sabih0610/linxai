# vps/manager.py
# LINxAI VPS Manager
#
# Connects to remote Ubuntu/VPS servers using Paramiko SSH.
# Runs commands remotely and returns structured JSON-style results.
#
# Phase 10 test target:
#   local-vm = same Multipass VM through SSH on 127.0.0.1
#
# Run standalone:
#   python3 vps/manager.py
#
# Test:
#   python3 vps/test_vps.py

import os
import time
import shlex
import socket
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

import paramiko
import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "/opt/linxai/config/servers.yaml"
DEFAULT_TIMEOUT = 20

FORBIDDEN_PATTERNS = [
    "rm -rf /",
    "rm -rf /*",
    "mkfs",
    "dd if=",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "init 0",
    "init 6",
    ":(){",
    "chmod -r 777 /",
    "chmod -R 777 /",
    "chown -r",
    "chown -R",
    "> /dev/sda",
    "wipefs",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


try:
    from .server_types import VPSServer
except ImportError:
    from server_types import VPSServer


class VPSManager:
    """
    LINxAI VPS Manager.

    Responsibilities:
    - Load remote server config from YAML
    - Connect through SSH using Paramiko
    - Execute safe remote commands
    - Return structured command results
    - Support single-server and multi-server execution
    """

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH, log_callback=None):
        self.config_path = config_path
        self.log_callback = log_callback
        self.servers: Dict[str, VPSServer] = {}
        self._clients: Dict[str, paramiko.SSHClient] = {}

        self.load_config()

    def _log(self, event_type: str, payload: dict):
        if self.log_callback:
            try:
                self.log_callback(event_type, payload)
            except Exception as e:
                logger.error(f"VPS log callback failed: {e}")

    def load_config(self):
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(
                f"VPS config not found: {self.config_path}. "
                f"Create config/servers.yaml first."
            )

        with open(self.config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        servers = raw.get("servers", {})

        if not servers:
            raise ValueError("No servers found in config/servers.yaml")

        self.servers = {}

        for name, cfg in servers.items():
            self.servers[name] = VPSServer(
                name=name,
                host=cfg["host"],
                port=int(cfg.get("port", 22)),
                username=cfg["username"],
                key_path=os.path.expanduser(cfg["key_path"]),
                description=cfg.get("description", ""),
                tags=cfg.get("tags", []),
            )

    def list_servers(self) -> List[dict]:
        return [
            {
                "name": server.name,
                "host": server.host,
                "port": server.port,
                "username": server.username,
                "description": server.description,
                "tags": server.tags or [],
            }
            for server in self.servers.values()
        ]

    def get_server(self, name: str) -> VPSServer:
        if name not in self.servers:
            raise KeyError(f"Unknown VPS server: {name}")
        return self.servers[name]

    def _is_command_safe(self, command: str) -> tuple[bool, str]:
        normalized = command.strip().lower()

        for pattern in FORBIDDEN_PATTERNS:
            if pattern in normalized:
                return False, f"Forbidden remote command pattern detected: {pattern}"

        return True, "Command passed VPS safety guard"

    def connect(self, server_name: str) -> paramiko.SSHClient:
        if server_name in self._clients:
            return self._clients[server_name]

        server = self.get_server(server_name)

        if not os.path.exists(server.key_path):
            raise FileNotFoundError(f"SSH key not found: {server.key_path}")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=server.host,
                port=server.port,
                username=server.username,
                key_filename=server.key_path,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )

            self._clients[server_name] = client

            self._log("vps_connected", {
                "server": server_name,
                "host": server.host,
                "port": server.port,
                "username": server.username,
                "timestamp": _now(),
            })

            return client

        except Exception as e:
            self._log("vps_connection_failed", {
                "server": server_name,
                "host": server.host,
                "error": str(e),
                "timestamp": _now(),
            })
            raise ConnectionError(f"Failed to connect to {server_name}: {e}") from e

    def run_command(
        self,
        server_name: str,
        command: str,
        timeout: int = DEFAULT_TIMEOUT,
        sudo: bool = False,
    ) -> dict:
        safe, reason = self._is_command_safe(command)

        if not safe:
            result = {
                "server": server_name,
                "command": command,
                "status": "blocked",
                "exit_code": None,
                "stdout": "",
                "stderr": reason,
                "duration_ms": 0,
                "timestamp": _now(),
            }
            self._log("vps_command_blocked", result)
            return result

        server = self.get_server(server_name)
        start = time.time()

        try:
            client = self.connect(server_name)

            if sudo:
                remote_command = f"sudo -n bash -lc {shlex.quote(command)}"
            else:
                remote_command = f"bash -lc {shlex.quote(command)}"

            stdin, stdout, stderr = client.exec_command(
                remote_command,
                timeout=timeout,
                get_pty=False,
            )

            exit_code = stdout.channel.recv_exit_status()

            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()

            duration_ms = int((time.time() - start) * 1000)

            result = {
                "server": server_name,
                "host": server.host,
                "command": command,
                "remote_command": remote_command,
                "status": "success" if exit_code == 0 else "error",
                "exit_code": exit_code,
                "stdout": out,
                "stderr": err,
                "duration_ms": duration_ms,
                "timestamp": _now(),
            }

            self._log("vps_command_executed", result)
            return result

        except socket.timeout:
            duration_ms = int((time.time() - start) * 1000)

            result = {
                "server": server_name,
                "host": server.host,
                "command": command,
                "status": "timeout",
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Remote command timed out after {timeout}s",
                "duration_ms": duration_ms,
                "timestamp": _now(),
            }

            self._log("vps_command_timeout", result)
            return result

        except Exception as e:
            duration_ms = int((time.time() - start) * 1000)

            result = {
                "server": server_name,
                "host": server.host,
                "command": command,
                "status": "error",
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "duration_ms": duration_ms,
                "timestamp": _now(),
            }

            self._log("vps_command_error", result)
            return result

    def run_many(
        self,
        server_names: List[str],
        command: str,
        timeout: int = DEFAULT_TIMEOUT,
        sudo: bool = False,
    ) -> List[dict]:
        results = []

        for server_name in server_names:
            results.append(
                self.run_command(
                    server_name=server_name,
                    command=command,
                    timeout=timeout,
                    sudo=sudo,
                )
            )

        return results

    def health_check(self, server_name: str) -> dict:
        return self.run_command(
            server_name,
            "echo LINXAI_VPS_OK && hostname && uptime",
            timeout=10,
        )

    def check_disk(self, server_name: str) -> dict:
        return self.run_command(
            server_name,
            "df -h /",
            timeout=10,
        )

    def check_memory(self, server_name: str) -> dict:
        return self.run_command(
            server_name,
            "free -m",
            timeout=10,
        )

    def check_cpu(self, server_name: str) -> dict:
        return self.run_command(
            server_name,
            "top -bn1 | head -5",
            timeout=10,
        )

    def close(self, server_name: str):
        client = self._clients.pop(server_name, None)
        if client:
            client.close()

    def close_all(self):
        for name in list(self._clients.keys()):
            self.close(name)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s [%(name)s] %(message)s"
    )

    print("=" * 55)
    print("  LINxAI VPS Manager — Standalone Test")
    print("=" * 55)
    print()

    manager = VPSManager()

    print("Configured servers:")
    for server in manager.list_servers():
        print(
            f"  - {server['name']} "
            f"({server['username']}@{server['host']}:{server['port']})"
        )

    print()
    print("Running health check on local-vm...")

    result = manager.health_check("local-vm")

    print()
    print("Status:", result["status"])
    print("Exit code:", result["exit_code"])
    print("Duration:", result["duration_ms"], "ms")
    print("Output:")
    print(result["stdout"])

    if result["stderr"]:
        print("Error:")
        print(result["stderr"])

    manager.close_all()