# ai/chat.py
# LINxAI Chat Responder
# Handles conversational inputs using hybrid approach:
# - Rule-based fast path for greetings and system status (instant)
# - Ollama for complex how-to questions and Linux guidance

import requests
import logging

logger = logging.getLogger(__name__)

CAPABILITIES = """I can help you with:
  ● Service management    — start, stop, restart, check status of any service
  ● Process management    — list, kill, prioritize processes
  ● Port & network        — check ports, firewall rules, network status
  ● File operations       — create, delete, move, find files
  ● User management       — add, remove, list users
  ● Package management    — install, remove, update packages
  ● System monitoring     — CPU, memory, disk usage, uptime
  ● Security monitoring   — eBPF kernel events, threat detection
  ● Log analysis          — view, tail, search logs
  Just type what you need in plain English."""

IDENTITY = """I am LINxAI — an Intelligent Linux Administration Layer.
  Built by Sabih Aamir, Syed Muhammad Hassan, and Syed Naviyan Shahzad
  at MAJU, Karachi (FYP 2026).
  I combine natural language understanding with kernel-level security
  monitoring to make Linux administration safe and intuitive."""


class ChatResponder:

    def __init__(self, model: str = "qwen2.5:1.5b",
                 host: str = "http://localhost:11434",
                 state_registry=None):
        self.model = model
        self.host = host
        self.state = state_registry

    def respond(self, user_input: str) -> str:
        normalized = user_input.lower().strip()

        # ── Rule-based fast path ──────────────────────────────────────────────

        # Greetings
        if normalized in ("hello", "hi", "hey", "good morning",
                          "good evening", "good afternoon", "howdy",
                          "salaam", "salam", "assalamu alaikum"):
            return self._greeting()

        # How are you
        if any(p in normalized for p in ("how are you", "how r u", "you ok")):
            return self._greeting()

        # Identity
        if any(p in normalized for p in (
            "who are you", "what are you", "who built you",
            "who made you", "introduce yourself", "about you",
            "what is linxai", "tell me about yourself"
        )):
            return IDENTITY

        # Capabilities
        if any(p in normalized for p in (
            "what can you do", "help me", "capabilities",
            "what do you do", "how can you help", "features"
        )):
            return CAPABILITIES

        # System status
        if any(p in normalized for p in (
            "system status", "server status", "is my server healthy",
            "how is my server", "system health", "server health"
        )):
            return self._system_status()

        # What is running
        if any(p in normalized for p in (
            "what is running", "what's running", "whats running",
            "show running services", "active services"
        )):
            return self._running_services()

        # Port queries
        if "port" in normalized and any(
            p in normalized for p in ("what is on", "what's on",
            "who is using", "what is using", "running on")
        ):
            port = self._extract_port(normalized)
            if port:
                return self._port_info(port)

        # ── Ollama path for complex questions ─────────────────────────────────
        return self._ask_ollama(user_input)

    def _greeting(self) -> str:
        if self.state:
            try:
                snap = self.state.get_snapshot()
                res = snap["resources"]
                ports = snap["ports"]
                health = snap["health"]
                health_icon = "✓" if health == "HEALTHY" else "⚠"
                active = [
                    f"{info['process']}:{p}"
                    for p, info in ports.items()
                    if info["criticality"] in ("CRITICAL", "HIGH")
                ]
                active_str = ", ".join(active[:4]) if active else "none"
                return (
                    f"Hello! I'm LINxAI — your intelligent Linux administration layer.\n"
                    f"  {health_icon} System: {health} | "
                    f"CPU: {res['cpu_pct']}% | "
                    f"Memory: {res['memory_pct']}% | "
                    f"Disk: {res['disk_pct']}%\n"
                    f"  Active: {active_str}\n"
                    f"  Type a Linux command or ask me anything."
                )
            except Exception:
                pass
        return "Hello! I'm LINxAI. Type a Linux command or ask me anything."

    def _system_status(self) -> str:
        if not self.state:
            return "System state not available."
        try:
            return self.state.format_health_summary()
        except Exception as e:
            return f"Could not read system state: {e}"

    def _running_services(self) -> str:
        if not self.state:
            return "System state not available."
        try:
            snap = self.state.get_snapshot()
            ports = snap["ports"]
            if not ports:
                return "No services detected on listening ports."
            lines = ["Active services:"]
            for port, info in sorted(ports.items()):
                crit_icon = {
                    "CRITICAL": "🔴",
                    "HIGH":     "🟠",
                    "MEDIUM":   "🟡",
                    "LOW":      "🟢",
                }.get(info["criticality"], "⚪")
                lines.append(
                    f"  {crit_icon} Port {port:5} — {info['process']:<12} "
                    f"[{info['criticality']}] {info['description']} "
                    f"(up {info['uptime_human']})"
                )
            return "\n".join(lines)
        except Exception as e:
            return f"Could not read running services: {e}"

    def _port_info(self, port: int) -> str:
        if not self.state:
            return f"System state not available."
        try:
            info = self.state.get_port_info(port)
            if not info:
                return f"Port {port} is not in use."
            return self.state.format_port_conflict(port)
        except Exception as e:
            return f"Could not read port info: {e}"

    def _extract_port(self, text: str) -> int:
        import re
        match = re.search(r'\b(\d{2,5})\b', text)
        if match:
            port = int(match.group(1))
            if 1 <= port <= 65535:
                return port
        return None

    def _ask_ollama(self, user_input: str) -> str:
        prompt = f"""You are LINxAI, an intelligent Linux administration assistant.
Answer this question concisely and helpfully. Focus on practical Linux guidance.
If asked about setting up software, give step-by-step terminal commands.
Keep your response under 150 words.

Question: {user_input}"""
        try:
            response = requests.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {"num_predict": 200, "temperature": 0.3}
                },
                timeout=60
            )
            response.raise_for_status()
            return response.json()["message"]["content"].strip()
        except Exception as e:
            logger.error(f"ChatResponder Ollama call failed: {e}")
            return "I could not generate a response. Please try again."
