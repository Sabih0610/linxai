# ai/engine.py
import requests
import json
import re
import logging
from ai.prompts import SYSTEM_PROMPT
from ai.fast_path import classify_fast
 
logger = logging.getLogger(__name__)
 
 
class AIEngine:
 
    def __init__(self, model: str = "qwen2.5:1.5b",
                 host: str = "http://localhost:11434",
                 timeout: int = 120,
                 cache=None):
        self.model = model
        self.host = host
        self.timeout = timeout
        self.cache = cache
        self.cpu_only = None
        self._verify_connection()
 
    def _verify_connection(self):
        try:
            r = requests.get(f"{self.host}/api/tags", timeout=5)
            r.raise_for_status()
            models = [m["name"] for m in r.json().get("models", [])]
            if not any(self.model.split(":")[0] in m for m in models):
                raise RuntimeError(
                    f"Model '{self.model}' not found. Run: ollama pull {self.model}"
                )
            print("  Warming up model...", end="", flush=True)
            requests.post(
                f"{self.host}/api/generate",
                json={
                    "model": self.model,
                    "prompt": "hi",
                    "stream": False,
                    "keep_alive": -1,
                },
                timeout=120
            )
            requests.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": "hi"}],
                    "stream": False,
                    "keep_alive": -1,
                    "options": {"num_predict": 5}
                },
                timeout=120
            )
            self.cpu_only = self._detect_cpu_only()
            print(" ready.")
            logger.info(f"AI Engine ready — model: {self.model}")
        except requests.ConnectionError:
            raise RuntimeError(
                "Cannot connect to Ollama at localhost:11434. "
                "Run: sudo systemctl start ollama"
            )

    def _detect_cpu_only(self):
        try:
            r = requests.get(f"{self.host}/api/ps", timeout=3)
            r.raise_for_status()
            models = r.json().get("models", [])
            model_key = self.model.split(":")[0]
            for model in models:
                name = model.get("name") or model.get("model") or ""
                if model_key not in name:
                    continue
                size_vram = model.get("size_vram")
                if size_vram is None:
                    return None
                return int(size_vram) <= 0
        except Exception:
            return None
        return None
 
    def _build_messages(self, user_input: str, context: list) -> list:
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        for turn in context[-3:]:
            messages.append({"role": "user", "content": turn.get("input", "")})
            messages.append({"role": "assistant", "content": json.dumps(turn.get("plan", {}))})
        messages.append({"role": "user", "content": user_input})
        return messages
 
    def _extract_json(self, raw: str) -> str:
        raw = raw.strip()
        if raw.startswith("{"):
            return raw
        if "```" in raw:
            parts = raw.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                if part.startswith("{"):
                    return part
        match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', raw, re.DOTALL)
        if match:
            return match.group(0)
        raise ValueError(f"No valid JSON found in model output: {raw[:200]}")

    def _repair_truncated_json(self, json_str: str) -> str:
        repaired = (json_str or "").strip()
        if not repaired:
            return repaired

        if repaired.count('"') % 2 == 1:
            repaired += '"'

        open_braces = repaired.count("{")
        close_braces = repaired.count("}")
        if close_braces < open_braces:
            repaired += "}" * (open_braces - close_braces)

        return repaired

    def _unknown_parse_plan(self) -> dict:
        return self._validate_plan({
            "intent": "unknown",
            "target": "",
            "pre_conditions": [],
            "command": "",
            "requires_sudo": False,
            "risk_level": "low",
            "rollback": "",
            "explanation": "I couldn't parse that — could you rephrase?",
        })
 
    def _validate_plan(self, plan: dict) -> dict:
        required = ["intent", "target", "command"]
        for field in required:
            if field not in plan:
                raise ValueError(f"Plan missing required field: '{field}'")
        plan.setdefault("pre_conditions", [])
        plan.setdefault("requires_sudo", False)
        plan.setdefault("risk_level", "low")
        plan.setdefault("rollback", "")
        plan.setdefault("explanation", "No explanation provided.")
        plan.setdefault("suggestion", "")
        plan.setdefault("port", "")
        plan.setdefault("goal", "")
        plan.setdefault("path", "")
        plan.setdefault("stack", "")
        plan.setdefault("repo_url", "")
        return plan

    def _fast_plan(self, user_input: str) -> dict | None:
        text = re.sub(r"\s+", " ", user_input.lower().strip())
        requested_port = self._extract_requested_port(text)

        env_setup = self._extract_env_setup_request(user_input, text)
        if env_setup:
            return self._validate_plan(env_setup)

        runtime_query = self._extract_runtime_query(text)
        if runtime_query:
            return self._validate_plan(runtime_query)

        if requested_port and self._is_listener_without_service(text):
            return self._validate_plan({
                "intent": "service_start",
                "target": "",
                "port": requested_port,
                "pre_conditions": [],
                "command": "",
                "requires_sudo": False,
                "risk_level": "low",
                "rollback": "",
                "explanation": (
                    "No specific service was named for the requested port."
                ),
                "suggestion": (
                    f"Ask whether to configure nginx for port "
                    f"{requested_port}, or use a temporary test listener."
                ),
            })

        service_port = self._extract_service_port_request(text)
        if service_port:
            service, port, intent = service_port
            action = {
                "service_restart": "restart",
                "service_stop": "stop",
            }.get(intent, "start")
            return self._validate_plan({
                "intent": intent,
                "target": service,
                "port": port,
                "pre_conditions": [{"check": "service_exists", "service": service}],
                "command": f"systemctl {action} {service}",
                "requires_sudo": True,
                "risk_level": "medium",
                "rollback": f"systemctl start {service}" if intent == "service_stop" else f"systemctl stop {service}",
                "explanation": (
                    f"{action.capitalize()}s {service}; port {port} must be "
                    f"configured in the service config, not systemctl."
                ),
            })

        if any(p in text for p in (
            "windows registry",
            "regedit",
            "registry editor",
        )):
            return self._validate_plan({
                "intent": "not_applicable",
                "target": "windows_registry",
                "pre_conditions": [],
                "command": "",
                "requires_sudo": False,
                "risk_level": "low",
                "rollback": "",
                "explanation": "The Windows registry does not exist on Linux.",
                "suggestion": (
                    "On Linux, system settings are usually stored in "
                    "configuration files under /etc or user dotfiles."
                ),
            })

        if any(p in text for p in (
            "mac address",
            "my mac",
            "show mac",
            "hardware address",
        )):
            return self._validate_plan({
                "intent": "network_info",
                "target": "mac_address",
                "pre_conditions": [],
                "command": "cat /sys/class/net/*/address",
                "requires_sudo": False,
                "risk_level": "low",
                "rollback": "",
                "explanation": "Shows network interface MAC addresses.",
            })

        if any(p in text for p in (
            "my ip",
            "ip address",
            "ip addresses",
        )):
            return self._validate_plan({
                "intent": "network_info",
                "target": "ip_address",
                "pre_conditions": [],
                "command": "ip -brief addr",
                "requires_sudo": False,
                "risk_level": "low",
                "rollback": "",
                "explanation": "Shows IP addresses.",
            })

        if any(p in text for p in (
            "hostname",
            "host name",
            "computer name",
        )):
            return self._validate_plan({
                "intent": "network_info",
                "target": "hostname",
                "pre_conditions": [],
                "command": "hostnamectl --static",
                "requires_sudo": False,
                "risk_level": "low",
                "rollback": "",
                "explanation": "Shows the system hostname.",
            })

        if any(p in text for p in (
            "what os",
            "which distro",
            "what distro",
            "linux version",
        )):
            return self._validate_plan({
                "intent": "network_info",
                "target": "os",
                "pre_conditions": [],
                "command": "lsb_release -d",
                "requires_sudo": False,
                "risk_level": "low",
                "rollback": "",
                "explanation": "Shows the Linux distribution.",
            })

        if any(p in text for p in (
            "macos dock",
            "open finder",
            "finder window",
        )):
            return self._validate_plan({
                "intent": "not_applicable",
                "target": "macos_gui",
                "pre_conditions": [],
                "command": "",
                "requires_sudo": False,
                "risk_level": "low",
                "rollback": "",
                "explanation": "That macOS GUI feature is not available on Linux.",
                "suggestion": "Use Linux desktop settings or shell commands instead.",
            })

        return None

    def _extract_requested_port(self, text: str) -> str | None:
        match = re.search(r"\bport\s+(?P<port>\d{1,5})\b", text)
        if not match:
            return None
        port = int(match.group("port"))
        if 1 <= port <= 65535:
            return str(port)
        return None

    def _is_listener_without_service(self, text: str) -> bool:
        patterns = (
            r"\b(?:start|run|create|open|stop|restart)\s+(?:a\s+)?(?:test\s+)?"
            r"(?:listener|listening|server|something)\s+(?:on\s+)?port\s+\d{1,5}\b",
            r"\b(?:start|run|create|open)\s+(?:any\s+service|a\s+service|service)\s+"
            r"(?:on|o|at|using)?\s*port\s+\d{1,5}\b",
            r"\b(?:start|run|stop|restart)\s+(?:on|o)?\s*port\s+\d{1,5}\b",
        )
        return any(re.search(pattern, text) for pattern in patterns)

    def _extract_service_port_request(self, text: str) -> tuple[str, str, str] | None:
        match = re.search(
            r"\b(?P<action>start|run|launch|restart|stop)\s+(?:the\s+)?"
            r"(?P<service>[\w@.-]+)(?:\s+service)?\s+"
            r"(?:on|at|using)\s+port\s+(?P<port>\d{1,5})\b",
            text,
        )
        if not match:
            return None

        service = match.group("service")
        if service in {
            "listening", "listener", "something", "server", "test",
            "port", "any",
        }:
            return None

        port = int(match.group("port"))
        if not 1 <= port <= 65535:
            return None
        action = match.group("action")
        intent = {
            "restart": "service_restart",
            "stop": "service_stop",
        }.get(action, "service_start")
        return service, str(port), intent

    def _extract_env_setup_request(self, user_input: str, text: str) -> dict | None:
        repo_url = self._extract_repo_url(user_input)
        path = self._extract_env_setup_path(user_input)

        if repo_url and any(word in text for word in (
            "install", "setup", "set up", "clone", "repo", "repository", "github",
        )):
            return {
                "intent": "env_setup",
                "target": "",
                "goal": "repo_install",
                "path": path,
                "stack": "",
                "repo_url": repo_url,
                "pre_conditions": [],
                "command": "",
                "requires_sudo": False,
                "risk_level": "medium",
                "rollback": "",
                "explanation": (
                    "Installs the repository with planner steps for cloning "
                    "and dependency setup."
                ),
            }

        if (
            "mern" in text
            or ("react" in text and "node" in text)
            or ("react" in text and "nodejs" in text)
        ) and any(word in text for word in ("setup", "set up", "environment", "scaffold")):
            return {
                "intent": "env_setup",
                "target": "",
                "goal": "mern_setup",
                "path": path,
                "stack": "mern",
                "repo_url": "",
                "pre_conditions": [],
                "command": "",
                "requires_sudo": False,
                "risk_level": "medium",
                "rollback": "",
                "explanation": "Sets up a MERN environment with planner steps.",
            }

        if any(phrase in text for phrase in (
            "python environment",
            "python env",
            "python virtual environment",
            "venv",
        )) and any(word in text for word in ("setup", "set up", "create", "make")):
            return {
                "intent": "env_setup",
                "target": "",
                "goal": "python_env",
                "path": path,
                "stack": "python",
                "repo_url": "",
                "pre_conditions": [],
                "command": "",
                "requires_sudo": False,
                "risk_level": "low",
                "rollback": "",
                "explanation": "Sets up a Python virtual environment with planner steps.",
            }

        return None

    def _extract_repo_url(self, user_input: str) -> str:
        match = re.search(r"https?://\S+", user_input)
        if not match:
            return ""
        return match.group(0).rstrip(".,);")

    def _extract_env_setup_path(self, user_input: str) -> str:
        match = re.search(
            r"\b(?:at|in|under|into|to)\s+"
            r"(?P<path>(?:~|/|\./|\../)?[A-Za-z0-9._/-]+)",
            user_input,
            re.IGNORECASE,
        )
        if not match:
            return ""
        path = match.group("path").rstrip(".,);")
        if path.startswith("http"):
            return ""
        return path

    def _extract_runtime_query(self, text: str) -> dict | None:
        if (
            re.search(r"\b(?:which|what(?:'s| is))\b.*\brunning\b.*\b(?:hour|minute|day|~\d|\d+)", text)
            or re.search(r"\b(?:process|processes|service|services)\b.*\brunning\b.*\b(?:hour|minute|day|~\d|\d+)", text)
        ):
            return {
                "intent": "process_list",
                "target": "elapsed",
                "pre_conditions": [],
                "command": "ps -eo comm,etime,pid --sort=start_time",
                "requires_sudo": False,
                "risk_level": "low",
                "rollback": "",
                "explanation": "Lists processes with elapsed runtime.",
            }

        if (
            "uptime" in text
            or re.search(r"\bhow long\b.*\b(?:server|machine|system|computer)\b.*\brunning\b", text)
            or re.search(r"\bhow long\b.*\b(?:server|machine|system|computer)\b.*\bup\b", text)
        ):
            return {
                "intent": "system_uptime",
                "target": "",
                "pre_conditions": [],
                "command": "uptime -p",
                "requires_sudo": False,
                "risk_level": "low",
                "rollback": "",
                "explanation": "Shows how long the machine has been running.",
            }

        return None
 
    def classify(self, user_input: str, context: list = None,
                 max_retries: int = 2) -> dict:
        if context is None:
            context = []

        fast_path_plan = classify_fast(user_input, {"recent": context})
        if fast_path_plan:
            fast_path_plan = self._validate_plan(fast_path_plan)
            logger.info(
                f"Fast path classified '{user_input}' -> "
                f"intent: {fast_path_plan.get('intent')}"
            )
            if self.cache:
                self.cache.store(user_input, fast_path_plan)
            return fast_path_plan

        fast_plan = self._fast_plan(user_input)
        if fast_plan:
            fast_plan["source"] = "engine_fast_path"
            if self.cache:
                self.cache.store(user_input, fast_plan)
            return fast_plan

        # Cache lookup — skip Ollama if we have a cached plan
        if self.cache:
            cached = self.cache.get(user_input)
            if cached:
                logger.info(f"Cache HIT: '{user_input}' → {cached.get('intent')}")
                return cached

        messages = self._build_messages(user_input, context)
        last_error = None
 
        for attempt in range(max_retries + 1):
            try:
                response = requests.post(
                    f"{self.host}/api/chat",
                    json={
                        "model": self.model,
                        "messages": messages,
                        "stream": False,
                        "format": "json",
                        "keep_alive": -1,
                        "options": {
                            "temperature": 0,
                            "top_p": 1,
                            "num_predict": 256,
                        }
                    },
                    timeout=self.timeout
                )
                response.raise_for_status()
                raw_content = response.json()["message"]["content"]
                logger.debug(f"Raw model output: {raw_content}")
                json_str = self._extract_json(raw_content)
                json_str = json_str.replace("\\", "\\\\") if "\\u" not in json_str and "\\" in json_str else json_str
                try:
                    plan = json.loads(json_str)
                except json.JSONDecodeError:
                    repaired_json = self._repair_truncated_json(json_str)
                    if repaired_json == json_str:
                        raise
                    plan = json.loads(repaired_json)
                plan = self._validate_plan(plan)
                logger.info(f"Classified '{user_input}' → intent: {plan['intent']}")
                # Store in cache for next time
                if self.cache:
                    self.cache.store(user_input, plan)
                return plan
 
            except (json.JSONDecodeError, ValueError) as e:
                last_error = e
                logger.warning(f"JSON parse attempt {attempt + 1} failed: {e}")
                if attempt < max_retries:
                    messages.append({
                        "role": "assistant",
                        "content": raw_content if 'raw_content' in locals() else ""
                    })
                    messages.append({
                        "role": "user",
                        "content": "Your response was not valid JSON. Return ONLY a raw JSON object with no extra text."
                    })
                continue
            except requests.RequestException as e:
                raise RuntimeError(f"Ollama request failed: {e}")
 
        logger.error(
            "Failed to parse model JSON after %s attempts: %s",
            max_retries + 1,
            last_error,
        )
        return self._unknown_parse_plan()

    def explain_audit_log(self, records: list) -> str:
        """
        Takes recent audit log records and returns a plain English
        explanation of what happened — for the 'what just happened' command.
        """
        if not records:
            return "No recent audit records found."

        # Build a concise summary of events for the model
        priority_modules = ("ai_engine", "cie", "executor", "system")
        filtered = [r for r in records if r.get("module") in priority_modules]
        use_records = filtered[-20:] if filtered else records[-20:]
        lines = []
        for r in use_records:
            ts = r.get("timestamp", "")[:19].replace("T", " ")
            module = r.get("module", "?")
            event = r.get("event_type", "?")
            payload = r.get("payload", {})

            # Extract the most meaningful field per module
            detail = ""
            if module == "ai_engine":
                detail = f"intent={payload.get('intent','?')} cmd={payload.get('command','?')}"
            elif module == "cie":
                detail = f"decision={payload.get('decision','?')} reason={payload.get('reason','?')}"
            elif module == "executor":
                detail = f"status={payload.get('status','?')} cmd={payload.get('command_issued','?')}"
            elif module == "ebpf":
                if event == "process_exec":
                    detail = f"process={payload.get('process','?')} pid={payload.get('pid','?')}"
                elif event == "network_connect":
                    detail = f"process={payload.get('process','?')} -> {payload.get('dest_ip','?')}:{payload.get('dest_port','?')}"
                elif event == "file_open":
                    detail = f"process={payload.get('process','?')} file={payload.get('filename','?')}"
            elif module == "resources":
                detail = f"event={event} {payload.get('reason','')}"
            elif module == "vps":
                detail = f"server={payload.get('server','?')} status={payload.get('status','?')}"
            elif module == "system":
                detail = f"system {event}"

            lines.append(f"[{ts}] {module}/{event}: {detail}")

        log_summary = "\n".join(lines)

        prompt = f"""You are LINxAI, an intelligent Linux administration assistant.
A user asked: "what just happened on my system?"

Here are the recent system events from the audit log:

{log_summary}

Explain in 3-5 plain English sentences what happened on this Linux system.
Be specific about what commands ran, what was detected, and whether anything looks suspicious.
Do not use technical jargon. Write as if explaining to a junior sysadmin.
Do not repeat the raw log lines. Synthesise them into a clear narrative."""

        try:
            response = requests.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {
                        "num_predict": 300,
                        "temperature": 0.3,
                    }
                },
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            return data["message"]["content"].strip()
        except Exception as e:
            logger.error(f"explain_audit_log failed: {e}")
            return f"Could not generate explanation: {e}"

    def explain_ebpf_alert(self, alert: dict) -> str:
        """
        Takes a single eBPF security alert and explains what it means
        and how serious it is. Used by the feedback loop.
        """
        event_type = alert.get("event_type", "unknown")
        payload = alert.get("payload", {})

        if event_type == "process_exec":
            desc = f"A process named '{payload.get('process','?')}' (PID {payload.get('pid','?')}) was launched by parent PID {payload.get('ppid','?')}."
        elif event_type == "network_connect":
            desc = f"Process '{payload.get('process','?')}' connected to {payload.get('dest_ip','?')}:{payload.get('dest_port','?')}."
        elif event_type == "file_open":
            desc = f"Process '{payload.get('process','?')}' accessed file '{payload.get('filename','?')}'."
        else:
            desc = str(alert)

        prompt = f"""You are a Linux security monitor.
A kernel-level eBPF probe detected this event:
{desc}

In one sentence, say whether this is: NORMAL, SUSPICIOUS, or DANGEROUS.
Then in one more sentence explain why.
Be direct. No preamble."""

        try:
            response = requests.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {"num_predict": 100, "temperature": 0.1}
                },
                timeout=30
            )
            response.raise_for_status()
            return response.json()["message"]["content"].strip()
        except Exception as e:
            return f"Alert: {desc}"
 
    def is_healthy(self) -> bool:
        try:
            r = requests.get(f"{self.host}/api/tags", timeout=3)
            return r.status_code == 200
        except Exception:
            return False
