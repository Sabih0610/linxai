# ai/engine.py
import requests
import json
import re
import logging
from ai.prompts import SYSTEM_PROMPT
 
logger = logging.getLogger(__name__)
 
 
class AIEngine:
 
    def __init__(self, model: str = "qwen2.5:1.5b",
                 host: str = "http://localhost:11434",
                 timeout: int = 120):
        self.model = model
        self.host = host
        self.timeout = timeout
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
                json={"model": self.model, "prompt": "hi", "stream": False},
                timeout=120
            )
            requests.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": "hi"}],
                    "stream": False,
                    "options": {"num_predict": 5}
                },
                timeout=120
            )
            print(" ready.")
            logger.info(f"AI Engine ready — model: {self.model}")
        except requests.ConnectionError:
            raise RuntimeError(
                "Cannot connect to Ollama at localhost:11434. "
                "Run: sudo systemctl start ollama"
            )
 
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
        return plan
 
    def classify(self, user_input: str, context: list = None,
                 max_retries: int = 2) -> dict:
        if context is None:
            context = []
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
                        "options": {
                            "temperature": 0.1,
                            "top_p": 0.9,
                            "num_predict": 512,
                        }
                    },
                    timeout=self.timeout
                )
                response.raise_for_status()
                raw_content = response.json()["message"]["content"]
                logger.debug(f"Raw model output: {raw_content}")
                json_str = self._extract_json(raw_content)
                json_str = json_str.replace("\\", "\\\\") if "\\u" not in json_str and "\\" in json_str else json_str
                plan = json.loads(json_str)
                plan = self._validate_plan(plan)
                logger.info(f"Classified '{user_input}' → intent: {plan['intent']}")
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
 
        raise RuntimeError(
            f"Failed to get valid JSON after {max_retries + 1} attempts. Last error: {last_error}"
        )

    def explain_audit_log(self, records: list) -> str:
        """
        Takes recent audit log records and returns a plain English
        explanation of what happened — for the 'what just happened' command.
        """
        if not records:
            return "No recent audit records found."

        # Build a concise summary of events for the model
        lines = []
        for r in records[-20:]:  # last 20 records
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