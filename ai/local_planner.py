"""No-warmup local planner. Existing fast paths, schema and typed bridge are reused."""
from dataclasses import asdict
import json
from urllib.request import Request, urlopen

from .fast_path import classify_fast
from .plan_schema import validate_plan
from .prompts import SYSTEM_PROMPT
from operations.plans import adapt_plan
from operations.registry import DirectoryParameters, FileParameters


class OllamaPlanner:
    def __init__(self, model="qwen2.5:1.5b"):
        if not isinstance(model, str) or not 1 <= len(model) <= 128:
            raise ValueError("Bounded local model name required")
        self.model = model

    def generate(self, text, context):
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        for turn in context[-5:]:
            messages.append({"role": "user", "content": str(turn.get("text", ""))[:4096]})
            messages.append({"role": "assistant", "content": json.dumps(turn.get("plan", {}))[:8192]})
        messages.append({"role": "user", "content": text})
        body = json.dumps({"model": self.model, "messages": messages, "stream": False,
                           "format": "json", "options": {"num_predict": 1024, "temperature": 0}}).encode()
        request = Request("http://127.0.0.1:11434/api/chat", data=body, headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=30) as response:
            data = response.read(65537)
        if len(data) > 65536:
            raise ValueError("Model response exceeds budget")
        return json.loads(json.loads(data)["message"]["content"])


def typed_request(prepared):
    parameters = asdict(prepared.parameters)
    if isinstance(prepared.parameters, (FileParameters, DirectoryParameters)):
        parameters["path"] = parameters.pop("relative_path")
    return {"action": prepared.contract.identifier, "parameters": parameters}


class Planner:
    def __init__(self, registry, model=None):
        self.registry, self.model = registry, model or OllamaPlanner()

    def propose(self, text, context=()):
        if not isinstance(text, str) or not text.strip() or len(text.encode()) > 8192 or "\x00" in text:
            raise ValueError("Request must be bounded nonempty text")
        plan = classify_fast(text)
        if plan is None:
            plan = self.model.generate(text, context)
        plan = validate_plan(plan)
        prepared = adapt_plan(plan, self.registry)
        return typed_request(prepared), plan
