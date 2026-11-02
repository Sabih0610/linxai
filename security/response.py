"""Unprivileged incident reasoning. Every mutation still passes registry/jobs/broker."""
from dataclasses import asdict
import threading
import time
from uuid import uuid4

from ai.local_planner import OllamaPlanner
from .policy_daemon import PolicyClient


class Responses:
    def __init__(self, registry, jobs, model=None):
        self.registry, self.jobs, self.model = registry, jobs, model or OllamaPlanner()

    def propose(self, incident):
        event = incident["evidence"]
        if event["kind"] != "network_connect" or event.get("protocol") != "tcp":
            raise ValueError("This response workflow supports only scoped IPv4 TCP connection incidents")
        proposal = self.model.generate_response(event)
        if not isinstance(proposal, dict) or set(proposal) != {"action", "address", "port", "duration"} or proposal["action"] != "response.network.block":
            raise ValueError("Unsupported or malformed model response; no fallback")
        if {"address":proposal["address"],"port":proposal["port"]} != event["target"]:
            raise ValueError("Model response target differs from incident evidence")
        request = {"action":"response.network.block", "parameters":{"policy_id":str(uuid4()),"event_id":event["id"],
                   "address":proposal["address"],"port":proposal["port"],"duration":proposal["duration"]}}
        self.registry.prepare(request["action"],request["parameters"])
        preview = self.jobs.preview(request,text="Scoped incident response for " + incident["id"])
        return preview


class ResponseWorker:
    """Model latency is isolated from capture/detection; root owner limits remain authoritative."""
    def __init__(self, store_factory, responses, status_client=None):
        self.store_factory, self.responses = store_factory, responses
        self.client = status_client or PolicyClient()
        self.health = {"state":"starting"}
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run,daemon=True,name="linxai-response")
    def tick(self):
        status = self.client.call("status")
        if status.get("auto_enabled") is not True or status.get("qualified") is not True:
            self.health = {"state":"disabled_or_unqualified"}
            return
        self.health = {"state":"ready"}
        store=self.store_factory()
        try:
            for incident in reversed(store.list("incident",8)):
                if incident.get("response_job"):
                    row=self.responses.jobs.store.get("job",incident["response_job"])
                    if row and row["state"]=="succeeded" and row.get("result",{}).get("verified"):
                        incident.update(state="contained",response="verified_scoped_containment",policy_id=row["request"]["parameters"]["policy_id"])
                    elif row and row["state"] in {"failed","unknown","review_required"}:
                        incident.update(state="escalated",response="review_required")
                    store.put("incident",incident["id"],incident)
                    continue
                if incident.get("response") not in {"none","retry_pending"} or incident["evidence"]["kind"]!="network_connect" or incident["evidence"].get("protocol")!="tcp":continue
                if incident.get("next_attempt",0)>time.time():continue
                event=incident["evidence"]
                active=next((policy for policy in status["policies"] if policy["state"]=="active" and policy["uid"]==event["uid"]
                             and policy["address"]==event["target"]["address"] and policy["port"]==event["target"]["port"]
                             and policy["expires_wall"]>time.time()),None)
                if active:
                    incident.update(response="covered_by_validated_policy",policy_id=active["id"])
                else:
                    # The root broker rechecks its own config/evidence; this bool grants no authority.
                    attempts=incident.get("response_attempts",0)+1
                    incident.update(response_attempts=attempts,next_attempt=time.time()+min(60,2**attempts))
                    try:
                        preview=self.responses.propose(incident)
                        self.responses.jobs.confirm(preview["id"],preview["digest"])
                        incident.update(response_job=preview["id"],response="proposed",state="response_proposed")
                    except Exception as exc:
                        incident.update(response="review_required" if attempts>=3 else "retry_pending",response_error=type(exc).__name__)
                        if attempts>=3:incident["state"]="escalated"
                store.put("incident",incident["id"],incident)
        finally:store.close()
    def run(self):
        while not self.stop.is_set():
            try:self.tick()
            except Exception as exc:
                self.health={"state":"unavailable", "error":type(exc).__name__}  # Detector remains independent.
            self.stop.wait(1)
