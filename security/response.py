"""Unprivileged incident reasoning. Every mutation still passes registry/jobs/broker."""
from dataclasses import asdict
import threading
import time
from uuid import uuid4

from ai.local_planner import OllamaPlanner
from .policy_daemon import PolicyClient


DEFAULT_DURATION = 120          # seconds; the root config's max_duration still bounds it
MODEL_BUDGET_S = 10            # the model only refines the duration, so it never delays containment


def block_request(event, model=None):
    """The block request for a TCP connection incident, built from the kernel EVIDENCE.

    QA 13 Nov 2026: containment used to depend on the local model answering within 30 s;
    a cold model on a small host timed out and the attacker stayed unblocked. The target
    now always comes from the evidence. The model may only suggest a duration (30-300 s);
    if it is unavailable, slow, malformed or names any other target, the default is used.
    Root configuration and the broker still decide whether the block is allowed."""
    if event["kind"] != "network_connect" or event.get("protocol") != "tcp":
        raise ValueError("This response workflow supports only scoped IPv4 TCP connection incidents")
    target = event["target"]
    duration, origin = DEFAULT_DURATION, "evidence; model unavailable"
    if model is not None:
        try:
            proposal = model.generate_response(event, timeout=MODEL_BUDGET_S)
            if (isinstance(proposal, dict) and set(proposal) == {"action", "address", "port", "duration"}
                    and proposal.get("action") == "response.network.block"
                    and {"address": proposal.get("address"), "port": proposal.get("port")} == target
                    and type(proposal.get("duration")) is int and 30 <= proposal["duration"] <= 300):
                duration, origin = proposal["duration"], "evidence; duration from local model"
            else:
                origin = "evidence; model answer ignored (malformed or different target)"
        except Exception as exc:
            origin = f"evidence; model unavailable ({type(exc).__name__})"
    request = {"action": "response.network.block", "parameters": {"policy_id": str(uuid4()), "event_id": event["id"],
               "address": target["address"], "port": target["port"], "duration": duration}}
    return request, origin


class Responses:
    def __init__(self, registry, jobs, model=None):
        self.registry, self.jobs, self.model = registry, jobs, model or OllamaPlanner()

    def propose(self, incident):
        request, origin = block_request(incident["evidence"], self.model)
        self.registry.prepare(request["action"],request["parameters"])
        preview = self.jobs.preview(request,text=f"Scoped incident response for {incident['id']} ({origin})")
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
