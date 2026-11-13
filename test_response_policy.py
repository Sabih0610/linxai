"""Policy workflows use simulated kernel/evidence/auth adapters, never real hooks."""
import copy
from dataclasses import asdict
import json
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from operations.broker import Broker, BrokerService
from operations.registry import ActionRegistry, Privilege
from operations.service import Execution, Observation
from security.events import normalize
from security.policy import Authority
from security.policy_daemon import handle
from security.response import Responses, ResponseWorker
from test_application import MemoryStore
from test_broker import PeerDouble, LedgerDouble, SystemDouble
from test_operations_service import MemoryAudit


class SimulatedKernel:
    real=False
    boot,host,digest="boot","host","simulated-program"
    def __init__(self,clock):self.clock,self.rows,self.denial,self.qualification=clock,{},True,True
    def qualified(self):return self.qualification
    def contains(self,policy):return self.rows.get(policy["id"])==policy["expires_ns"]
    def scope_available(self,*args):return True
    def install(self,policy):self.rows[policy["id"]]=policy["expires_ns"]
    def remove(self,policy):self.rows.pop(policy["id"],None)
    def verify_denial(self,policy):return self.denial and self.contains(policy) and self.clock()<policy["expires_ns"]


class ResponsePolicyTests(unittest.TestCase):
    def setUp(self):
        self.now=1_000_000_000
        self.clock=lambda:self.now
        self.store=MemoryStore();self.kernel=SimulatedKernel(self.clock)
        self.event=normalize({"event_type":"network_connect","payload":{"pid":123,"uid":1000,"start_ns":50,
                             "monotonic_ns":100,"protocol":6,"dest_ip":"127.0.0.1","dest_port":4444}},"host","boot",source="kernel")
        self.event["received_ns"]=self.now
        self.event["received_boottime_ns"]=self.now
        config={"owner_uid":1000,"targets":[{"address":"127.0.0.1","port":4444}],"max_duration":300,"max_active":4,"auto_enabled":False}
        self.authority=Authority(config,self.store,self.kernel,lambda key:copy.deepcopy(self.event) if key==self.event["id"] else None,clock=self.clock)
        self.params={"policy_id":str(uuid4()),"event_id":self.event["id"],"address":"127.0.0.1","port":4444,"duration":60}

    def test_first_response_verification_recurrence_expiry_and_revocation(self):
        policy=self.authority.apply(1000,self.params,str(uuid4()))
        self.assertEqual(policy["state"],"installed")
        self.assertEqual(policy["verification_origin"],"simulated")
        self.assertTrue(self.authority.verify(policy["id"])["verified"])
        self.assertEqual(self.store.get("policy",policy["id"])["state"],"active")
        # Known recurrence is matched by the installed kernel adapter; no model exists here.
        self.assertTrue(self.kernel.verify_denial(policy))
        self.now+=61_000_000_000
        self.assertFalse(self.kernel.verify_denial(policy))
        self.authority.tick()
        self.assertEqual(self.store.get("policy",policy["id"])["state"],"expired")
        self.authority.revoke(1000,{"policy_id":policy["id"]},str(uuid4()))
        self.assertTrue(self.authority.verify(policy["id"])["verified"])

    def test_scope_wrong_user_stale_or_forged_evidence_and_unqualified_kernel(self):
        for key,value in (("address","127.0.0.2"),("port",4445),("duration",301),("actor_uid",1000)):
            changed=dict(self.params);changed[key]=value
            with self.assertRaises((ValueError,PermissionError)):self.authority.preview(1000,changed)
        with self.assertRaises(PermissionError):self.authority.preview(1001,self.params)
        for key,value in (("source","simulated"),("boot","other"),("uid",1001),("identity_quality","incomplete_or_simulated")):
            prior=self.event[key];self.event[key]=value
            with self.assertRaises(PermissionError):self.authority.preview(1000,self.params)
            self.event[key]=prior
        self.now+=121_000_000_000
        with self.assertRaises(PermissionError):self.authority.preview(1000,self.params)
        self.now=1_000_000_000;self.kernel.qualification=False
        with self.assertRaises(PermissionError):self.authority.preview(1000,self.params)
        self.assertFalse(self.kernel.rows)

    def test_failed_containment_never_promotes_and_policy_ids_cannot_replay(self):
        policy=self.authority.apply(1000,self.params,str(uuid4()))
        self.kernel.denial=False
        self.assertFalse(self.authority.verify(policy["id"])["verified"])
        self.assertEqual(self.store.get("policy",policy["id"])["state"],"installed")
        with self.assertRaises(ValueError):self.authority.apply(1000,self.params,str(uuid4()))

    def test_auto_owner_limits_are_root_config_and_user_wire_cannot_grant_them(self):
        with self.assertRaises(PermissionError):self.authority.automatic(1000,self.params,str(uuid4()),"digest")
        self.authority.config["auto_enabled"]=True
        proof=self.authority.automatic(1000,self.params,str(uuid4()),"digest")
        self.assertTrue(proof["authorized"])
        request={"version":1,"method":"apply","actor_uid":1000,"parameters":self.params,"operation_id":str(uuid4())}
        with self.assertRaises(PermissionError):handle(self.authority,1000,request,MemoryAudit())
        request["authenticated"]=True
        with self.assertRaises(ValueError):handle(self.authority,1000,request,MemoryAudit())
        self.assertFalse(self.kernel.rows)

    def test_crash_restore_requires_validated_root_policy_auto_limits_and_original_expiry(self):
        self.authority.config["auto_enabled"]=True
        policy=self.authority.apply(1000,self.params,str(uuid4()));self.authority.verify(policy["id"])
        self.kernel.rows.clear();self.authority.tick()
        self.assertTrue(self.kernel.contains(policy))
        self.authority.config["auto_enabled"]=False;self.kernel.rows.clear();self.authority.tick()
        self.assertEqual(self.store.get("policy",policy["id"])["state"],"review_required")

    def test_existing_service_lifecycle_executes_exact_response_and_correlates(self):
        outer=self
        class PolicySystem(SystemDouble):
            def check(self,op_id,required,identity):
                if required.identifier=="response_owner_scope":
                    args=dict(required.arguments);payload=json.loads(args["parameters"])
                    value=outer.authority.preview(identity.uid,payload["parameters"])
                    return Observation(op_id,required,True,"root scope",json.dumps(value,sort_keys=True))
                return super().check(op_id,required,identity)
            def execute(self,op_id,prepared,identity):
                payload=json.loads(prepared.stdin)
                outer.assertEqual(payload["operation_id"],op_id)
                value=outer.authority.apply(payload["actor_uid"],payload["parameters"],op_id)
                self.calls.append((op_id,prepared))
                return Execution(op_id,prepared.argv,0,stdout=json.dumps(value))
            def verify(self,op_id,required,prepared,execution,identity):
                ok=outer.authority.verify(prepared.parameters.policy_id)["verified"] if required.identifier=="response_policy_verified" else True
                return Observation(op_id,required,ok,"scoped verification")
        peer=PeerDouble();system=PolicySystem(peer);audit=MemoryAudit();auth=Mock();auth.authorize.return_value=True
        broker=Broker(1000,["linxai-lab"],LedgerDouble(),audit,system_factory=lambda peer:system,authorizer_factory=lambda system:auth)
        request={"action":"response.network.block","parameters":self.params};op=str(uuid4())
        result=broker.handle(peer,{"version":1,"request_id":op,"request":request})
        self.assertEqual(result["status"],"succeeded",result)
        self.assertEqual(self.store.get("policy",self.params["policy_id"])["operation_id"],op)
        self.assertTrue(all(row["operation_id"]==op for row in audit.records))

    def test_block_target_always_comes_from_evidence_never_the_model(self):
        # QA 13 Nov 2026: containment no longer depends on the model. A changed target, an
        # authority claim, a malformed answer or a slow/absent model all yield the EVIDENCE
        # target with the default duration; only a well-formed matching answer sets duration.
        from security.response import DEFAULT_DURATION
        model=Mock();jobs=Mock();registry=ActionRegistry(actor_uid=1000)
        jobs.preview.side_effect=lambda request,text="":{"request":request,"text":text}
        incident={"id":self.event["id"],"evidence":self.event}
        responses=Responses(registry,jobs,model)
        target=self.event["target"]
        for answer in ({"action":"response.network.block","address":"127.0.0.2","port":4444,"duration":60},
                       {"action":"response.network.block","address":"127.0.0.1","port":4444,"duration":60,"authenticated":True},
                       "not json", TimeoutError("cold model")):
            model.generate_response.side_effect=answer if isinstance(answer,Exception) else None
            model.generate_response.return_value=answer
            params=responses.propose(incident)["request"]["parameters"]
            self.assertEqual({"address":params["address"],"port":params["port"]},target,answer)
            self.assertEqual(params["duration"],DEFAULT_DURATION,answer)
        model.generate_response.side_effect=None
        model.generate_response.return_value={"action":"response.network.block",**target,"duration":45}
        preview=responses.propose(incident)
        self.assertEqual(preview["request"]["parameters"]["duration"],45)
        self.assertIn("duration from local model",preview["text"])
        self.assertEqual(model.generate_response.call_args.kwargs["timeout"],10)     # bounded model budget
        # Without any model at all, containment still proceeds from the evidence.
        from security.response import block_request
        self.assertEqual(block_request(self.event,None)[0]["parameters"]["port"],target["port"])

    def test_known_policy_recurrence_does_not_call_model(self):
        policy=self.authority.apply(1000,self.params,str(uuid4()));self.authority.verify(policy["id"])
        incidents=MemoryStore();incident={"id":self.event["id"],"evidence":self.event,"response":"none"}
        incidents.put("incident",incident["id"],incident)
        incidents.close=lambda:None
        responses=Mock();client=Mock()
        client.call.return_value={"auto_enabled":True,"qualified":True,"policies":[self.store.get("policy",policy["id"])]}
        worker=ResponseWorker(lambda:incidents,responses,client);worker.tick()
        responses.propose.assert_not_called()
        self.assertEqual(incidents.get("incident",incident["id"])["response"],"covered_by_validated_policy")
