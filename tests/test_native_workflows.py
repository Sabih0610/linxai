"""Actual isolated stdlib provisioning/device-file/protocol tests; no real SSH/device."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from uuid import uuid4

from operations.audit import JsonlAudit
from operations.registry import ActionRegistry
from operations.service import LocalPolicy,OperationService
from operations.workflows import WorkflowSystem
from test_workflows import configured_assets


@unittest.skipUnless(sys.platform=='linux','native Linux required')
class NativeWorkflowTests(unittest.TestCase):
    def setUp(self):
        if os.getuid()==0:self.skipTest('ordinary user required')
        self.temp=self.enterContext(tempfile.TemporaryDirectory(prefix='.linxai-workflows-',dir=Path.home()))
        self.root=Path(self.temp);self.workspace=self.root/'workspace';self.workspace.mkdir(mode=0o700)
        self.device=self.root/'switch.json'
        registry=ActionRegistry(str(self.workspace),actor_uid=os.getuid(),assets_json=json.dumps(configured_assets(str(self.device))))
        self.service=OperationService(registry,WorkflowSystem(),LocalPolicy(os.getuid()),JsonlAudit(self.root/'audit.jsonl'))
    def action(self,name,parameters):return self.service.run({'action':name,'parameters':parameters})
    def test_real_python_project_is_reproducible_and_preserves_edits(self):
        first=self.action('project.scaffold',{'path':'demo'})
        self.assertEqual(first.status,'succeeded',first)
        marker=self.workspace/'demo/.venv/.linxai-environment.json';prior=marker.read_bytes()
        second=self.action('project.scaffold',{'path':'demo'})
        self.assertEqual(second.status,'succeeded',second)
        self.assertEqual(marker.read_bytes(),prior)
        # The freshly managed interpreter really starts; no packages are downloaded.
        result=subprocess.run([str(self.workspace/'demo/.venv/bin/python'),'-I','-c','import sys;print(sys.prefix)'],shell=False,capture_output=True,text=True,timeout=3)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),str(self.workspace/'demo/.venv'))
        readme=self.workspace/'demo/README.md';readme.write_text('owner edit')
        blocked=self.action('project.scaffold',{'path':'demo'})
        self.assertEqual(blocked.status,'validation_failed',blocked)
        self.assertFalse(blocked.executed);self.assertEqual(readme.read_text(),'owner edit')
    def test_real_node_project_is_idempotent_and_preserves_edits(self):
        first=self.action('project.node',{'path':'web'})
        self.assertEqual(first.status,'succeeded',first)
        package=json.loads((self.workspace/'web/package.json').read_text())
        self.assertEqual(package['scripts']['start'],'node index.js')
        index=self.workspace/'web/index.js'
        self.assertEqual(index.stat().st_mode&0o777,0o600)
        second=self.action('project.node',{'path':'web'})
        self.assertEqual(second.status,'succeeded',second)
        if Path('/usr/bin/node').is_file():
            check=subprocess.run(['/usr/bin/node','--check',str(index)],capture_output=True,text=True,timeout=10)
            self.assertEqual(check.returncode,0,check.stderr)
        index.write_text('owner edit')
        blocked=self.action('project.node',{'path':'web'})
        self.assertEqual(blocked.status,'validation_failed',blocked)
        self.assertFalse(blocked.executed);self.assertEqual(index.read_text(),'owner edit')
    def test_real_go_cpp_docker_projects_are_idempotent_private_and_preserve_edits(self):
        # 13 Nov 2026 recipes; scripts/validate_recipes.py proves they build/test/run with real toolchains.
        for action,path,edit in (('project.go','svc','main.go'),('project.cpp','tool','main.cpp'),('project.docker','box','Dockerfile')):
            first=self.action(action,{'path':path})
            self.assertEqual(first.status,'succeeded',(action,first))
            target=self.workspace/path/edit
            self.assertEqual(target.stat().st_mode&0o777,0o600)
            self.assertEqual(self.action(action,{'path':path}).status,'succeeded',action)
            target.write_text('owner edit')
            blocked=self.action(action,{'path':path})
            self.assertEqual(blocked.status,'validation_failed',(action,blocked))
            self.assertFalse(blocked.executed);self.assertEqual(target.read_text(),'owner edit')
        compose=(self.workspace/'box/compose.yaml').read_text()
        self.assertIn('"127.0.0.1:8000:8000"',compose)                    # published on loopback only
    def test_development_device_diff_apply_verified_restore_and_replay_denial(self):
        self.assertEqual(self.action('device.initialize',{'asset':'switch'}).status,'succeeded')
        inspected=self.action('device.inspect',{'asset':'switch'});revision=json.loads(inspected.stdout)['revision']
        request={'asset':'switch','interface':'port1','enabled':True,'expected_revision':revision,'transaction_id':str(uuid4())}
        applied=self.action('device.interface.set',request)
        self.assertEqual(applied.status,'succeeded',applied)
        self.assertEqual(applied.recovery,'available_for_review',applied)
        self.assertTrue(json.loads(self.device.read_text())['interfaces']['port1'])
        restored=self.service.run(applied.restoration)
        self.assertEqual(restored.status,'succeeded',restored)
        self.assertFalse(json.loads(self.device.read_text())['interfaces']['port1'])
        repeated=self.service.run(applied.restoration)
        self.assertEqual(repeated.status,'validation_failed',repeated)
        stale=self.action('device.interface.set',request)
        self.assertEqual(stale.status,'validation_failed',stale)
    def test_symlink_device_and_stale_revision_do_not_mutate_target(self):
        self.action('device.initialize',{'asset':'switch'})
        original=self.device.read_bytes()
        result=self.action('device.interface.set',{'asset':'switch','interface':'port1','enabled':True,'expected_revision':'0'*64,'transaction_id':str(uuid4())})
        self.assertEqual(result.status,'validation_failed',result);self.assertEqual(self.device.read_bytes(),original)
        outside=self.root/'outside';outside.write_text('keep')
        self.device.unlink();self.device.symlink_to(outside)
        self.assertEqual(self.action('device.inspect',{'asset':'switch'}).status,'validation_failed')
        self.assertEqual(outside.read_text(),'keep')
    def test_actual_remote_peer_protocol_and_persistent_replay_without_ssh(self):
        state=self.root/'remote';state.mkdir(mode=0o700)
        request={'version':1,'operation_id':str(uuid4()),'request':{'action':'memory.usage','parameters':{}}}
        command=[sys.executable,'-I','-B','-m','operations.remote_peer','--state',str(state)]
        # The transport contract bounds the full peer lifecycle, not only its command.
        timeout=self.service.registry.prepare('remote.operation', {'asset':'lab','action':'memory.usage','parameters':{}}).contract.timeout_s
        result=subprocess.run(command,input=json.dumps(request),shell=False,capture_output=True,text=True,timeout=timeout)
        self.assertEqual(result.returncode,0,result.stderr)
        reply=json.loads(result.stdout)
        self.assertEqual(reply['uid'],os.getuid());self.assertEqual(reply['result']['operation_id'],request['operation_id'])
        self.assertTrue(reply['result']['verified'])
        repeated=subprocess.run(command,input=json.dumps(request),shell=False,capture_output=True,text=True,timeout=timeout)
        self.assertNotEqual(repeated.returncode,0)
