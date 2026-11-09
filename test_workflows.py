"""Typed recipe/SSH/device contracts; no real remote services or devices."""
import json
import unittest
from unittest.mock import Mock
from uuid import uuid4
from ai.local_planner import Planner
from operations.registry import ActionRegistry


def configured_assets(path='/srv/work/switch.json'):
    return {'switch':{'platform':'development_file','path':path,'ports':['port1','Ethernet1/1']},
            'lab':{'platform':'linux_ssh','host':'example.invalid','username':'owner','port':22,'expected_uid':1000,
                   'python':'/home/owner/.local/share/linxai/venv/bin/python','key_path':'/home/owner/.ssh/key','known_hosts':'/home/owner/.ssh/known_hosts'}}


class WorkflowTests(unittest.TestCase):
    def setUp(self):self.registry=ActionRegistry('/srv/work',actor_uid=1000,assets_json=json.dumps(configured_assets()))
    def test_python_recipe_and_remote_natural_language_use_same_registry(self):
        model=Mock();planner=Planner(self.registry,model)
        request,_=planner.propose('create a python project in demo')
        self.assertEqual(request,{'action':'project.scaffold','parameters':{'path':'demo'}})
        for text in ('create a node project in web','scaffold a nodejs app in web','create an express app in web'):
            request,_=planner.propose(text)
            self.assertEqual(request,{'action':'project.node','parameters':{'path':'web'}})
        with self.assertRaises(ValueError):self.registry.prepare('project.node',{'path':'../escape'})
        request,_=planner.propose('on lab show memory usage')
        self.assertEqual(request['action'],'remote.operation')
        self.assertEqual(request['parameters']['action'],'memory.usage')
        model.generate.assert_not_called()
    def test_strict_ssh_array_and_no_caller_command_or_recursive_request(self):
        prepared=self.registry.prepare('remote.operation',{'asset':'lab','action':'memory.usage','parameters':{}})
        self.assertEqual(prepared.argv[0],'/usr/bin/ssh')
        self.assertIn('StrictHostKeyChecking=yes',prepared.argv)
        self.assertIn('/dev/null',prepared.argv)
        self.assertNotIn('AutoAddPolicy',str(prepared))
        self.assertIn('operations.remote_peer',prepared.argv[-1])
        for params in ({'asset':'lab','action':'shell','parameters':{}},{'asset':'lab','action':'remote.operation','parameters':{}},
                       {'asset':'lab','action':'memory.usage','parameters':{},'command':'id'}):
            with self.assertRaises(ValueError):self.registry.prepare('remote.operation',params)
    def test_workspace_unknown_assets_paths_and_interface_parameters_fail(self):
        for path in ('../escape','/other/project','x/../project'):
            with self.assertRaises(ValueError):self.registry.prepare('environment.python',{'path':path})
        with self.assertRaises(ValueError):self.registry.prepare('device.inspect',{'asset':'unknown'})
        base={'asset':'switch','interface':'port1','enabled':True,'expected_revision':'0'*64,'transaction_id':str(uuid4())}
        for key,value in (('interface','../port1'),('enabled',1),('expected_revision','unbound'),('transaction_id','not-uuid')):
            params={**base,key:value}
            with self.assertRaises(ValueError):self.registry.prepare('device.interface.set',params)
    def test_unknown_platform_explicit_and_no_model_for_unknown_remote(self):
        data=configured_assets();data['switch']['platform']='unspecified_vendor'
        registry=ActionRegistry('/srv/work',actor_uid=1000,assets_json=json.dumps(data))
        with self.assertRaises(ValueError):registry.prepare('device.inspect',{'asset':'switch'})
        model=Mock()
        with self.assertRaises(ValueError):Planner(registry,model).propose('on unknown do something')
        model.generate.assert_not_called()

    def test_netconf_device_assets_are_strict_and_pinned(self):
        # Network-device extension: vendor-neutral NETCONF/OpenConfig through the same typed device actions.
        base={'platform':'netconf','host':'192.0.2.10','port':830,'username':'netops','key_path':'/home/owner/.ssh/netconf',
              'host_key_sha256':'SHA256:'+'A'*43,'state_dir':'/home/owner/.linxai/netconf','ports':['ge-0/0/1','Ethernet1/1']}
        registry=ActionRegistry('/srv/work',actor_uid=1000,assets_json=json.dumps({'core':base}))
        prepared=registry.prepare('device.inspect',{'asset':'core'})
        self.assertEqual(prepared.argv[:3],('/usr/bin/python3','-I','-c'))
        self.assertIn("platform')=='netconf'",prepared.argv[3])
        compile(prepared.argv[3],'workflow','exec')
        params={'asset':'core','interface':'ge-0/0/1','enabled':False,'expected_revision':'0'*64,'transaction_id':str(uuid4())}
        self.assertEqual(registry.prepare('device.interface.set',params).parameters.interface,'ge-0/0/1')
        with self.assertRaises(ValueError):registry.prepare('device.interface.set',{**params,'interface':'ge-0/0/9'})
        for change in ({'host_key_sha256':'SHA256:short'},{'host_key_sha256':None},{'host':'evil host;id'},{'port':0},
                       {'key_path':'relative/key'},{'extra':'field'},{'ports':[]}):
            bad=dict(base,**change)
            if change.get('host_key_sha256',1) is None:bad.pop('host_key_sha256')
            reg=ActionRegistry('/srv/work',actor_uid=1000,assets_json=json.dumps({'core':bad}))
            with self.assertRaises(ValueError,msg=change):reg.prepare('device.inspect',{'asset':'core'})

    def test_agentless_targets_use_fixed_templates_only(self):
        # Agentless extension: no LINxAI on the target; pinned SSH; fixed command templates.
        asset={'platform':'linux_agentless','host':'192.0.2.30','port':22,'username':'ops','key_path':'/home/owner/.ssh/k',
               'known_hosts':'/home/owner/.ssh/known_hosts','systemd_scope':'system'}
        registry=ActionRegistry('/srv/work',actor_uid=1000,assets_json=json.dumps({'srv':asset}))
        prepared=registry.prepare('remote.operation',{'asset':'srv','action':'service.restart','parameters':{'service':'nginx'}})
        self.assertEqual(json.loads(prepared.parameters.parameters_json),{'service':'nginx.service'})
        self.assertIn("sudo', '-n'",prepared.argv[3]); compile(prepared.argv[3],'workflow','exec')
        self.assertIn('remote_asset_safe',[c.identifier for c in prepared.mandatory_checks])
        for action,params in (('file.create',{'path':'x'}),('shell',{}),('remote.operation',{}),('service.status',{'service':'a b'}),
                              ('service.status',{'service':'ssh; reboot'}),('ports.listen',{'port':70000})):
            with self.assertRaises(ValueError,msg=action):registry.prepare('remote.operation',{'asset':'srv','action':action,'parameters':params})
        for change in ({'systemd_scope':'root'},{'known_hosts':'relative'},{'extra':1},{'host':'bad host'}):
            reg=ActionRegistry('/srv/work',actor_uid=1000,assets_json=json.dumps({'srv':dict(asset,**change)}))
            with self.assertRaises(ValueError,msg=change):reg.prepare('remote.operation',{'asset':'srv','action':'memory.usage','parameters':{}})

    def test_nested_remote_input_is_rejected_before_recursing_or_model(self):
        values=configured_assets();values['a']=values['lab']
        registry=ActionRegistry('/srv/work',actor_uid=1000,assets_json=json.dumps(values))
        model=Mock()
        with self.assertRaisesRegex(ValueError,'Nested remote'):
            Planner(registry,model).propose('on a '*1100+'show memory usage')
        model.generate.assert_not_called()
