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
