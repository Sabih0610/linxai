"""Shared adapters for typed recipes, strict SSH peers and development devices."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .service import Observation
from .supervised import SupervisedLinuxAdapter
from .workflow_contracts import WORKFLOWS


def assets(path,uid):
    path=Path(path)
    if not path.exists():return '{}'
    SupervisedLinuxAdapter()._directories(path.parent,uid,private_leaf=True)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or info.st_nlink!=1 or info.st_mode&0o077:raise PermissionError('Private owned assets configuration required')
        data=stream.read(65537)
    if len(data)>65536:raise ValueError('Assets configuration exceeds bound')
    value=json.loads(data)
    if not isinstance(value,dict) or len(value)>32:raise ValueError('At most 32 named assets supported')
    for name,item in value.items():
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,31}',name) or not isinstance(item,dict):raise ValueError('Invalid named asset')
    return json.dumps(value,sort_keys=True)


class WorkflowSystem(SupervisedLinuxAdapter):
    def check(self,op_id,required,identity):
        args=dict(required.arguments)
        try:
            if required.identifier=='workflow_prerequisites':
                from ._workflow_program import WORKFLOW_PROGRAM
                result=self._run(op_id,('/usr/bin/python3','-I','-c',WORKFLOW_PROGRAM,'check'),args['payload'].encode(),5)
                ok=not result.error and result.returncode==0
                return Observation(op_id,required,ok,'Workflow prerequisites checked' if ok else result.error or result.stderr[:1024],result.stdout)
            if required.identifier=='remote_asset_safe':
                asset=json.loads(args['asset_json']);evidence=[]
                from vps.server_types import VPSServer
                server=VPSServer('',asset['host'],asset['port'],asset['username'],asset['key_path'])
                for name,private in ((server.key_path,True),(asset['known_hosts'],False)):
                    path=Path(name)
                    if not path.is_absolute():raise ValueError('Absolute owner-configured SSH files required')
                    self._directories(path.parent,identity.uid)
                    info=path.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_uid not in ({identity.uid} if private else {0,identity.uid}) or info.st_nlink!=1 or info.st_mode&(0o077 if private else 0o022):raise PermissionError('Unsafe SSH identity/known-hosts file')
                    evidence.append([str(path),info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns])
                    if not private:
                        with path.open('rb') as stream:data=stream.read(1048577)
                        if not data or len(data)>1048576:raise ValueError('Known hosts missing or exceeds bound')
                        evidence.append(hashlib.sha256(data).hexdigest())
                return Observation(op_id,required,True,'Pinned SSH peer files verified',json.dumps(evidence,sort_keys=True))
        except Exception as exc:return Observation(op_id,required,False,type(exc).__name__+': '+str(exc)[:1024])
        return super().check(op_id,required,identity)

    def verify(self,op_id,required,prepared,execution,identity):
        args=dict(required.arguments)
        try:
            if required.identifier=='workflow_verified':
                argv=prepared.argv[:-1]+('verify',)
                result=self._run(op_id,argv,prepared.stdin,5)
                value=json.loads(result.stdout) if not result.error and result.returncode==0 else {}
                return Observation(op_id,required,value.get('verified') is True,'Workflow postconditions verified' if value else result.error or result.stderr[:1024])
            if required.identifier=='remote_operation_verified':
                value=json.loads(execution.stdout)
                result=value['result']
                ok=type(value['uid']) is int and value['uid']==args['expected_uid'] and result['operation_id']==op_id and result['status']=='succeeded' and result['verified'] is True
                return Observation(op_id,required,ok,'Pinned peer typed operation result checked')
        except Exception as exc:return Observation(op_id,required,False,type(exc).__name__)
        return super().verify(op_id,required,prepared,execution,identity)

    def recovery_request(self,prepared,execution):
        if prepared.contract.identifier!='device.interface.set':return None
        value=json.loads(execution.stdout)
        return value.get('restoration') if value.get('verified') is True else None
