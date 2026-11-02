"""Fixed SSH endpoint. OS login identity and remote config define authority."""
from dataclasses import asdict
import json
import argparse
import os
from pathlib import Path
import select
import sys
import time

from .audit import JsonlAudit
from .broker import BrokerClient
from .ipc import request_id,unique
from .registry import ActionRegistry,Privilege
from .service import LocalPolicy,OperationService
from .store import Store
from .workflows import WorkflowSystem


class PeerService(OperationService):
    def __init__(self,operation_id,*args):
        super().__init__(*args);self.operation_id=operation_id
    def _new_operation_id(self):return self.operation_id


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state",default=str(Path.home()/".linxai"))
    args=parser.parse_args()
    system=WorkflowSystem();identity=system.resolve_identity()
    if not identity.ordinary():raise PermissionError('Remote endpoint requires ordinary SSH login')
    deadline=time.monotonic()+5;data=bytearray()
    while True:
        remaining=deadline-time.monotonic()
        if remaining<=0 or not select.select([sys.stdin.buffer],[],[],remaining)[0]:raise TimeoutError('Remote request deadline')
        chunk=os.read(sys.stdin.fileno(),8192)
        if not chunk:break
        data.extend(chunk)
        if len(data)>65536:raise ValueError('Remote request exceeds bound')
    envelope=json.loads(data,object_pairs_hook=unique)
    if not isinstance(envelope,dict) or set(envelope)!={'version','operation_id','request'} or type(envelope['version']) is not int or envelope['version']!=1:raise ValueError('Remote protocol version 1 required')
    operation_id=request_id(envelope['operation_id'])
    state=Path(args.state).absolute()
    store=Store(state/'remote.sqlite')
    config_path=state/'remote.json'
    workspace=None
    if config_path.exists():
        fd=os.open(config_path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            import stat
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=identity.uid or info.st_mode&0o077 or info.st_nlink!=1:raise PermissionError('Private remote config required')
            raw=stream.read(8193)
        if len(raw)>8192:raise ValueError('Remote configuration exceeds bound')
        config=json.loads(raw)
        if set(config)!={'workspace'}:raise ValueError('Unknown remote configuration')
        workspace=config['workspace']
    registry=ActionRegistry(workspace,actor_uid=identity.uid)
    request=envelope['request']
    if not isinstance(request,dict) or set(request)!={'action','parameters'} or request['action'] not in {'disk.usage','memory.usage','ports.listen','service.status','file.create','directory.create','service.start','service.stop','service.restart'}:raise ValueError('Unsupported remote request')
    prepared=registry.prepare(request['action'],request['parameters'])
    store.put('remote_request',operation_id,{'state':'admitted'},replace=False,limit=10000)
    if prepared.contract.privilege is Privilege.AUTHENTICATED_ADMIN:
        result=BrokerClient().run(request,operation_id=operation_id)
    else:
        service=PeerService(operation_id,registry,system,LocalPolicy(identity.uid),JsonlAudit(state/'remote-audit.jsonl'))
        result=service.run(request)
    store.put('remote_request',operation_id,asdict(result),limit=10000)
    value=asdict(result)
    for key in ('stdout','stderr'):value[key]=value[key][:8192]
    print(json.dumps({'version':1,'uid':identity.uid,'result':value},sort_keys=True))


if __name__=='__main__':main()
