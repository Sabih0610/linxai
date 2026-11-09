"""Typed environment, DevOps, strict remote and development-device contracts."""
from dataclasses import dataclass, asdict
import json
from pathlib import PurePosixPath
import re
import shlex
from uuid import UUID
from ._workflow_program import WORKFLOW_PROGRAM
from . import iot_contracts


@dataclass(frozen=True)
class Project:
    path:str
@dataclass(frozen=True)
class Device:
    asset:str
@dataclass(frozen=True)
class Interface:
    asset:str
    interface:str
    enabled:bool
    expected_revision:str
    transaction_id:str
@dataclass(frozen=True)
class Restore:
    asset:str
    transaction_id:str
    expected_revision:str
@dataclass(frozen=True)
class Remote:
    asset:str
    action:str
    parameters_json:str

WORKFLOWS=frozenset({'environment.python','project.scaffold','project.node','device.initialize','device.inspect','device.interface.set','device.interface.restore','remote.operation'})|iot_contracts.IOT_ACTIONS
TYPES=(Project,Device,Interface,Restore,Remote,*iot_contracts.TYPES)


def _netconf_asset(asset,InvalidParameters):
    """Owner-configured NETCONF device (vendor-neutral OpenConfig; see _netconf_program)."""
    expected={'platform','host','port','username','key_path','host_key_sha256','state_dir','ports'}
    if set(asset)!=expected:raise InvalidParameters('NETCONF asset requires exactly: '+', '.join(sorted(expected)))
    if not isinstance(asset['host'],str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}',asset['host']):raise InvalidParameters('Invalid NETCONF host')
    if type(asset['port']) is not int or not 1<=asset['port']<=65535:raise InvalidParameters('Invalid NETCONF port')
    if not isinstance(asset['username'],str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}',asset['username']):raise InvalidParameters('Invalid NETCONF username')
    if not isinstance(asset['host_key_sha256'],str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',asset['host_key_sha256']):raise InvalidParameters('Pinned SHA256 host key fingerprint required')
    for field in ('key_path','state_dir'):
        if not isinstance(asset[field],str) or not asset[field].startswith('/') or len(asset[field])>4095 or '\x00' in asset[field]:raise InvalidParameters('Absolute key and state paths required')


AGENTLESS_ACTIONS=frozenset({'disk.usage','memory.usage','ports.listen','service.status','service.start','service.stop','service.restart'})


def _agentless(registry,contract,name,asset,parameters):
    """Agentless Linux target: fixed command templates over pinned SSH (see _agentless_program)."""
    from .registry import ActionRegistry, InvalidParameters, PreparedAction, requirement
    expected={'platform','host','port','username','key_path','known_hosts'}|({'systemd_scope'} if asset.get('platform')=='linux_agentless' else set())
    if set(asset)!=expected:raise InvalidParameters('Agentless asset requires exactly: '+', '.join(sorted(expected)))
    for field in ('host','username'):
        if not isinstance(asset[field],str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}',asset[field]):raise InvalidParameters('Invalid configured SSH endpoint')
    if type(asset['port']) is not int or not 1<=asset['port']<=65535:raise InvalidParameters('Invalid SSH port')
    for field in ('key_path','known_hosts'):
        if not isinstance(asset[field],str) or not asset[field].startswith('/') or len(asset[field])>4095 or '\x00' in asset[field]:raise InvalidParameters('Absolute bounded SSH metadata paths required')
    if asset['platform']=='linux_agentless' and asset['systemd_scope'] not in {'system','user'}:raise InvalidParameters('systemd_scope must be system or user')
    if parameters['action'] not in AGENTLESS_ACTIONS:raise InvalidParameters('Action not available agentlessly; no raw commands')
    nested=ActionRegistry('/remote-permitted',actor_uid=registry.actor_uid).prepare(parameters['action'],parameters['parameters'])
    values=asdict(nested.parameters) if parameters['action']!='ports.listen' else {k:v for k,v in asdict(nested.parameters).items() if k=='port'}
    if 'service' in values:values={'service':values['service']}
    encoded=json.dumps(values,sort_keys=True,separators=(',',':'),allow_nan=False)
    typed=Remote(name,parameters['action'],encoded)
    payload={'action':'remote.operation','parameters':asdict(typed),'asset':asset}
    checks=(requirement('linux_runtime'),requirement('trusted_executable',path='/usr/bin/ssh'),
            requirement('remote_asset_safe',asset_json=json.dumps(asset,sort_keys=True)),
            requirement('workflow_prerequisites',payload=json.dumps(payload,sort_keys=True)))
    post=(requirement('exit_code',value=0),requirement('workflow_verified',payload=json.dumps(payload,sort_keys=True)))
    return PreparedAction(contract,typed,('/usr/bin/python3','-I','-c',WORKFLOW_PROGRAM,'apply'),checks,post,json.dumps(payload,sort_keys=True).encode())


def prepare(registry,identifier,parameters,contract):
    from .registry import ActionRegistry, InvalidParameters, PreparedAction, requirement
    if registry.actor_uid is None:raise InvalidParameters('Backend OS actor required')
    assets=json.loads(registry.assets_json)
    asset={}
    if identifier in {'environment.python','project.scaffold','project.node'}:
        if set(parameters)!={'path'}:raise InvalidParameters('Exact project path required')
        typed=Project(registry.relative_path(parameters['path']))
        payload={'action':identifier,'parameters':asdict(typed),'workspace':registry.permitted_workspace}
    else:
        name=parameters.get('asset')
        if not isinstance(name,str) or name not in assets:raise InvalidParameters('Unknown backend-configured asset')
        asset=assets[name]
        if identifier in iot_contracts.IOT_ACTIONS:
            typed=iot_contracts.typed(identifier,name,asset,parameters,InvalidParameters)
            payload={'action':identifier,'parameters':asdict(typed),'asset':asset}
            checks=(requirement('linux_runtime'),requirement('trusted_executable',path='/usr/bin/python3'),
                    requirement('workflow_prerequisites',payload=json.dumps(payload,sort_keys=True)))
            post=(requirement('exit_code',value=0),requirement('workflow_verified',payload=json.dumps(payload,sort_keys=True)))
            return PreparedAction(contract,typed,('/usr/bin/python3','-I','-c',WORKFLOW_PROGRAM,'apply'),checks,post,json.dumps(payload,sort_keys=True).encode())
        if identifier=='remote.operation':
            if set(parameters)!={'asset','action','parameters'}:raise InvalidParameters('Exact remote action fields required')
            if asset.get('platform') in {'linux_agentless','windows_agentless'}:return _agentless(registry,contract,name,asset,parameters)
            if asset.get('platform')!='linux_ssh':raise InvalidParameters('Asset is not a configured Linux SSH peer')
            allowed={'disk.usage','memory.usage','ports.listen','service.status','file.create','directory.create','service.start','service.stop','service.restart'}
            if parameters['action'] not in allowed:raise InvalidParameters('Remote action not admitted; no recursion/raw commands')
            # Validate nested parameters with a lexical remote workspace; the peer supplies its own real root.
            ActionRegistry('/remote-permitted',actor_uid=asset['expected_uid']).prepare(parameters['action'],parameters['parameters'])
            encoded=json.dumps(parameters['parameters'],sort_keys=True,separators=(',',':'),allow_nan=False)
            if len(encoded.encode())>32768:raise InvalidParameters('Remote parameters exceed bound')
            typed=Remote(name,parameters['action'],encoded)
            peer=asset['python']
            if not isinstance(peer,str) or not peer.startswith('/') or not re.fullmatch(r'python(?:3(?:\.[0-9]+)?)?',PurePosixPath(peer).name):raise InvalidParameters('Configured peer interpreter required')
            for field in ('host','username'):
                if not isinstance(asset.get(field),str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}',asset[field]):raise InvalidParameters('Invalid configured SSH endpoint')
            if type(asset.get('port')) is not int or not 1<=asset['port']<=65535 or type(asset.get('expected_uid')) is not int or asset['expected_uid']<=0:raise InvalidParameters('Invalid SSH port/UID')
            for field in ('key_path','known_hosts'):
                if not isinstance(asset.get(field),str) or not asset[field].startswith('/') or len(asset[field])>4095 or '\x00' in asset[field]:raise InvalidParameters('Absolute bounded SSH metadata paths required')
            argv=('/usr/bin/ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                  '-o','UpdateHostKeys=no','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','ForwardAgent=no',
                  '-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','ControlMaster=no',
                  '-o','ConnectTimeout=5','-o','GlobalKnownHostsFile=/dev/null','-o','UserKnownHostsFile='+asset['known_hosts'],
                  '-i',asset['key_path'],'-p',str(asset['port']),'--',asset['username']+'@'+asset['host'],
                  shlex.join([peer,'-I','-B','-m','operations.remote_peer']))
            stdin=json.dumps({'version':1,'request':{'action':typed.action,'parameters':parameters['parameters']}},sort_keys=True).encode()
            checks=(requirement('linux_runtime'),requirement('trusted_executable',path='/usr/bin/ssh'),
                    requirement('remote_asset_safe',asset_json=json.dumps(asset,sort_keys=True)))
            post=(requirement('exit_code',value=0),requirement('remote_operation_verified',expected_uid=asset['expected_uid']))
            return PreparedAction(contract,typed,argv,checks,post,stdin)
        if asset.get('platform')=='netconf':_netconf_asset(asset,InvalidParameters)
        elif asset.get('platform')!='development_file':raise InvalidParameters('Unsupported device platform; no vendor compatibility implied')
        elif not isinstance(asset.get('path'),str) or not asset['path'].startswith('/'):raise InvalidParameters('Invalid development device configuration')
        if not isinstance(asset.get('ports'),list) or not 1<=len(asset['ports'])<=64:raise InvalidParameters('Configured interface allowlist required')
        if any(not isinstance(port,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_./:-]{0,31}',port) or '..' in port for port in asset['ports']):raise InvalidParameters('Malformed configured interface')
        if identifier in {'device.initialize','device.inspect'}:
            if set(parameters)!={'asset'}:raise InvalidParameters('Exact device fields required')
            typed=Device(name)
        else:
            expected={'asset','transaction_id','expected_revision'}|({'interface','enabled'} if identifier=='device.interface.set' else set())
            if set(parameters)!=expected:raise InvalidParameters('Exact interface/restore fields required')
            token=parameters['transaction_id']
            if not isinstance(token,str) or str(UUID(token))!=token:raise InvalidParameters('Canonical transaction UUID required')
            revision=parameters['expected_revision']
            if not isinstance(revision,str) or not re.fullmatch(r'[0-9a-f]{64}',revision):raise InvalidParameters('Expected revision SHA256 required')
            if identifier=='device.interface.set':
                if parameters['interface'] not in asset['ports'] or type(parameters['enabled']) is not bool:raise InvalidParameters('Configured interface and boolean state required')
                typed=Interface(name,parameters['interface'],parameters['enabled'],revision,token)
            else:typed=Restore(name,token,revision)
        payload={'action':identifier,'parameters':asdict(typed),'asset':asset}
    checks=(requirement('linux_runtime'),requirement('trusted_executable',path='/usr/bin/python3'),
            requirement('workflow_prerequisites',payload=json.dumps(payload,sort_keys=True)))
    post=(requirement('exit_code',value=0),requirement('workflow_verified',payload=json.dumps(payload,sort_keys=True)))
    return PreparedAction(contract,typed,('/usr/bin/python3','-I','-c',WORKFLOW_PROGRAM,'apply'),checks,post,json.dumps(payload,sort_keys=True).encode())
