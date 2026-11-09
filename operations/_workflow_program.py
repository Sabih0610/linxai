"""Fixed ordinary-user recipe/device worker; no caller executable or shell text."""
WORKFLOW_PROGRAM = r'''
import fcntl, hashlib, importlib.util, json, os, pathlib, stat, sys, time, uuid, venv
if sys.platform != 'linux' or os.getuid()==0 or os.getuid()!=os.geteuid() or os.getgid()!=os.getegid():
    raise PermissionError('Ordinary Linux user required')
uid=os.getuid()
os.umask(0o077)
raw=sys.stdin.buffer.read(65537)
if len(raw)>65536: raise ValueError('Workflow payload exceeds bound')
request=json.loads(raw)
mode=sys.argv[1]
action=request['action'];params=request['parameters']
def chain(path,private=False):
    path=pathlib.Path(path)
    for part in reversed((path,*path.parents)):
        info=part.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,uid) or info.st_mode&0o022:
            raise PermissionError('Unsafe directory/symlink chain')
    if private and (info.st_uid!=uid or info.st_mode&0o077): raise PermissionError('Private owned directory required')
    return [info.st_dev,info.st_ino,info.st_uid,info.st_mode]
def read(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or info.st_mode&0o077 or info.st_nlink!=1:
            raise PermissionError('Private singly-linked owned regular file required')
        data=stream.read(65537)
    if len(data)>65536:raise ValueError('File exceeds bound')
    return data
def atomic(path,data,exclusive=False):
    chain(path.parent,True)
    temp=path.parent/('.linxai-'+uuid.uuid4().hex)
    fd=os.open(path if exclusive else temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        if not exclusive:os.replace(temp,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if temp.exists():temp.unlink()
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def revision(value):return hashlib.sha256(encoded(value)).hexdigest()
if action=='project.node':
    root=pathlib.Path(request['workspace']);chain(root,True)
    relative=pathlib.PurePosixPath(params['path'])
    if relative.is_absolute() or any(part in ('','.','..') for part in relative.parts):raise ValueError('Invalid relative project')
    project=root.joinpath(*relative.parts);chain(project.parent)
    existing=project.exists()
    if existing:chain(project,True)
    runtime='/usr/bin/node'
    expected={'schema':1,'recipe':'node-stdlib-v1','runtime':runtime}
    templates={'package.json':b'{\n  "name": "linxai-node-project",\n  "version": "0.1.0",\n  "private": true,\n  "type": "module",\n  "scripts": {"start": "node index.js"},\n  "engines": {"node": ">=18"}\n}\n',
               'index.js':b'import http from "node:http";\nconst port = Number(process.env.PORT || 3000);\nhttp.createServer((req, res) => {\n  res.writeHead(200, {"content-type": "application/json"});\n  res.end(JSON.stringify({status: "ok"}));\n}).listen(port, "127.0.0.1", () => console.log("listening on 127.0.0.1:" + port));\n',
               'README.md':b'# Managed Node.js project\nRun with npm start (or node index.js). Dependencies are not downloaded.\n',
               '.gitignore':b'node_modules/\n'}
    marker=project/'.linxai-node.json'
    for name,data in templates.items():
        if os.path.lexists(project/name) and read(project/name)!=data:raise ValueError('Existing recipe file differs; no overwrite')
    if os.path.lexists(marker) and json.loads(read(marker)).get('recipe')!=expected['recipe']:raise ValueError('Existing project is not this managed recipe; review')
    before={'project_exists':existing,'parent':chain(project.parent),'managed':os.path.lexists(marker),'recipe':expected,
            'runtime_present':os.path.isfile(runtime)}
    if mode=='check':print(json.dumps(before));raise SystemExit(0)
    if mode=='apply':
        if not existing:project.mkdir(mode=0o700)
        chain(project,True)
        for name,data in templates.items():
            if not os.path.lexists(project/name):atomic(project/name,data,True)
        if not os.path.lexists(marker):atomic(marker,encoded(expected),True)
    elif not os.path.lexists(marker):raise ValueError('Node project missing')
    for name,data in templates.items():
        if read(project/name)!=data:raise ValueError('Node project verification failed')
    if json.loads(read(marker))!=expected:raise ValueError('Node project marker differs')
    print(json.dumps({'verified':True,'project':str(project),'recipe':expected,'created':not existing,'runtime_present':os.path.isfile(runtime)}))
elif action in ('environment.python','project.scaffold'):
    root=pathlib.Path(request['workspace']);chain(root,True)
    relative=pathlib.PurePosixPath(params['path'])
    if relative.is_absolute() or any(part in ('','.','..') for part in relative.parts):raise ValueError('Invalid relative project')
    project=root.joinpath(*relative.parts);chain(project.parent)
    existing=project.exists()
    if existing:chain(project,True)
    marker=project/'.venv'/'.linxai-environment.json'
    expected={'schema':1,'recipe':'python-stdlib-v1','base':os.path.realpath(sys.executable)}
    base_digest=hashlib.sha256(pathlib.Path(expected['base']).read_bytes()).hexdigest()
    expected['interpreter_sha256']=base_digest
    if project.exists() and (project/'.venv').exists():
        chain(project/'.venv',True)
        if json.loads(read(marker))!=expected:raise ValueError('Existing environment is not this managed recipe; review')
        binary=project/'.venv/bin/python'
        info=binary.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or info.st_nlink!=1 or hashlib.sha256(binary.read_bytes()).hexdigest()!=base_digest:
            raise ValueError('Existing interpreter identity differs; never execute it for verification')
    elif mode=='verify':raise ValueError('Environment missing')
    if importlib.util.find_spec('venv') is None:raise RuntimeError('OS venv module unavailable')
    templates={'README.md':b'# Managed Python project\nUse .venv/bin/python explicitly. Dependencies are not downloaded.\n',
               'app.py':b'print("Hello from LINxAI")\n',
               'pyproject.toml':b'[project]\nname="linxai-project"\nversion="0.1.0"\nrequires-python=">=3.11"\ndependencies=[]\n'}
    if action=='project.scaffold' and existing:
        for name,data in templates.items():
            path=project/name
            if os.path.lexists(path) and read(path)!=data:raise ValueError('Existing recipe file differs; no overwrite')
    before={'project_exists':existing,'parent':chain(project.parent),'managed_environment':marker.exists(),'recipe':expected}
    if mode=='check':print(json.dumps(before));raise SystemExit(0)
    if mode=='apply' and not marker.exists():
        if not existing:project.mkdir(mode=0o700)
        chain(project,True)
        target=project/'.venv';target.mkdir(mode=0o700)
        fd=os.open(project,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            anchor='/proc/self/fd/'+str(fd)+'/.venv'
            venv.EnvBuilder(with_pip=False,symlinks=False).create(anchor)
            # Restore usable activation paths after fd-anchored generation.
            for name in ('activate','activate.csh','activate.fish','Activate.ps1'):
                path=target/'bin'/name
                if path.exists():
                    info=path.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('Unsafe activation file')
                    data=path.read_bytes().replace(anchor.encode(),str(target).encode())
                    atomic(path,data)
            atomic(marker,encoded(expected),True)
        finally:os.close(fd)
    if action=='project.scaffold':
        templates={'README.md':b'# Managed Python project\nUse .venv/bin/python explicitly. Dependencies are not downloaded.\n',
                   'app.py':b'print("Hello from LINxAI")\n',
                   'pyproject.toml':b'[project]\nname="linxai-project"\nversion="0.1.0"\nrequires-python=">=3.11"\ndependencies=[]\n'}
        for name,data in templates.items():
            path=project/name
            if os.path.lexists(path):
                if read(path)!=data:raise ValueError('Existing project file differs; no overwrite')
            elif mode=='apply':atomic(path,data,True)
            else:raise ValueError('Recipe file missing')
    if json.loads(read(marker))!=expected:raise ValueError('Environment verification failed')
    print(json.dumps({'verified':True,'project':str(project),'recipe':expected,'created':not existing}))
else:
    asset=request['asset'];path=pathlib.Path(asset['path']);chain(path.parent,True)
    lock=os.open(path.parent/(path.name+'.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    info=os.fstat(lock)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or info.st_nlink!=1 or info.st_mode&0o077:raise PermissionError('Unsafe device lock')
    fcntl.flock(lock,fcntl.LOCK_EX)
    def device():
        value=json.loads(read(path))
        if set(value)!= {'schema','platform','interfaces'} or value['schema']!=1 or value['platform']!='development_file':raise ValueError('Unsupported device schema')
        if set(value['interfaces'])!=set(asset['ports']) or any(type(up) is not bool for up in value['interfaces'].values()):raise ValueError('Invalid configured interfaces')
        return value
    if not path.exists():
        if action!='device.initialize' or mode=='verify':raise ValueError('Configured development device missing')
        if mode=='check':print(json.dumps({'device_absent':True,'parent':chain(path.parent,True)}));raise SystemExit(0)
        atomic(path,encoded({'schema':1,'platform':'development_file','interfaces':{port:False for port in asset['ports']}}),True)
    value=device();current=revision(value)
    if action in ('device.initialize','device.inspect'):
        print(json.dumps({'verified':True,'platform':'development_file','device':value,'revision':current}));raise SystemExit(0)
    transactions=path.parent/(path.name+'.transactions')
    if transactions.exists():chain(transactions,True)
    token=params['transaction_id'];uuid.UUID(token)
    transaction=transactions/(token+'.json')
    if action=='device.interface.set':
        desired=json.loads(json.dumps(value));desired['interfaces'][params['interface']]=params['enabled']
        if mode in ('check','apply') and current!=params['expected_revision']:raise ValueError('Device state changed; inspect and preview again')
        if mode=='check':
            if transaction.exists():raise ValueError('Consumed device transaction ID')
            print(json.dumps({'revision':current,'before':value['interfaces'][params['interface']],'after':params['enabled']}));raise SystemExit(0)
        if mode=='apply':
            if not transactions.exists():transactions.mkdir(mode=0o700)
            if sum(1 for _ in transactions.iterdir())>=1000:raise ValueError('Transaction retention full; archive before mutation')
            snapshot={'schema':1,'asset':params['asset'],'uid':uid,'prior':value,'after':revision(desired),'created':time.time(),'state':'captured','operation_id':request['operation_id']}
            atomic(transaction,encoded(snapshot),True)
            atomic(path,encoded(desired));value=device();current=revision(value)
        saved=json.loads(read(transaction))
        if value['interfaces'][params['interface']]!=params['enabled'] or current!=saved['after']:raise ValueError('Device postcondition failed')
        restoration={'action':'device.interface.restore','parameters':{'asset':params['asset'],'transaction_id':token,'expected_revision':current}}
        print(json.dumps({'verified':True,'platform':'development_file','revision':current,'restoration':restoration,'diff':{'interface':params['interface'],'from':saved['prior']['interfaces'][params['interface']],'to':params['enabled']}}))
    elif action=='device.interface.restore':
        saved=json.loads(read(transaction))
        if saved['asset']!=params['asset'] or saved['uid']!=uid or time.time()-saved['created']>300:raise ValueError('Restoration scope/expiry mismatch')
        if mode in ('check','apply') and (saved['state']!='captured' or current!=params['expected_revision'] or current!=saved['after']):raise ValueError('Restoration stale, consumed or altered')
        if mode=='check':print(json.dumps({'revision':current,'prior':revision(saved['prior']),'transaction':token}));raise SystemExit(0)
        if mode=='apply':
            atomic(path,encoded(saved['prior']));saved['state']='restored';atomic(transaction,encoded(saved))
        if device()!=saved['prior']:raise ValueError('Restoration postcondition failed')
        print(json.dumps({'verified':True,'platform':'development_file','restored':True,'revision':revision(saved['prior'])}))
    else:raise ValueError('Unsupported workflow action')
'''


def _with_netconf(program):
    """Insert the NETCONF device branch ahead of the development-file device branch."""
    import textwrap
    from ._netconf_program import NETCONF_CODE
    marker = "else:\n    asset=request['asset'];path=pathlib.Path(asset['path'])"
    if program.count(marker) != 1:
        raise RuntimeError("workflow program layout changed")
    branch = "elif request['asset'].get('platform')=='netconf':\n" + textwrap.indent(NETCONF_CODE.strip("\n"), "    ") + "\n"
    return program.replace(marker, branch + marker)


WORKFLOW_PROGRAM = _with_netconf(WORKFLOW_PROGRAM)


def _with_iot(program):
    import textwrap
    from ._iot_program import IOT_CODE
    marker = "elif request['asset'].get('platform')=='netconf':"
    if program.count(marker) != 1:
        raise RuntimeError("workflow program layout changed")
    return program.replace(marker, "elif action.startswith('iot.'):\n" + textwrap.indent(IOT_CODE.strip("\n"), "    ") + "\n" + marker)


WORKFLOW_PROGRAM = _with_iot(WORKFLOW_PROGRAM)


def _with_agentless(program):
    import textwrap
    from ._agentless_program import AGENTLESS_CODE
    marker = "elif action.startswith('iot.'):"
    if program.count(marker) != 1:
        raise RuntimeError("workflow program layout changed")
    return program.replace(marker, "elif action == 'remote.operation':\n" + textwrap.indent(AGENTLESS_CODE.strip("\n"), "    ") + "\n" + marker)


WORKFLOW_PROGRAM = _with_agentless(WORKFLOW_PROGRAM)
