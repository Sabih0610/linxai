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
# Fixed project recipes (Node since 2 Nov; Go, C++ and Docker since 13 Nov 2026). Each writes only
# its own template files into a new or managed folder, never overwrites an owner edit, verifies
# every byte, and never downloads, builds or runs anything. The first runtime path is recorded
# in the marker; `runtime_present` reports whether any listed toolchain is installed.
RECIPES={
 'project.node':('Node.js','node-stdlib-v1','.linxai-node.json',['/usr/bin/node'],{
  'package.json':b'{\n  "name": "linxai-node-project",\n  "version": "0.1.0",\n  "private": true,\n  "type": "module",\n  "scripts": {"start": "node index.js"},\n  "engines": {"node": ">=18"}\n}\n',
  'index.js':b'import http from "node:http";\nconst port = Number(process.env.PORT || 3000);\nhttp.createServer((req, res) => {\n  res.writeHead(200, {"content-type": "application/json"});\n  res.end(JSON.stringify({status: "ok"}));\n}).listen(port, "127.0.0.1", () => console.log("listening on 127.0.0.1:" + port));\n',
  'README.md':b'# Managed Node.js project\nRun with npm start (or node index.js). Dependencies are not downloaded.\n',
  '.gitignore':b'node_modules/\n'}),
 'project.go':('Go','go-stdlib-v1','.linxai-go.json',['/usr/bin/go','/usr/local/go/bin/go','/usr/lib/go/bin/go'],{
  'go.mod':b'module linxai.local/project\n\ngo 1.22\n',
  'main.go':b'// Managed Go project: standard library only, so it builds offline.\npackage main\n\nimport (\n\t"encoding/json"\n\t"log"\n\t"net/http"\n\t"os"\n)\n\nfunc health(w http.ResponseWriter, r *http.Request) {\n\tw.Header().Set("Content-Type", "application/json")\n\t_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})\n}\n\nfunc main() {\n\taddr := os.Getenv("ADDR")\n\tif addr == "" {\n\t\taddr = "127.0.0.1:8080"\n\t}\n\thttp.HandleFunc("/", health)\n\tlog.Printf("listening on %s", addr)\n\tlog.Fatal(http.ListenAndServe(addr, nil))\n}\n',
  'main_test.go':b'package main\n\nimport (\n\t"net/http"\n\t"net/http/httptest"\n\t"testing"\n)\n\nfunc TestHealth(t *testing.T) {\n\trec := httptest.NewRecorder()\n\thealth(rec, httptest.NewRequest(http.MethodGet, "/", nil))\n\tif rec.Code != http.StatusOK || rec.Body.String() != "{\\"status\\":\\"ok\\"}\\n" {\n\t\tt.Fatalf("unexpected response %d %q", rec.Code, rec.Body.String())\n\t}\n}\n',
  'README.md':b'# Managed Go project\nStandard library only. Build with `go build ./...`, test with `go test ./...`, run with `go run .`\n(listens on 127.0.0.1:8080; set ADDR to change). Nothing is downloaded by LINxAI.\n',
  '.gitignore':b'/bin/\n/project\n'}),
 'project.cpp':('C++','cpp-cmake-v1','.linxai-cpp.json',['/usr/bin/cmake','/usr/bin/g++','/usr/bin/c++'],{
  'CMakeLists.txt':b'cmake_minimum_required(VERSION 3.16)\nproject(linxai_project LANGUAGES CXX)\n\nset(CMAKE_CXX_STANDARD 17)\nset(CMAKE_CXX_STANDARD_REQUIRED ON)\nset(CMAKE_CXX_EXTENSIONS OFF)\n\nadd_executable(app main.cpp)\nif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")\n  target_compile_options(app PRIVATE -Wall -Wextra -Wpedantic)\nendif()\n\nenable_testing()\nadd_test(NAME smoke COMMAND app --self-test)\n',
  'main.cpp':b'// Managed C++17 project (CMake). Standard library only.\n#include <iostream>\n#include <string>\n\nint main(int argc, char** argv) {\n    if (argc > 1 && std::string(argv[1]) == "--self-test") {\n        return std::string("ok").size() == 2 ? 0 : 1;\n    }\n    std::cout << "Hello from LINxAI" << std::endl;\n    return 0;\n}\n',
  'README.md':b'# Managed C++ project\nConfigure and build: `cmake -S . -B build && cmake --build build`; test: `ctest --test-dir build`;\nrun: `./build/app`. Without CMake: `g++ -std=c++17 -Wall -o app main.cpp`.\n',
  '.gitignore':b'/build/\n/app\n'}),
 'project.docker':('Docker','docker-python-v1','.linxai-docker.json',['/usr/bin/docker','/usr/local/bin/docker'],{
  'Dockerfile':b'# Managed container project: small Python standard-library web service.\nFROM python:3.12-slim\nENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1\nWORKDIR /app\nRUN useradd --system --uid 10001 --no-create-home app\nCOPY --chown=app:app app.py .\nUSER app\nEXPOSE 8000\nHEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "import urllib.request; urllib.request.urlopen(\'http://127.0.0.1:8000/\', timeout=2)"]\nCMD ["python", "app.py"]\n',
  'app.py':b'# Managed container service: standard library only.\nimport json\nimport os\nfrom http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n\n\nclass Health(BaseHTTPRequestHandler):\n    def do_GET(self):\n        body = json.dumps({"status": "ok"}).encode()\n        self.send_response(200)\n        self.send_header("Content-Type", "application/json")\n        self.send_header("Content-Length", str(len(body)))\n        self.end_headers()\n        self.wfile.write(body)\n\n\nif __name__ == "__main__":\n    port = int(os.environ.get("PORT", "8000"))\n    ThreadingHTTPServer(("0.0.0.0", port), Health).serve_forever()   # inside the container only\n',
  'compose.yaml':b'services:\n  app:\n    build: .\n    ports:\n      - "127.0.0.1:8000:8000"   # published on this machine only\n    read_only: true\n    security_opt:\n      - no-new-privileges:true\n    restart: unless-stopped\n',
  '.dockerignore':b'.git\n.linxai-*.json\n__pycache__/\n*.pyc\n',
  'README.md':b'# Managed container project\nBuild and run: `docker compose up --build` (the image download happens in Docker, not LINxAI).\nThe service runs as a non-root user and is published on 127.0.0.1:8000 only.\n'}),
}
if action in RECIPES:
    label,recipe,marker_name,runtimes,templates=RECIPES[action]
    root=pathlib.Path(request['workspace']);chain(root,True)
    relative=pathlib.PurePosixPath(params['path'])
    if relative.is_absolute() or any(part in ('','.','..') for part in relative.parts):raise ValueError('Invalid relative project')
    project=root.joinpath(*relative.parts);chain(project.parent)
    existing=project.exists()
    if existing:chain(project,True)
    expected={'schema':1,'recipe':recipe,'runtime':runtimes[0]}
    present=any(os.path.isfile(r) for r in runtimes)
    marker=project/marker_name
    for name,data in templates.items():
        if os.path.lexists(project/name) and read(project/name)!=data:raise ValueError('Existing recipe file differs; no overwrite')
    if os.path.lexists(marker) and json.loads(read(marker)).get('recipe')!=expected['recipe']:raise ValueError('Existing project is not this managed recipe; review')
    before={'project_exists':existing,'parent':chain(project.parent),'managed':os.path.lexists(marker),'recipe':expected,
            'runtime_present':present}
    if mode=='check':print(json.dumps(before));raise SystemExit(0)
    if mode=='apply':
        if not existing:project.mkdir(mode=0o700)
        chain(project,True)
        for name,data in templates.items():
            if not os.path.lexists(project/name):atomic(project/name,data,True)
        if not os.path.lexists(marker):atomic(marker,encoded(expected),True)
    elif not os.path.lexists(marker):raise ValueError(label+' project missing')
    for name,data in templates.items():
        if read(project/name)!=data:raise ValueError(label+' project verification failed')
    if json.loads(read(marker))!=expected:raise ValueError(label+' project marker differs')
    print(json.dumps({'verified':True,'project':str(project),'recipe':expected,'created':not existing,'runtime_present':present,
                      'files':sorted(templates)}))
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
    from ._windows_program import WINDOWS_CODE
    windows = ("elif action == 'remote.operation' and request['asset'].get('platform') == 'windows_agentless':\n"
               + textwrap.indent(WINDOWS_CODE.strip("\n"), "    ") + "\n")
    linux = "elif action == 'remote.operation':\n" + textwrap.indent(AGENTLESS_CODE.strip("\n"), "    ") + "\n"
    return program.replace(marker, windows + linux + marker)


WORKFLOW_PROGRAM = _with_agentless(WORKFLOW_PROGRAM)
