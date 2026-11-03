"""Package a clean committed candidate; never publishes or deploys components."""
import argparse
import hashlib
import io
import json
import os
import re
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parent.parent


def safe_name(name):
    path=PurePosixPath(name)
    if name!=path.as_posix() or '\\' in name or ':' in name or '\x00' in name:raise ValueError('Noncanonical candidate path')
    blocked={'.git','.env','models','biometric_samples','enrollments','node_modules','__pycache__'}
    forbidden={'.pem','.key','.db','.sqlite','.jsonl','.gguf','.safetensors','.bin','.jpg','.png','.mp4','.wav'}
    if path.is_absolute() or not path.parts or any(part in {'','..','.'} or part in blocked or part.startswith('.venv') for part in path.parts):
        raise ValueError('Unsafe/non-source candidate path: '+name)
    if path.suffix.lower() in forbidden or path.name.startswith(('id_rsa','id_ed25519','.env.')):
        raise ValueError('Sensitive/generated candidate path: '+name)
    return path


def sources(archive):
    files={};size=0
    with tarfile.open(fileobj=io.BytesIO(archive)) as reader:
        for member in reader:
            if member.isdir():continue
            safe_name(member.name)
            if not member.isfile() or member.size>4*1024*1024 or len(files)>=4096 or member.name in files:
                raise ValueError('Unexpected candidate source member')
            size+=member.size
            if size>32*1024*1024:raise ValueError('Candidate source size budget exceeded')
            data=reader.extractfile(member).read()
            if re.search(rb'^-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----\r?$',data,re.MULTILINE):
                raise ValueError('Private key material in candidate source')
            files[member.name]=data
    required={'AGENTS.md','uv.lock','operations/registry.py','operations/service.py','operations/broker.py','ui/desktop.py','voice/pipeline.py','docs/REQUIREMENTS_INVENTORY.md'}
    if not required<=files.keys():raise ValueError('Required predecessor implementation absent')
    return files


def write_tar(path,files):
    with tarfile.open(path,'x') as archive:
        for name,data in sorted(files.items()):
            safe_name(name)
            info=tarfile.TarInfo(name)
            info.size,info.mode,info.uid,info.gid,info.mtime=len(data),0o644,0,0,0
            archive.addfile(info,io.BytesIO(data))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--offline',action='store_true')
    args=parser.parse_args(argv)
    def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT,timeout=30)
    if git('status','--porcelain').strip():raise ValueError('Commit/review all intended changes before packaging; no dirty-source candidate')
    revision=git('rev-parse','HEAD').decode().strip()
    branch=git('branch','--show-current').decode().strip()
    files=sources(git('archive','--format=tar','HEAD'))
    output=args.output.absolute();output.mkdir(parents=True,exist_ok=False)
    manifest={'schema':1,'classification':'development candidate; full acceptance pending',
              'repository':git('remote','get-url','origin').decode().strip(),'branch':branch,'commit':revision,
              'source_files':{name:hashlib.sha256(data).hexdigest() for name,data in sorted(files.items())},
              'build_python':sys.version,'weights_credentials_samples':'excluded; no runtime data bundled'}
    write_tar(output/'source.tar',files)
    with tempfile.TemporaryDirectory(prefix='linxai-build-') as directory:
        source=Path(directory)
        for name,data in files.items():
            path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        env=dict(os.environ,SOURCE_DATE_EPOCH='315532800',UV_PYTHON_DOWNLOADS='never')
        command=[sys.executable,'-m','uv','build','--wheel','--out-dir',str(output)]
        if args.offline:command.append('--offline')
        subprocess.run(command,cwd=source,env=env,check=True,timeout=180)
        subprocess.run([sys.executable,'-I','-B',str(source/'scripts/package_trusted.py'),str(output/'trusted-components.tar')],
                       cwd=source,check=True,timeout=30)
    manifest['artifacts']={path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(output.iterdir()) if path.is_file()}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps({'output':str(output),'commit':revision,'artifacts':manifest['artifacts']},indent=2))
    return 0


if __name__=='__main__':raise SystemExit(main())
