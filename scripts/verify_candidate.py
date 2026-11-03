"""Verify committed artifacts and exercise the actual wheel as an ordinary Linux user."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'scripts'))
from package_candidate import safe_name,sources
from run_candidate import run


def verify(directory):
    directory=Path(directory)
    if (directory/'manifest.json').stat().st_size>1024*1024:raise ValueError('Manifest budget exceeded')
    manifest=json.loads((directory/'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('schema')!=1 or not isinstance(manifest.get('artifacts'),dict) or not 3<=len(manifest['artifacts'])<=8:raise ValueError('Invalid candidate manifest')
    for name,digest in manifest['artifacts'].items():
        if safe_name(name).name!=name:raise ValueError('Unexpected artifact directory')
        path=directory/name
        if path.is_symlink() or path.stat().st_size>32*1024*1024 or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:raise ValueError('Artifact hash mismatch: '+name)
    files=sources((directory/'source.tar').read_bytes())
    if {name:hashlib.sha256(data).hexdigest() for name,data in files.items()}!=manifest['source_files']:raise ValueError('Committed source manifest mismatch')
    wheels=[name for name in manifest['artifacts'] if name.endswith('.whl')]
    if len(wheels)!=1:raise ValueError('Exactly one application wheel required')
    with zipfile.ZipFile(directory/wheels[0]) as wheel:
        if len(wheel.infolist())>4096 or sum(info.file_size for info in wheel.infolist())>32*1024*1024:raise ValueError('Wheel size budget')
        names=set()
        for info in wheel.infolist():
            safe_name(info.filename)
            if info.filename in names:raise ValueError('Duplicate wheel member')
            names.add(info.filename)
            if '.dist-info/' not in info.filename and (info.filename not in files or wheel.read(info)!=files[info.filename]):raise ValueError('Wheel differs from committed source: '+info.filename)
        if not {'operations/registry.py','operations/service.py','operations/broker.py','voice/pipeline.py','ui/desktop.py'}<=names:raise ValueError('Required wheel modules missing')
    trusted={}
    with tarfile.open(directory/'trusted-components.tar') as archive:
        members=archive.getmembers()
        if len(members)>500 or sum(member.size for member in members)>16*1024*1024:raise ValueError('Protected bundle size budget')
        for member in members:
            safe_name(member.name)
            if not member.isfile() or member.uid!=0 or member.gid!=0 or member.mode&0o022 or member.name in trusted:raise ValueError('Unsafe protected bundle member')
            trusted[member.name]=archive.extractfile(member).read()
    for name,data in trusted.items():
        if name.startswith('usr/lib/linxai-trusted/'):
            original=name.removeprefix('usr/lib/linxai-trusted/')
            if original=='broker_entry.py':original='deployment/broker_entry.py'
        elif name.startswith('usr/lib/systemd/system/') or name.startswith('usr/share/polkit-1/actions/'):
            original='deployment/'+Path(name).name
        elif name.startswith('usr/share/doc/linxai/'):
            original=('requirements/' if Path(name).name.endswith('-os.json') else 'deployment/')+Path(name).name
            if Path(name).name=='broker-manifest.json':continue
        else:raise ValueError('Unknown protected destination')
        if original not in files or files[original]!=data:raise ValueError('Protected component differs from committed source: '+name)
    recorded=json.loads(trusted.pop('usr/share/doc/linxai/broker-manifest.json'))
    if {name:hashlib.sha256(data).hexdigest() for name,data in trusted.items()}!=recorded:raise ValueError('Protected bundle manifest mismatch')
    return manifest,files,wheels[0]


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    parser.add_argument('--report',required=True,type=Path)
    parser.add_argument('--verify-only',action='store_true',help='Hash/source/package verification only; no Linux installation')
    parser.add_argument('--desktop',action='store_true',help='Explicitly install locked Qt profile; hardware remains unopened')
    args=parser.parse_args(argv)
    report={'verifier_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'schema':1,'results':[],'target_acceptance':'pending; artifact workflow is not privileged/kernel/hardware acceptance'}
    try:
        manifest,files,wheel=verify(args.directory)
        report.update(commit=manifest['commit'],artifact_hashes=manifest['artifacts'],source_files=len(files),package_verification='passed')
        if not args.verify_only:
            from install_app import ordinary_user
            ordinary_user()
            with tempfile.TemporaryDirectory(prefix='.linxai-artifact-',dir=Path.home()) as temporary:
                root=Path(temporary);source=root/'source';source.mkdir()
                for name,data in files.items():
                    path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
                prefix=root/'app'
                command=[sys.executable,'-I',str(source/'scripts/install_app.py'),'--offline','--prefix',str(prefix)]
                if args.desktop:command.append('--desktop')
                install=run(command,660,cwd=root);report['results'].append(install)
                if install['returncode']!=0:raise RuntimeError('Locked dependency installation failed')
                try:
                    # Replace with the exact hashed wheel, not a checkout/editable rebuild.
                    report['results'].append(run([sys.executable,'-m','uv','pip','install','--offline','--no-deps','--reinstall',
                        '--python',str(prefix/'venv/bin/python'),str((args.directory/wheel).absolute())],60,cwd=root))
                    report['results'].append(run([str(prefix/'venv/bin/python'),'-I','-B',str(source/'scripts/installed_workflow.py'),'--root',str(root)],90,cwd=root))
                    report['results'].append(run([str(prefix/'bin/linxai'),'memory.usage','--audit-path',str(root/'cli-audit.jsonl')],10,cwd=root))
                finally:
                    report['results'].append(run([sys.executable,'-I',str(source/'scripts/install_app.py'),'--prefix',str(prefix),'--uninstall'],30,cwd=root))
                    if prefix.exists():raise RuntimeError('Managed removal failed')
        report['status']='FAILED' if any(row['returncode']!=0 for row in report['results']) else 'ARTIFACT CHECKS PASSED; TARGET ACCEPTANCE PENDING'
    except Exception as exc:report.update(status='FAILED',error=f'{type(exc).__name__}: {exc}')
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:value for key,value in report.items() if key!='results'},indent=2))
    return 1 if report['status']=='FAILED' else 0


if __name__=='__main__':raise SystemExit(main())
