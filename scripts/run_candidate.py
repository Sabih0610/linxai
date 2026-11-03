"""Automated ordinary-user candidate acceptance; no host/hardware provisioning."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))


def run(command,timeout,cwd=ROOT,env=None):
    # All supported test tools have bounded suites/output. Keep report tails bounded.
    started=time.monotonic()
    value=subprocess.run(command,cwd=cwd,env=env,shell=False,capture_output=True,text=True,timeout=timeout)
    return {'argv':[str(arg) for arg in command],'returncode':value.returncode,'seconds':round(time.monotonic()-started,3),
            'stdout_tail':value.stdout[-16384:],'stderr_tail':value.stderr[-16384:]}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',required=True,type=Path)
    parser.add_argument('--offline',action='store_true')
    parser.add_argument('--desktop',action='store_true',help='Explicit pinned Qt installation and offscreen smoke; no physical GUI claim')
    args=parser.parse_args(argv)
    from scripts.install_app import ordinary_user,safe_chain
    ordinary_user();safe_chain(Path.home())
    report={'operations_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'operations').glob('*.py'))},'source_snapshot':json.loads((ROOT/'SOURCE_SNAPSHOT.json').read_text()).get('parent_commit') if (ROOT/'SOURCE_SNAPSHOT.json').exists() else None,'schema':1,'kind':'native ordinary-user installed candidate','cloud':False,'uid':os.getuid(),
            'results':[],'target_pending':['systemd service success','polkit/account authentication','real BCC and enforcement','SSH/vendor lab','camera/spoof/microphone/WER','real model','24-hour stress','owner acceptance']}
    try:
        report['results'].append(run([sys.executable,'-B',str(ROOT/'scripts/test.py'),'all'],300))
        with tempfile.TemporaryDirectory(prefix='.linxai-candidate-',dir=Path.home()) as directory:
            prefix=Path(directory)/'installed candidate'
            command=[sys.executable,'-I',str(ROOT/'scripts/install_app.py'),'--prefix',str(prefix)]
            if args.offline:command.append('--offline')
            if args.desktop:command.append('--desktop')
            install=run(command,660);report['results'].append(install)
            if install['returncode']!=0:raise RuntimeError('Candidate installation failed')
            python=str(prefix/'venv/bin/python')
            probe='''import json,pathlib,operations,voice.pipeline
from operations.registry import ACTIONS
from security.face import FaceAuthority
from operations.broker import FACE_ADMIN
from vps.server_types import VPSServer
assert FACE_ADMIN <= ACTIONS.keys()
assert len(ACTIONS)>=20
assert pathlib.Path(operations.__file__).is_relative_to(pathlib.Path(__import__('sys').prefix))
print(json.dumps({'module':operations.__file__,'actions':sorted(ACTIONS),'voice':'installed; hardware unopened'}))'''
            report['results'].append(run([python,'-I','-B','-c',probe],10,cwd=directory))
            report['results'].append(run([str(prefix/'bin/linxai'),'memory.usage','--audit-path',str(Path(directory)/'cli-audit.jsonl')],10,cwd=directory))
            report['results'].append(run([python,'-I','-B',str(ROOT/'scripts/installed_workflow.py'),'--root',directory],90,cwd=directory))
            if args.desktop:
                env=dict(os.environ,QT_QPA_PLATFORM='offscreen')
                code='''from PySide6.QtWidgets import QApplication
from ui.desktop import build_window
class Client:
 def call(self,method,**fields):return {'jobs':[]} if method=='jobs' else {}
app=QApplication([]);window=build_window(Client());assert window.tabs.count()==5
window.timer.stop();window.pool.waitForDone(3000);app.processEvents();window.close()
print('Installed Qt window constructed; physical desktop/hardware untested')'''
                report['results'].append(run([python,'-I','-B','-c',code],15,cwd=directory,env=env))
            report['results'].append(run([sys.executable,'-I',str(ROOT/'scripts/install_app.py'),'--prefix',str(prefix),'--uninstall'],30))
            if prefix.exists():raise RuntimeError('Managed uninstall incomplete')
        report['status']='FAILED' if any(row['returncode']!=0 for row in report['results']) else 'IMPLEMENTED—LAB ACCEPTANCE PENDING'
    except Exception as exc:
        report.update(status='FAILED',error=f'{type(exc).__name__}: {exc}')
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':report['status'],'steps':len(report['results']),'report':str(args.report)},indent=2))
    return 1 if report['status']=='FAILED' else 3


if __name__=='__main__':raise SystemExit(main())
