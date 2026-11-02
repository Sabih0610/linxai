"""Explicit protected native camera/spoof trials. Never part of ordinary setup."""
import json
from pathlib import Path
import time
from uuid import uuid4

from operations.store import Store
from operations.supervised import SupervisedLinuxAdapter
from .face import CameraProcess, REQUIRED_CASES


def main():
    from broker_entry import verify_bundle
    verify_bundle(Path(__file__).absolute().parent.parent)
    system=SupervisedLinuxAdapter()
    config_path=Path('/etc/linxai/face.json')
    system._directories(config_path.parent,0)
    import stat
    info=config_path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
        raise PermissionError('Untrusted face configuration')
    config=json.loads(config_path.read_text())
    store=Store('/var/lib/linxai-face/state.sqlite',uid=0)
    uid=config['owner_uid'];profile=store.get('face_profile',str(uid))
    if not profile or profile.get('origin')!='actual_camera' or profile.get('enrolled') is not True:
        raise PermissionError('Actual protected account enrollment required')
    print('Controlled lab only. Present each labelled person/physical spoof when prompted. '
          'Labels are operator observations; no automated biometric assurance claim.',flush=True)
    cases={};observations={}
    # Each trial performs real camera capture; no caller-supplied authorized boolean.
    for case in ('owner_live','wrong_user','photo_replay','video_replay'):
        input('Present '+case+'; press Enter when ready: ')
        import secrets
        sequence=[secrets.choice(('left','right')) for _ in range(2)]
        print('Move horizontally in these directions: '+', '.join(sequence),flush=True)
        try:
            result=CameraProcess(uid,config['camera_index']).run('authenticate',str(uuid4()),sequence)
            bound=result.get('uid')==uid and result.get('provider')==profile['provider'] and result.get('template_sha256')==profile['template_sha256']
            accepted=bound and all(result.get(field) is True for field in ('match','live','challenge'))
            cases[case]=bool(bound and (accepted if case=='owner_live' else not accepted))
            observations[case]=result
        except Exception as exc:
            cases[case]=False  # Broken provider is not evidence that a spoof was rejected.
            observations[case]={'error':type(exc).__name__}
    input('Disconnect/disable the lab camera physically, then press Enter: ')
    try:
        CameraProcess(uid,config['camera_index']).run('authenticate',str(uuid4()),['left','right'])
        cases['missing_camera']=False
    except Exception as exc:
        cases['missing_camera']=True;observations['missing_camera']={'error':type(exc).__name__}
    record={'origin':'actual_device_suite','uid':uid,'template_sha256':profile['template_sha256'],
            'provider':profile['provider'],'cases':cases,'observations':observations,'created':time.time(),
            'expires':time.time()+86400,'limitation':'Single labelled lab trial per case; not biometric assurance or certification'}
    store.put('face_qualification',str(uid),record)
    print(json.dumps(record,indent=2))
    raise SystemExit(0 if set(cases)==REQUIRED_CASES and all(cases.values()) else 2)
