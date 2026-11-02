"""Isolated protected camera worker. No raw frames leave the process or are retained."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time


def main():
    if os.getuid()!=0 or os.geteuid()!=0:raise PermissionError('Protected root camera worker required')
    raw=sys.stdin.buffer.read(8193)
    if len(raw)>8192:raise ValueError('Camera request bound')
    request=json.loads(raw)
    if set(request)!={'mode','uid','camera','nonce','sequence'} or type(request['uid']) is not int or request['uid']<=0 or type(request['camera']) is not int or not 0<=request['camera']<=15:raise ValueError('Invalid bounded capture request')
    from operations import ipc
    ipc.request_id(request['nonce'])
    if request['mode'] not in {'enroll','authenticate','revoke'} or not isinstance(request['sequence'],list) or (request['mode']=='authenticate' and (len(request['sequence'])!=2 or any(turn not in {'left','right'} for turn in request['sequence']))) or (request['mode']!='authenticate' and request['sequence']!=[]):raise ValueError('Invalid camera mode/challenge')
    from operations.supervised import SupervisedLinuxAdapter
    parent=Path('/var/lib/linxai-face');SupervisedLinuxAdapter()._directories(parent,0,private_leaf=True)
    import fcntl
    lock=os.open(parent/'camera.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    template=parent/(str(request['uid'])+'.yml')
    def safe_template():
        info=template.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077 or info.st_nlink!=1 or info.st_size>8*1024*1024:raise PermissionError('Unsafe account template')
        return hashlib.sha256(template.read_bytes()).hexdigest()
    if request['mode']=='revoke':
        if template.exists():safe_template();template.unlink()
        print(json.dumps({'uid':request['uid'],'enrolled':False}));return
    import cv2,numpy as np
    from executor.face_auth import FaceAuthEngine,CASCADE_PATH,AUTH_CONFIDENCE_THRESHOLD
    class Bound(FaceAuthEngine):
        def _load_template(self):pass  # Never consult the historical per-home template.
        def locate(self,gray):
            found=self.cascade.detectMultiScale(gray,1.1,5,minSize=(60,60))
            if len(found)!=1:return None,None
            x,y,w,h=found[0]
            return cv2.resize(gray[y:y+h,x:x+w],(100,100)),float(x+w/2)/gray.shape[1]
    auth=Bound();enroll=request['mode']=='enroll'
    digest=None if enroll else safe_template()
    if not enroll:auth.recognizer.read(str(template))
    camera=cv2.VideoCapture(request['camera']);camera.set(cv2.CAP_PROP_FRAME_WIDTH,640);camera.set(cv2.CAP_PROP_FRAME_HEIGHT,480)
    if not camera.isOpened():raise RuntimeError('Camera unavailable; password fallback required')
    frames,faces,centres=[],[],[]
    try:
        if not enroll:time.sleep(1)  # Ordinary desktop can display the root-authored challenge.
        for _ in range(30):
            ok,frame=camera.read()
            if not ok:break
            gray=cv2.cvtColor(cv2.resize(frame,(640,480)),cv2.COLOR_BGR2GRAY)
            face,centre=auth.locate(gray)
            if face is not None:faces.append(face);centres.append(centre);frames.append(gray)
            time.sleep(0.08)
    finally:camera.release()
    provider='opencv-lbph-flow-direction-v1:'+cv2.__version__+':'+hashlib.sha256(Path(__file__).read_bytes()+Path(sys.modules['executor.face_auth'].__file__).read_bytes()).hexdigest()
    if len(faces)<20:raise RuntimeError('Insufficient single-face samples')
    if enroll:
        auth.recognizer.train(faces,np.array([0]*len(faces)))
        temporary=parent/(str(request['uid'])+'.pending.yml')
        if os.path.lexists(temporary):raise FileExistsError('Previous enrollment requires review')
        os.umask(0o077);auth.recognizer.save(str(temporary))
        info=temporary.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077 or info.st_nlink!=1:raise PermissionError('Unsafe temporary template')
        if template.exists():safe_template()
        os.replace(temporary,template)
        print(json.dumps({'uid':request['uid'],'enrolled':True,'template_sha256':safe_template(),'provider':provider}));return
    live,flow=auth._check_liveness(frames)
    scores=[auth.recognizer.predict(face) for face in faces]
    match=sum(1 for label,score in scores if label==0 and score<=AUTH_CONFIDENCE_THRESHOLD)>=len(scores)*0.8
    groups=[float(np.mean(part)) for part in np.array_split(centres,3)]
    sequence=request['sequence']
    challenge=(len(sequence)==2 and all((groups[index+1]-groups[index]>0.04) if turn=='right' else (groups[index]-groups[index+1]>0.04) for index,turn in enumerate(sequence)))
    print(json.dumps({'uid':request['uid'],'nonce':request['nonce'],'template_sha256':digest,'provider':provider,
                      'match':bool(match),'live':bool(live),'challenge':bool(challenge),'origin':'actual_camera'}))
