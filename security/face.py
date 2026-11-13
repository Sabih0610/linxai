"""Protected account/operation-bound camera mechanism with trusted password fallback."""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import threading
import time
from uuid import uuid4

from operations import ipc
from operations.broker import RootAudit
from operations.service import Identity
from operations.store import Store
from operations.supervised import SupervisedLinuxAdapter

REQUIRED_CASES={'owner_live','wrong_user','photo_replay','video_replay','missing_camera'}


class CameraProcess:
    real=True
    def __init__(self,uid,camera):self.uid,self.camera=uid,camera
    def run(self,mode,nonce,sequence):
        uid=self.uid
        class Runner(SupervisedLinuxAdapter):
            def resolve_identity(self):
                if os.getuid()!=0 or os.geteuid()!=0:raise PermissionError('Protected capture context required')
                import pwd
                return Identity(uid,uid,pwd.getpwuid(uid).pw_name)
        payload={'mode':mode,'uid':uid,'camera':self.camera,'nonce':nonce,'sequence':sequence}
        argv=('/usr/bin/python3','-I','-B','/usr/lib/linxai-trusted/broker_entry.py','face-capture')
        result=Runner()._run(str(uuid4()),argv,json.dumps(payload).encode(),15)
        if result.error or result.returncode!=0 or len(result.stdout)>8192:raise RuntimeError('Camera/provider unavailable or deadline exceeded')
        return json.loads(result.stdout)


class FaceAuthority:
    def __init__(self,config,store,camera):
        if set(config)!={'owner_uid','camera_index','primary_enabled'} or type(config['owner_uid']) is not int or config['owner_uid']<=0 or type(config['camera_index']) is not int or not 0<=config['camera_index']<=15 or type(config['primary_enabled']) is not bool:
            raise ValueError('Invalid root-owned face configuration')
        self.config,self.store,self.camera=config,store,camera
        self.capture_lock,self.state_lock=threading.Lock(),threading.RLock()
        self.pending=None
        self.next_attempt=0.0
    def profile(self):return self.store.get('face_profile',str(self.config['owner_uid']))
    def qualified(self,profile):
        qualification=self.store.get('face_qualification',str(self.config['owner_uid']))
        return bool(profile and profile.get("enrolled") is True and qualification and qualification.get('origin')=='actual_device_suite'
                    and qualification.get('template_sha256')==profile.get('template_sha256')
                    and qualification.get('provider')==profile.get('provider')
                    and time.time()<qualification.get('expires',0)<=time.time()+86401
                    and set(qualification.get('cases',{}))==REQUIRED_CASES
                    and all(value is True for value in qualification['cases'].values()))
    def status(self):
        profile=self.profile()
        return {'uid':self.config['owner_uid'],'enrolled':bool(profile and profile.get('enrolled')),
                'qualified':self.qualified(profile),'primary_enabled':self.config['primary_enabled'],
                'profile':profile,'pending':self.pending,'password_fallback':'trusted polkit; credentials never enter this process'}
    def enroll(self,uid,operation_id):
        if uid!=self.config['owner_uid']:raise PermissionError('Wrong enrollment account')
        ipc.request_id(operation_id)
        with self.capture_lock:
            result=self.camera.run('enroll',str(uuid4()),[])
            if result.get('enrolled') is not True or result.get('uid')!=uid:raise RuntimeError('Enrollment not captured for requested OS account')
            profile={'uid':uid,'enrolled':True,'template_sha256':result['template_sha256'],'provider':result['provider'],
                     'operation_id':operation_id,'origin':'actual_camera' if self.camera.real else 'simulated'}
            self.store.put('face_qualification',str(uid),{'origin':'invalidated_by_enrollment_or_revocation'})
            self.store.put('face_profile',str(uid),profile)
            return profile
    def revoke(self,uid,operation_id):
        if uid!=self.config['owner_uid']:raise PermissionError('Wrong revocation account')
        with self.capture_lock:
            result=self.camera.run('revoke',str(uuid4()),[])
            profile={'uid':uid,'enrolled':False,'operation_id':ipc.request_id(operation_id),'origin':'actual_camera' if self.camera.real else 'simulated'}
            self.store.put('face_qualification',str(uid),{'origin':'invalidated_by_enrollment_or_revocation'})
            self.store.put('face_profile',str(uid),profile)
            return profile
    def authenticate(self,uid,operation_id,digest,nonce,label):
        if uid!=self.config['owner_uid'] or not re.fullmatch('[0-9a-f]{64}',digest):raise PermissionError('Wrong account or operation digest')
        ipc.request_id(operation_id);ipc.request_id(nonce)
        profile=self.profile()
        if not self.config['primary_enabled'] or not self.qualified(profile):return {'authorized':False,'reason':'password_required; face not natively qualified'}
        with self.state_lock:
            if time.monotonic()<self.next_attempt:return {'authorized':False,'reason':'rate_limited; password_required'}
            self.next_attempt=time.monotonic()+10
        if hasattr(self.store,'retire'):self.store.retire('face_nonce',lambda old:True,high=900,keep=600)   # nonces are single-use and short-lived
        self.store.put('face_nonce',nonce,{'uid':uid,'operation_id':operation_id,'digest':digest},replace=False,limit=1000)
        if not self.capture_lock.acquire(blocking=False):return {'authorized':False,'reason':'camera_busy; password_required'}
        try:
            import secrets
            sequence=[secrets.choice(('left','right')) for _ in range(2)]
            self.pending={'uid':uid,'operation_id':operation_id,'label':label[:256],'nonce':nonce,'sequence':sequence,'expires':time.time()+15}
            result=self.camera.run('authenticate',nonce,sequence)
            authorized=(self.camera.real and result.get('uid')==uid and result.get('nonce')==nonce
                        and result.get('match') is True and result.get('live') is True and result.get('challenge') is True
                        and result.get('template_sha256')==profile['template_sha256'] and result.get('provider')==profile['provider'])
            return {'authorized':bool(authorized),'uid':uid,'operation_id':operation_id,'digest':digest,'nonce':nonce,
                    'expires_ns':time.monotonic_ns()+2_000_000_000,'origin':'actual_camera' if self.camera.real else 'simulated'}
        finally:
            self.pending=None;self.capture_lock.release()


class FaceClient:
    def call(self,method,**fields):
        path=Path('/run/linxai-face/control.sock')
        SupervisedLinuxAdapter()._directories(path.parent,0)
        info=path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0:raise PermissionError('Untrusted face mechanism')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(20);sock.connect(str(path))
            if ipc.credentials(sock)[1]!=0:raise PermissionError('Face peer is not root')
            ipc.send(sock,{'version':1,'method':method,**fields});value=ipc.receive(sock,timeout=20)
        if value.get('status')!='ok':raise PermissionError('Face mechanism refused; password required')
        return value['result']
    def authorize(self,peer,operation):
        from operations.service import fingerprint
        nonce=str(uuid4());digest=fingerprint(operation)
        proof=self.call('authenticate',actor_uid=peer.uid,operation_id=operation.operation_id,digest=digest,nonce=nonce,label=operation.prepared.contract.identifier)
        return (proof.get('authorized') is True and proof.get('origin')=='actual_camera' and proof.get('uid')==peer.uid
                and proof.get('operation_id')==operation.operation_id and proof.get('digest')==digest and proof.get('nonce')==nonce
                and type(proof.get('expires_ns')) is int and time.monotonic_ns()<proof['expires_ns']<=time.monotonic_ns()+3_000_000_000)


def handle(authority,uid,request,audit):
    fields={'status':set(),'preview':{'actor_uid'},'enroll':{'actor_uid','parameters','operation_id'},
            'revoke':{'actor_uid','parameters','operation_id'},'authenticate':{'actor_uid','operation_id','digest','nonce','label'}}
    method=request.get('method')
    if type(request.get('version')) is not int or request['version']!=1 or method not in fields or set(request)!={'version','method'}|fields[method]:raise ValueError('Unsupported face request')
    if uid not in {0,authority.config['owner_uid']}:raise PermissionError('Wrong face peer')
    if method=='status':return authority.status()
    if uid!=0 or request['actor_uid']!=authority.config['owner_uid']:raise PermissionError('Only authenticated root mechanism may request account operations')
    if method=='preview':return authority.status()
    if method=='authenticate':return authority.authenticate(request['actor_uid'],request['operation_id'],request['digest'],request['nonce'],request['label'])
    if request['parameters']!={}:raise ValueError('No client biometric/identity fields accepted')
    operation_id=ipc.request_id(request['operation_id'])
    audit.append({'operation_id':operation_id,'phase':'face','status':'starting','fingerprint':'','details':{'method':method,'uid':request['actor_uid']}})
    value=authority.enroll(request['actor_uid'],operation_id) if method=='enroll' else authority.revoke(request['actor_uid'],operation_id)
    audit.append({'operation_id':operation_id,'phase':'face','status':'completed','fingerprint':'','details':{'method':method,'uid':request['actor_uid']}})
    return value


def main():
    from broker_entry import verify_bundle
    verify_bundle(Path(__file__).absolute().parent.parent)
    path=Path('/etc/linxai/face.json');system=SupervisedLinuxAdapter();system._directories(path.parent,0)
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise PermissionError('Unsafe face configuration')
    config=json.loads(path.read_text());store=Store('/var/lib/linxai-face/state.sqlite',uid=0)
    authority=FaceAuthority(config,store,CameraProcess(config['owner_uid'],config['camera_index']))
    audit=RootAudit('/var/lib/linxai-face/audit.jsonl');slots=threading.BoundedSemaphore(4)
    socket_path=Path('/run/linxai-face/control.sock');system._directories(socket_path.parent,0)
    import fcntl
    lock=os.open(socket_path.parent/'face.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if os.path.lexists(socket_path):
        info=socket_path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0:raise PermissionError('Unknown face socket')
        socket_path.unlink()
    def serve(conn):
        with conn:
            try:
                conn.settimeout(3);uid=ipc.credentials(conn)[1]
                if uid not in {0,config['owner_uid']}:raise PermissionError('Wrong face peer')
                value=handle(authority,uid,ipc.receive(conn,timeout=3),audit)
                ipc.send(conn,{'status':'ok','result':value})
            except Exception as exc:
                try:ipc.send(conn,{'status':'error','reason':type(exc).__name__})
                except Exception:pass
            finally:slots.release()
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(str(socket_path));socket_path.chmod(0o666);server.listen(8)
        try:
            while True:
                conn,_=server.accept()
                if slots.acquire(blocking=False):threading.Thread(target=serve,args=(conn,),daemon=True).start()
                else:conn.close()
        finally:socket_path.unlink(missing_ok=True);os.close(lock)
