"""Deterministic authentication/voice contracts; no camera, mic, PAM or model."""
import copy
import io
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from uuid import uuid4

from operations.registry import ActionRegistry, Privilege
from operations.service import Operation, Execution
from operations.broker import Polkit
from security.face import FaceAuthority, FaceClient, REQUIRED_CASES, handle
from test_application import MemoryStore
from test_broker import PeerDouble
from voice.pipeline import FRAME_BYTES, select_speech, transcribe, wer


class ReplayStore(MemoryStore):
    def put(self, kind, key, value, **kw):
        if kw.get('replace') is False and self.get(kind,key) is not None:
            raise ValueError('Consumed nonce')
        super().put(kind,key,value,**kw)


class Camera:
    real = False
    def __init__(self): self.calls=[]; self.override={}
    def run(self,mode,nonce,sequence):
        self.calls.append(mode)
        return {'uid':1000,'enrolled':True,'template_sha256':'a'*64,'provider':'fixture-v1',
                'nonce':nonce,'match':True,'live':True,'challenge':True,**self.override}


class AuthVoiceTests(unittest.TestCase):
    def setUp(self):
        self.store,self.camera=ReplayStore(),Camera()
        self.authority=FaceAuthority({'owner_uid':1000,'camera_index':0,'primary_enabled':True},self.store,self.camera)
    def qualified_fixture(self):
        profile=self.authority.enroll(1000,str(uuid4()))
        self.store.put('face_qualification','1000',{'origin':'actual_device_suite',
            'template_sha256':profile['template_sha256'],'provider':profile['provider'],
            'cases':{case:True for case in REQUIRED_CASES},'expires':__import__('time').time()+86400})
    def authenticate(self,**changes):
        fields=dict(uid=1000,operation_id=str(uuid4()),digest='b'*64,nonce=str(uuid4()),label='service.restart')
        fields.update(changes)
        return self.authority.authenticate(**fields)
    def test_account_fields_and_missing_mandatory_authorization_rejected(self):
        registry=ActionRegistry(actor_uid=1000)
        for action in ('auth.face.enroll','auth.face.revoke'):
            prepared=registry.prepare(action,{})
            self.assertEqual(prepared.contract.privilege,Privilege.AUTHENTICATED_ADMIN)
            self.assertTrue({'face_owner_scope','authenticated_authorization'} <= {c.identifier for c in prepared.mandatory_checks})
            for fields in ({'uid':0},{'authenticated':True},{'template':'face.png'},{'password':'secret'}):
                with self.assertRaises(ValueError):registry.prepare(action,fields)
    def test_wrong_account_unqualified_simulation_never_authorizes(self):
        with self.assertRaises(PermissionError):self.authority.enroll(1001,str(uuid4()))
        self.assertFalse(self.authenticate()['authorized'])
        self.qualified_fixture()
        self.assertFalse(self.authenticate()['authorized'])
        self.assertEqual(self.camera.calls,['enroll','authenticate'])
    def test_fresh_account_operation_provider_and_nonce_required(self):
        self.qualified_fixture();self.camera.real=True  # Simulated effects; tests only, never native evidence.
        self.assertTrue(self.authenticate()['authorized'])
        for override in ({'uid':1001},{'nonce':'wrong'},{'provider':'different'}, {'template_sha256':'c'*64}, {'challenge':False},{'live':False},{'match':False}):
            self.authority.next_attempt=0
            self.camera.override=override
            self.assertFalse(self.authenticate()['authorized'])
        self.authority.next_attempt=0
        nonce=str(uuid4());self.authenticate(nonce=nonce)
        self.authority.next_attempt=0
        with self.assertRaises(ValueError):self.authenticate(nonce=nonce)
        with self.assertRaises(PermissionError):self.authenticate(uid=0)
    def test_revocation_and_enrollment_invalidate_qualification(self):
        self.qualified_fixture();self.assertTrue(self.authority.qualified(self.authority.profile()))
        self.authority.revoke(1000,str(uuid4()))
        self.assertFalse(self.authority.qualified(self.authority.profile()))
        self.camera.override={'provider':'new'}
        self.authority.enroll(1000,str(uuid4()))
        self.assertFalse(self.authority.qualified(self.authority.profile()))
    def test_read_only_owner_cannot_inject_credentials_or_camera_proof(self):
        self.assertEqual(handle(self.authority,1000,{'version':1,'method':'status'},Mock())['uid'],1000)
        with self.assertRaises(PermissionError):handle(self.authority,1001,{'version':1,'method':'status'},Mock())
        with self.assertRaises(PermissionError):handle(self.authority,1000,{'version':1,'method':'enroll','actor_uid':1000,'parameters':{},'operation_id':str(uuid4())},Mock())
        with self.assertRaises(ValueError):handle(self.authority,0,{'version':1,'method':'status','authorized':True},Mock())
    def operation(self,action='service.restart'):
        parameters={'service':'linxai-lab'} if action.startswith('service.') else {}
        return Operation(str(uuid4()),PeerDouble().validate(),'{}',ActionRegistry(actor_uid=1000).prepare(action,parameters))
    def test_unavailable_face_falls_back_to_os_auth_enrollment_always_password(self):
        runner=Mock();runner._run.return_value=Execution('id',(),0)
        with patch.object(FaceClient,'authorize',side_effect=OSError('camera absent')) as face:
            auth=Polkit(runner)
            self.assertTrue(auth.authorize(PeerDouble(),self.operation()))
            self.assertEqual(auth.last_method,'polkit')
            self.assertTrue(auth.authorize(PeerDouble(),self.operation('auth.face.enroll')))
            self.assertEqual(face.call_count,1)
        self.assertIn('org.linxai.face.manage',runner._run.call_args.args[1])
    def test_face_proof_cannot_authorize_another_operation(self):
        client=FaceClient();client.call=Mock(return_value={'authorized':True,'origin':'actual_camera','uid':1000,
            'operation_id':str(uuid4()),'digest':'b'*64,'nonce':str(uuid4()),'expires_ns':10**30})
        self.assertFalse(client.authorize(PeerDouble(),self.operation()))
    def test_vad_bounds_and_silence_fail_closed(self):
        vad=Mock();vad.is_speech.side_effect=[False,True]+[False]*20
        self.assertEqual(len(select_speech([b'\0'*FRAME_BYTES]*30,vad)),FRAME_BYTES*21)
        with self.assertRaises(ValueError):select_speech([b'bad'],vad)
        vad.is_speech.side_effect=None;vad.is_speech.return_value=False
        with self.assertRaises(ValueError):select_speech([b'\0'*FRAME_BYTES]*5,vad)
    def test_local_transcription_no_download_and_bounded_wer(self):
        model=Mock();model.transcribe.return_value=([types.SimpleNamespace(text=' restart nginx ')],None)
        module=types.SimpleNamespace(WhisperModel=Mock(return_value=model))
        with tempfile.TemporaryDirectory() as directory,patch.dict(sys.modules,{'faster_whisper':module}):
            self.assertEqual(transcribe(b'\0\0'*100,Path(directory).absolute()),'restart nginx')
            self.assertTrue(module.WhisperModel.call_args.kwargs['local_files_only'])
        self.assertAlmostEqual(wer('restart nginx service','restart apache service')['wer'],1/3)
        with self.assertRaises(ValueError):transcribe(b'odd','missing')
        with self.assertRaises(ValueError):wer('','anything')


if __name__=='__main__':unittest.main()
