"""Candidate archive boundaries. Does not build/install or open hardware."""
import io
import tarfile
import tempfile
from pathlib import Path
import unittest
from test_dev_environment import load_script


class CandidateTests(unittest.TestCase):
    def test_secrets_generated_data_and_traversal_rejected(self):
        package=load_script('package_candidate')
        for name in ('../escape.py','/absolute.py','models/weights.bin','.env','account/id_rsa','samples/face.jpg','state.sqlite','a/.git/config','a/.venv/site.py'):
            with self.subTest(name=name),self.assertRaises(ValueError):package.safe_name(name)
    def test_nonregular_and_missing_predecessors_rejected(self):
        package=load_script('package_candidate');data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w') as archive:
            item=tarfile.TarInfo('operations/registry.py');item.type=tarfile.SYMTYPE;item.linkname='/outside';archive.addfile(item)
        with self.assertRaises(ValueError):package.sources(data.getvalue())
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w'):pass
        with self.assertRaises(ValueError):package.sources(data.getvalue())
    def test_noneditable_build_excludes_stale_build_outputs(self):
        setup=load_script('setup_dev')
        with setup.clean_build_source() as source:
            self.assertFalse((source/'build').exists())
            self.assertIn('actor_uid',(source/'operations/registry.py').read_text())
            self.assertTrue((source/'voice/pipeline.py').is_file())
            self.assertTrue((source/'security/enforce.c').is_file())
            self.assertFalse(list(source.rglob('*.egg-info')))

    def test_typed_remote_metadata_does_not_import_legacy_paramiko(self):
        import subprocess
        import sys
        result=subprocess.run([sys.executable,'-B','-c',"import sys;sys.modules['paramiko']=None;from vps.server_types import VPSServer;assert 'vps.manager' not in sys.modules;print('typed SSH metadata independent')"],shell=False,capture_output=True,text=True,timeout=5,cwd=Path(__file__).parent)
        self.assertEqual(result.returncode,0,result.stderr)

    def artifact_fixture(self,root,protected=b"trusted"):
        import hashlib,json,zipfile
        package=load_script('package_candidate')
        files={name:b"fixture" for name in ('AGENTS.md','uv.lock','operations/registry.py','operations/service.py','operations/broker.py','ui/desktop.py','voice/pipeline.py','docs/REQUIREMENTS_INVENTORY.md')}
        files['deployment/broker_entry.py']=b"trusted"
        package.write_tar(root/'source.tar',files)
        with zipfile.ZipFile(root/'app.whl','w') as archive:
            for name,data in files.items():
                if name.endswith('.py') and not name.startswith('deployment/'):archive.writestr(name,data)
        name='usr/lib/linxai-trusted/broker_entry.py'
        entries={name:protected,'usr/share/doc/linxai/broker-manifest.json':json.dumps({name:hashlib.sha256(protected).hexdigest()}).encode()}
        package.write_tar(root/'trusted-components.tar',entries)
        manifest={'schema':1,'commit':'f'*40,'source_files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()},
            'artifacts':{path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in root.iterdir()}}
        (root/'manifest.json').write_text(json.dumps(manifest))

    def test_changed_artifact_is_rejected_before_installation(self):
        verifier=load_script('verify_candidate')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.artifact_fixture(root)
            self.assertEqual(verifier.verify(root)[0]['commit'],'f'*40)
            (root/'app.whl').write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError,'hash mismatch'):verifier.verify(root)

    def test_self_consistent_protected_archive_cannot_change_committed_code(self):
        verifier=load_script('verify_candidate')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.artifact_fixture(root,protected=b"changed")
            with self.assertRaisesRegex(ValueError,'differs from committed source'):verifier.verify(root)

    def test_manifested_source_tar_is_deterministic(self):
        package=load_script('package_candidate')
        with tempfile.TemporaryDirectory() as directory:
            first,second=Path(directory)/'a.tar',Path(directory)/'b.tar'
            package.write_tar(first,{'b.py':b'b','a.py':b'a'})
            package.write_tar(second,{'a.py':b'a','b.py':b'b'})
            self.assertEqual(first.read_bytes(),second.read_bytes())
            with self.assertRaises(FileExistsError):package.write_tar(first,{'a.py':b'keep'})


if __name__=='__main__':unittest.main()
