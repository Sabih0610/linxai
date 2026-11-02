"""Account-bound face enrollment/revocation contracts, never camera/UID claims."""
from dataclasses import dataclass
import json
from ._policy_program import POLICY_PROGRAM

FACE_PROGRAM=POLICY_PROGRAM.replace('/run/linxai-policy/control.sock','/run/linxai-face/control.sock').replace(
    "request['method'] = 'apply' if sys.argv[1] == 'response.network.block' else 'revoke'",
    "request['method'] = 'enroll' if sys.argv[1] == 'auth.face.enroll' else 'revoke'")


@dataclass(frozen=True)
class FaceParameters:
    pass


def prepare(registry,identifier,parameters,contract):
    from .registry import InvalidParameters,PreparedAction,requirement
    if parameters or registry.actor_uid is None:raise InvalidParameters('Face action takes no identity/biometric/client authority fields')
    checks=(requirement('linux_runtime'),requirement('trusted_executable',path='/usr/bin/python3'),
            requirement('authenticated_authorization',action=identifier),requirement('face_owner_scope',uid=registry.actor_uid))
    post=(requirement('exit_code',value=0),requirement('face_profile_verified',uid=registry.actor_uid,enrolled=int(identifier=='auth.face.enroll')))
    body=json.dumps({'actor_uid':registry.actor_uid,'parameters':{}},sort_keys=True).encode()
    return PreparedAction(contract,FaceParameters(),('/usr/bin/python3','-I','-c',FACE_PROGRAM,identifier),checks,post,body)
