"""Hard-deadline voice process. Only transcript text crosses into the planning API."""
import json
from pathlib import Path
import sys
from uuid import uuid4
from operations.supervised import SupervisedLinuxAdapter


def listen(model,duration=10):
    if type(duration) is not int or not 1<=duration<=15:raise ValueError('Voice duration must be 1–15 seconds')
    path=Path(model)
    if not path.is_absolute() or not path.is_dir():raise ValueError('Install/provide local Whisper weights explicitly; no automatic downloads')
    result=SupervisedLinuxAdapter()._run(str(uuid4()),(sys.executable,'-I','-B','-m','voice.worker','--model',str(path),'--duration',str(duration)),b'',45)
    if result.error or result.returncode!=0:raise RuntimeError('Voice input unavailable, incomplete or timed out')
    text=json.loads(result.stdout)['text']
    if not isinstance(text,str) or not text.strip() or len(text.encode())>8192:raise ValueError('Invalid transcript')
    return text
