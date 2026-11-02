"""Explicit protected camera qualification; no escalation or security installation."""
import os
from pathlib import Path
import stat
import sys

if os.environ.get('LINXAI_TEST_HARDWARE')!='1':
    print('PENDING: controlled camera/spoof lab and LINXAI_TEST_HARDWARE=1 required')
    raise SystemExit(3)
if not hasattr(os,'getuid') or os.getuid()!=0 or not sys.flags.isolated:
    raise PermissionError('Use explicit isolated root lab invocation; no escalation performed')
entry=Path('/usr/lib/linxai-trusted/broker_entry.py')
for path in (*reversed(entry.parents),entry):
    info=path.lstat()
    if info.st_uid!=0 or info.st_mode&0o022 or not (stat.S_ISDIR(info.st_mode) if path!=entry else stat.S_ISREG(info.st_mode)):
        raise PermissionError('Untrusted protected bootstrap')
os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(entry),'face-qualify'])
