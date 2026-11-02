"""Forward explicit native qualification to the protected root bootstrap."""
import os
from pathlib import Path
import stat
import sys

if os.environ.get("LINXAI_TEST_KERNEL") != "1":
    print("PENDING: prepared target and LINXAI_TEST_KERNEL=1 required")
    raise SystemExit(3)
if not hasattr(os,"getuid") or os.getuid()!=0 or not sys.flags.isolated:
    raise PermissionError("Use explicit isolated root lab invocation; no escalation is performed")
entry=Path("/usr/lib/linxai-trusted/broker_entry.py")
for parent in entry.parents:
    info=parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
        raise PermissionError("Untrusted protected deployment")
info=entry.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
    raise PermissionError("Untrusted protected bootstrap")
os.execv("/usr/bin/python3",["/usr/bin/python3","-I","-B",str(entry),"qualify"])
