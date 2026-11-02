"""Fixed, isolated Linux program for future unprivileged create dispatch.

This is backend-owned source, never interpolated with model input. The registry
only places it in argv; it does not launch it. No parent directories are created.
"""

CREATE_PROGRAM = r'''
import os
import sys
from contextlib import ExitStack

if sys.platform != "linux" or os.geteuid() == 0:
    raise SystemExit("Creation requires an unprivileged Linux process")
workspace, relative, kind = sys.argv[1:]
if (not workspace.startswith("/") or workspace == "/"
        or relative.startswith("/") or kind not in {"file", "directory"}):
    raise SystemExit("Invalid create arguments")
parts = workspace[1:].split("/") + relative.split("/")
if any(not part or part in {".", ".."} for part in parts):
    raise SystemExit("Invalid create path")
data = sys.stdin.buffer.read(65537)
if len(data) > 65536 or (kind == "directory" and data):
    raise SystemExit("Invalid create content")
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
with ExitStack() as stack:
    parent = os.open("/", flags)
    stack.callback(os.close, parent)
    for part in parts[:-1]:
        parent = os.open(part, flags, dir_fd=parent)
        stack.callback(os.close, parent)
    if kind == "directory":
        os.mkdir(parts[-1], 0o700, dir_fd=parent)
    else:
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
'''.strip()
