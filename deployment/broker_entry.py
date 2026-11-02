"""Root bootstrap: verify all import code before importing the mechanism."""
import os
from pathlib import Path
import stat
import sys


def verify_bundle(root):
    if not sys.flags.isolated or os.getuid() != 0 or os.geteuid() != 0:
        raise PermissionError("Use isolated OS Python and root-owned deployment")
    for path in (root, *root.parents):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError("Untrusted deployment directory")
    paths = list(root.rglob("*"))
    if len(paths) > 500:
        raise PermissionError("Deployment bundle too large")
    for path in paths:
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise PermissionError("Untrusted deployment entry")
    return root


if __name__ == "__main__":
    root = verify_bundle(Path(__file__).absolute().parent)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root))
    if sys.argv[1:] == ["sensor"]:
        from security.sensor import main
    elif sys.argv[1:] == ["policy"]:
        from security.policy_daemon import main
    elif sys.argv[1:] == ["qualify"]:
        from security.qualification import main
    elif not sys.argv[1:]:
        from operations.broker import main
    else:
        raise ValueError("Unsupported protected component")
    main()
