"""Process facts the kernel event alone cannot carry (widened detection, 13 Nov 2026).

Read from procfs by the monitor when it processes a real-kernel event, for processes of
the monitored account (procfs only lets the owner read these links):

* `stdio_tcp`: the process, or its parent, has standard input/output on a TCP socket.
  That is the defining shape of a reverse or bind shell however it was launched
  (python/perl/php/ruby one-liners, `nc -e`, `socat exec:`, pty.spawn), and it does not
  occur for terminals, pipes or SSH sessions (pty or AF_UNIX socketpair).
* `tool_identity`: the executable is byte-identical (size + SHA-256) to a known network
  or attack tool installed on the host while running under another name ("kworker").

Only metadata is read: fd link targets, /proc/<pid>/net/tcp{,6} inode tables, stat and
the executable's bytes. Never memory, environment or command lines. Identity is bound
by start time, so a recycled PID yields no facts. Every failure yields no facts.
"""
import hashlib
import os
import shutil

from .lineage import TOLERANCE_NS, _stat

# Shells and interpreters whose standard I/O on a TCP socket means a remote shell.
SHELLISH = frozenset({"sh", "bash", "dash", "zsh", "ksh", "fish", "busybox", "ash", "mksh", "tcsh", "csh",
                      "python", "python2", "python3", "perl", "php", "ruby", "lua", "node", "nodejs", "irb",
                      "nc", "ncat", "netcat", "nc.openbsd", "nc.traditional", "socat", "telnet", "openssl"})
# Binaries worth recognising when renamed (network tools, scanners, tunnels).
KNOWN_TOOLS = ("nc", "ncat", "netcat", "nc.openbsd", "nc.traditional", "socat", "telnet", "nmap", "masscan",
               "hydra", "chisel", "openssl")
MAX_HASH_BYTES = 64 * 1024 * 1024


def shellish(name):
    base = os.path.basename(name or "")
    return base in SHELLISH or base.startswith(("python3.", "python2.", "perl5"))


def _digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


class ToolCatalog:
    """Size+hash fingerprints of the host's real tools; files are hashed only on a size match."""
    def __init__(self, names=KNOWN_TOOLS, which=shutil.which):
        self.by_size, self.cache = {}, {}
        for name in names:
            found = which(name)
            if not found:
                continue
            try:
                real = os.path.realpath(found)
                size = os.stat(real).st_size
                if 0 < size <= MAX_HASH_BYTES:
                    names = self.by_size.setdefault(size, {}).setdefault(_digest(real), set())
                    names.update({name, os.path.basename(found), os.path.basename(real)})   # every name the host uses
            except OSError:
                continue

    def identify(self, path):
        """The set of host names for a known tool binary at `path`, or None."""
        try:
            info = os.stat(path)
        except OSError:
            return None
        candidates = self.by_size.get(info.st_size)
        if not candidates:
            return None
        key = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size)
        if key not in self.cache:
            try:
                self.cache[key] = candidates.get(_digest(path))
            except OSError:
                return None
            if len(self.cache) > 4096:
                self.cache.clear()
        return self.cache[key]


def _tcp_inodes(proc_root, pid):
    inodes = set()
    for table in ("tcp", "tcp6"):
        try:
            with open(f"{proc_root}/{pid}/net/{table}", "rb") as stream:
                lines = stream.read(4 << 20).decode(errors="replace").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) > 9:
                inodes.add(fields[9])
    return inodes


def _stdio_sockets(proc_root, pid):
    found = {}
    for fd in (0, 1, 2):
        try:
            target = os.readlink(f"{proc_root}/{pid}/fd/{fd}")
        except OSError:
            continue
        if target.startswith("socket:[") and target.endswith("]"):
            found[fd] = target[8:-1]
    return found


def _stdio_on_tcp(proc_root, pid):
    sockets = _stdio_sockets(proc_root, pid)
    if not sockets:
        return False
    tcp = _tcp_inodes(proc_root, pid)
    return any(inode in tcp for inode in sockets.values())


def facts(event, *, proc_root="/proc", tools=None, hz=None):
    """Return {} or {"stdio_tcp": "self"|"parent", "tool_identity": name} for a real-kernel event."""
    pid, out = event.get("pid"), {}
    try:
        first = _stat(proc_root, pid)
    except (OSError, ValueError, IndexError, TypeError):
        return out                                      # already exited
    hz = hz or os.sysconf("SC_CLK_TCK")
    start_ns = event.get("start_ns")
    if start_ns is None or abs(first["start_ticks"] * 1_000_000_000 // hz - start_ns) > TOLERANCE_NS:
        return out                                      # PID not provably the event's process
    if event.get("kind") == "file_open":
        # The kernel reports the REAL uid; a setuid-root program (sudo checking the owner's
        # password reads /etc/shadow) runs with effective uid 0 and is not a non-root attempt.
        try:
            with open(f"{proc_root}/{pid}/status", "rb") as stream:
                for line in stream.read(8192).decode(errors="replace").splitlines():
                    if line.startswith("Uid:"):
                        if int(line.split()[2]) == 0:
                            out["privileged"] = True
                        break
        except (OSError, ValueError, IndexError):
            pass
        return out
    if event.get("kind") == "process_exec" and shellish(event.get("target", {}).get("path")):
        if _stdio_on_tcp(proc_root, pid):
            out["stdio_tcp"] = "self"
        elif first.get("ppid", 0) > 1 and _stdio_on_tcp(proc_root, first["ppid"]):
            try:
                parent = _stat(proc_root, first["ppid"])
                if shellish(parent.get("comm")):
                    out["stdio_tcp"] = "parent"         # e.g. python pty.spawn bridging the socket
            except (OSError, ValueError, IndexError):
                pass
    if tools is not None and event.get("kind") in {"process_exec", "network_connect"}:
        names = tools.identify(f"{proc_root}/{pid}/exe")
        shown = os.path.basename(event.get("target", {}).get("path") or "") if event.get("kind") == "process_exec" else event.get("process", "")
        if names and shown not in {n[:15] for n in names} | set(names):    # kernel comm is at most 15 characters
            out["tool_identity"] = sorted(names, key=len)[0]
    return out
