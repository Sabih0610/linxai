"""Fixed stdlib-only bridge to the protected kernel policy mechanism."""
POLICY_PROGRAM = r'''
import json, os, pathlib, socket, stat, struct, sys, time
path = pathlib.Path('/run/linxai-policy/control.sock')
for parent in (path.parent, *path.parent.parents):
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError('Untrusted policy directory')
info = path.lstat()
if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
    raise PermissionError('Untrusted policy socket')
payload = sys.stdin.buffer.read(8193)
if len(payload) > 8192:
    raise ValueError('Policy request bound exceeded')
request = json.loads(payload)
request['version'] = 1
request['method'] = 'apply' if sys.argv[1] == 'response.network.block' else 'revoke'
wire = json.dumps(request, allow_nan=False).encode()
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.settimeout(10)
    sock.connect(str(path))
    if struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1] != 0:
        raise PermissionError('Policy peer is not root')
    sock.sendall(struct.pack('!I', len(wire)) + wire)
    deadline = time.monotonic() + 10
    def exact(size):
        value = bytearray()
        while len(value) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError('Policy deadline')
            sock.settimeout(remaining)
            chunk = sock.recv(size-len(value))
            if not chunk: raise ValueError('Incomplete policy response')
            value.extend(chunk)
        return bytes(value)
    size, = struct.unpack('!I', exact(4))
    if not 1 <= size <= 32768: raise ValueError('Policy response bound')
    response = json.loads(exact(size))
print(json.dumps(response))
raise SystemExit(0 if response.get('status') == 'ok' else 2)
'''
