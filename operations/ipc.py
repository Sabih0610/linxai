"""Bounded local protocol. Transport credentials, never JSON, identify callers."""
import json
import socket
import struct
import time
from uuid import UUID

MAX_FRAME = 262144
VERSION = 1


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def exact(sock, size, deadline=None):
    result = bytearray()
    while len(result) < size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Protocol read deadline expired")
            if hasattr(sock, "settimeout"):
                sock.settimeout(remaining)
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise ValueError("Incomplete protocol frame")
        result.extend(chunk)
    return bytes(result)


def receive(sock, timeout=5):
    deadline = time.monotonic() + timeout
    size, = struct.unpack("!I", exact(sock, 4, deadline))
    if not 1 <= size <= MAX_FRAME:
        raise ValueError("Protocol frame exceeds bound")
    value = json.loads(exact(sock, size, deadline), object_pairs_hook=unique,
                       parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
    if not isinstance(value, dict):
        raise ValueError("Protocol object required")
    return value


def send(sock, value):
    data = json.dumps(value, allow_nan=False, separators=(",", ":")).encode()
    if len(data) > MAX_FRAME:
        raise ValueError("Protocol response exceeds bound")
    sock.sendall(struct.pack("!I", len(data)) + data)


def request_id(value):
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("Canonical UUID request ID required")
    return value


def credentials(sock):
    return struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
