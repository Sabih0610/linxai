"""Bounded loopback-only HTTP with an absolute deadline and no proxy/redirect path."""
import http.client
import io
import json
import socket
import time


def chat(body, *, timeout=30):
    data=json.dumps(body,allow_nan=False).encode()
    if len(data)>65536:raise ValueError("Model request exceeds bound")
    wire=(b"POST /api/chat HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: "
          +str(len(data)).encode()+b"\r\n\r\n"+data)
    deadline=time.monotonic()+timeout
    raw=bytearray()
    with socket.create_connection(("127.0.0.1",11434),timeout=min(timeout,5)) as conn:
        conn.settimeout(max(0.001,deadline-time.monotonic()))
        conn.sendall(wire)
        while True:
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError("Model request deadline expired")
            conn.settimeout(remaining)
            chunk=conn.recv(8192)
            if not chunk:break
            raw.extend(chunk)
            if len(raw)>81920:raise ValueError("Model HTTP response exceeds bound")
    boundary=raw.find(b"\r\n\r\n")
    if not 0<boundary<=16384:raise ValueError("Invalid/big model HTTP headers")
    class Buffered:
        def makefile(self,*args,**kwargs):return io.BytesIO(raw)
    response=http.client.HTTPResponse(Buffered());response.begin()
    if response.status!=200:raise ValueError("Local model unavailable; redirects are forbidden")
    payload=response.read(65537)
    if len(payload)>65536:raise ValueError("Model payload exceeds bound")
    return json.loads(payload)
