"""Deterministic loopback model transport tests; never starts or downloads a model."""
import io
import json
import unittest
from unittest.mock import patch
from ai.local_http import chat


class SocketDouble:
    def __init__(self,data):self.data=io.BytesIO(data);self.sent=b"";self.timeouts=[]
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def settimeout(self,value):self.timeouts.append(value)
    def sendall(self,data):self.sent=data
    def recv(self,size):return self.data.read(size)


class ModelTransportTests(unittest.TestCase):
    def test_fixed_loopback_no_proxy_and_bounded_json(self):
        payload=json.dumps({"message":{"content":"{}"}}).encode()
        sock=SocketDouble(b"HTTP/1.1 200 OK\r\nContent-Length: "+str(len(payload)).encode()+b"\r\n\r\n"+payload)
        with patch("ai.local_http.socket.create_connection",return_value=sock) as connect:
            self.assertEqual(chat({"model":"test"})["message"]["content"],"{}")
        self.assertEqual(connect.call_args.args[0],("127.0.0.1",11434))
        self.assertIn(b"Connection: close",sock.sent)
        self.assertTrue(all(0<value<=30 for value in sock.timeouts))

    def test_redirect_and_oversized_payload_are_rejected(self):
        for raw in (b"HTTP/1.1 302 Found\r\nLocation: https://external.invalid\r\n\r\n", b"x"*81921):
            with patch("ai.local_http.socket.create_connection",return_value=SocketDouble(raw)):
                with self.assertRaises(ValueError):chat({})

    def test_absolute_deadline_prevents_drip_feed_extension(self):
        sock=SocketDouble(b"HTTP/1.1 200 OK\r\n\r\n{}")
        with patch("ai.local_http.socket.create_connection",return_value=sock),patch("ai.local_http.time.monotonic",side_effect=[0,0,31]):
            with self.assertRaises(TimeoutError):chat({})
