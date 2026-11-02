"""Process-group supervision with bounded pipes, input and wall-clock deadlines."""
import os
import selectors
import signal
import subprocess
import time

from .service import Execution
from .system import LinuxSystemAdapter


class SupervisedLinuxAdapter(LinuxSystemAdapter):
    def _run(self, op_id, argv, stdin, timeout_s):
        if not self.resolve_identity().ordinary():
            return Execution(op_id, argv, None, started=False, error="Ordinary account required")
        if not 0 < timeout_s <= 120 or len(stdin) > 65536:
            return Execution(op_id, argv, None, started=False, error="Process budget invalid")
        cancel = getattr(self, "cancel_event", None)
        if cancel and cancel.is_set():
            return Execution(op_id, argv, None, started=False, error="Cancelled before launch")
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "SYSTEMD_PAGER": "cat"}
        buffers, error, proc = {"stdout": bytearray(), "stderr": bytearray()}, "", None
        deadline = time.monotonic() + timeout_s
        last_progress = 0.0
        try:
            proc = subprocess.Popen(list(argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    shell=False, cwd="/", env=env, close_fds=True, start_new_session=True)
            with selectors.DefaultSelector() as selector:
                for name in buffers:
                    pipe = getattr(proc, name)
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, name)
                pending = memoryview(stdin)
                if pending:
                    os.set_blocking(proc.stdin.fileno(), False)
                    selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
                else:
                    proc.stdin.close()
                while selector.get_map():
                    if cancel and cancel.is_set():
                        error = "Cancelled read operation"
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        error = "Command deadline exceeded"
                        break
                    for key, events in selector.select(min(remaining, 0.1)):
                        if key.data == "stdin":
                            try:
                                pending = pending[os.write(key.fd, pending[:4096]):]
                            except BrokenPipeError:
                                pending = memoryview(b"")
                            if not pending:
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                        else:
                            chunk = os.read(key.fd, 8192)
                            if not chunk:
                                selector.unregister(key.fileobj)
                            else:
                                buf = buffers[key.data]
                                budget = self.OUTPUT_LIMIT - len(buf)
                                buf.extend(chunk[:budget])
                                callback = getattr(self, "progress", None)
                                if callback and time.monotonic() - last_progress >= 0.25:
                                    try:
                                        callback(op_id, key.data, bytes(buf[-8192:]).decode(errors="replace"))
                                    except Exception:
                                        self.progress_degraded = True
                                    last_progress = time.monotonic()
                                if len(chunk) > budget:
                                    error = "Output limit exceeded"
                    if error:
                        break
            if error:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait(timeout=max(0.1, deadline - time.monotonic()) if not error else 2)
        except (OSError, subprocess.SubprocessError) as exc:
            error = f"Command I/O, deadline or launch failed: {exc}"
        finally:
            if proc:
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait(timeout=2)
                for pipe in (proc.stdin, proc.stdout, proc.stderr):
                    pipe.close()
        return Execution(op_id, argv, proc.returncode if proc else None,
                         buffers["stdout"].decode(errors="replace"), buffers["stderr"].decode(errors="replace"),
                         started=proc is not None, error=error)
