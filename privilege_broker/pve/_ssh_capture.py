"""Private, bounded POSIX pipe capture for the worker's fixed SSH invocation."""

from __future__ import annotations

import math
import os
import selectors
import signal
import subprocess
import time

CAPTURE_LIMIT_BYTES = 64 * 1024
_IO_CHUNK = 8192


class SshCaptureError(RuntimeError):
    """Capture failed after SSH started; remote execution may have happened."""


class SshOutputLimitExceeded(SshCaptureError):
    """Combined stdout and stderr exceeded the worker's capture budget."""


def run_ssh(
    argv: list[str],
    *,
    input: str,
    capture_output: bool,
    text: bool,
    timeout: float,
    decode_errors: str = "replace",
) -> subprocess.CompletedProcess[str]:
    """Retain at most 64 KiB combined, without unbounded communicate().

    The call shape matches the worker's existing injected runner. Only the
    fixed text/capture mode is supported. POSIX nonblocking pipes multiplex
    stdin with both output streams; no reader thread or temporary file exists.
    An abort kills the owned process group before reaping its leader. This is
    process cleanup, not a sandbox against deliberately escaping descendants.
    """
    if os.name != "posix":
        raise RuntimeError("the default SSH runner requires POSIX pipes")
    if capture_output is not True or text is not True:
        raise ValueError("the SSH runner requires text capture mode")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("the SSH timeout must be positive and finite")
    payload = input.encode("utf-8")
    deadline = time.monotonic() + timeout
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    used = 0
    offset = 0
    with selectors.DefaultSelector() as selector:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            start_new_session=True,
        )
        try:
            for name in ("stdout", "stderr", "stdin"):
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                if name == "stdin" and not payload:
                    pipe.close()
                    continue
                event = selectors.EVENT_WRITE if name == "stdin" else selectors.EVENT_READ
                selector.register(pipe, event, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                for key, _ in selector.select(remaining):
                    pipe = key.fileobj
                    if key.data == "stdin":
                        try:
                            offset += os.write(pipe.fileno(), payload[offset : offset + _IO_CHUNK])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            offset = len(payload)
                        if offset == len(payload):
                            selector.unregister(pipe)
                            pipe.close()
                        continue
                    try:
                        chunk = os.read(pipe.fileno(), min(_IO_CHUNK, CAPTURE_LIMIT_BYTES - used + 1))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(pipe)
                        pipe.close()
                        continue
                    if used + len(chunk) > CAPTURE_LIMIT_BYTES:
                        raise SshOutputLimitExceeded("SSH capture limit exceeded")
                    buffers[key.data].extend(chunk)
                    used += len(chunk)
            process.wait(timeout=max(0, deadline - time.monotonic()))
        except BaseException as exc:
            # Do not poll/reap the leader before signalling: its unreaped PID
            # still identifies this call's group, including inherited pipes.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            if isinstance(exc, (subprocess.TimeoutExpired, SshCaptureError)) or not isinstance(exc, Exception):
                raise
            raise SshCaptureError("SSH output capture failed") from exc
        finally:
            for pipe in (process.stdin, process.stdout, process.stderr):
                pipe.close()
    return subprocess.CompletedProcess(
        argv,
        process.returncode,
        buffers["stdout"].decode("utf-8", errors=decode_errors),
        buffers["stderr"].decode("utf-8", errors=decode_errors),
    )
