"""Real local process/pipe tests; no SSH connection or PVE operation."""

from __future__ import annotations

import os
import selectors
import subprocess
import sys
import time

import pytest

from privilege_broker.pve._ssh_capture import SshCaptureError, SshOutputLimitExceeded, run_ssh

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX pipe capture adapter")


@pytest.fixture
def children(monkeypatch):
    real_popen = subprocess.Popen
    started = []

    def tracked_popen(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        started.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", tracked_popen)
    yield started
    for child in started:
        reaped = child.returncode is not None
        if not reaped:
            child.kill()
            child.wait()
        assert reaped, "the capture adapter must reap its child"
        assert all(pipe.closed for pipe in (child.stdin, child.stdout, child.stderr))


def _run(code, *, input="payload", timeout=5):
    return run_ssh([sys.executable, "-c", code], input=input, timeout=timeout, capture_output=True, text=True)


def test_duplex_pipes_do_not_deadlock_with_large_stdin(children) -> None:
    code = (
        "import sys\n"
        "sys.stdout.buffer.write(b'x' * 32768); sys.stdout.flush()\n"
        "data = sys.stdin.buffer.read()\n"
        "sys.stderr.write(str(len(data)))\n"
    )
    result = _run(code, input="p" * (512 * 1024))
    assert result.returncode == 0
    assert result.stdout == "x" * 32768
    assert result.stderr == str(512 * 1024)
    assert len(children) == 1


@pytest.mark.parametrize("combined", [False, True], ids=["stdout-only", "both-streams"])
def test_exact_combined_byte_budget_is_accepted(children, combined) -> None:
    count = 32768 if combined else 65536
    code = f"import sys; sys.stdout.buffer.write(b'o' * {count}); sys.stdout.flush()"
    if combined:
        code += "; sys.stderr.buffer.write(b'e' * 32768); sys.stderr.flush()"
    result = _run(code)
    assert len(result.stdout) == count
    assert len(result.stderr) == (32768 if combined else 0)


def test_one_byte_over_combined_budget_aborts(children, monkeypatch) -> None:
    code = "import sys; sys.stdout.buffer.write(b'o' * 32768); sys.stderr.buffer.write(b'e' * 32769)"
    real_read = os.read
    observed = []

    def observe_read(fd, amount):
        chunk = real_read(fd, amount)
        output_fds = {pipe.fileno() for child in children for pipe in (child.stdout, child.stderr) if not pipe.closed}
        if fd in output_fds:
            observed.append((amount, len(chunk)))
        return chunk

    monkeypatch.setattr(os, "read", observe_read)
    with pytest.raises(SshOutputLimitExceeded):
        _run(code)
    assert observed and max(amount for amount, _ in observed) <= 8192
    assert sum(size for _, size in observed) == 65537


def test_multibyte_output_is_counted_in_bytes(children) -> None:
    with pytest.raises(SshOutputLimitExceeded):
        _run("import sys; sys.stdout.buffer.write('é'.encode('utf-8') * 32769)")


def test_invalid_output_bytes_are_replaced(children) -> None:
    result = _run("import os; os.write(1, b'out\\xff'); os.write(2, b'err\\xfe')")
    assert result.stdout == "out\ufffd"
    assert result.stderr == "err\ufffd"


def test_timeout_covers_a_child_that_never_reads_stdin(children) -> None:
    with pytest.raises(subprocess.TimeoutExpired):
        _run("import time; time.sleep(30)", input="p" * (512 * 1024), timeout=0.2)


def test_timeout_covers_wait_after_output_pipes_close(children) -> None:
    code = "import os, time; os.close(1); os.close(2); time.sleep(30)"
    with pytest.raises(subprocess.TimeoutExpired):
        _run(code, timeout=0.2)


def test_capture_io_failure_is_ambiguous_and_reaps_child(monkeypatch, children) -> None:
    real_selector = selectors.DefaultSelector

    def broken_selector():
        selector = real_selector()

        def fail_select(*args):
            raise OSError("SYNTHETIC_CAPTURE_IO_DETAIL")

        monkeypatch.setattr(selector, "select", fail_select)
        return selector

    monkeypatch.setattr(selectors, "DefaultSelector", broken_selector)
    with pytest.raises(SshCaptureError, match="SSH output capture failed") as excinfo:
        _run("import time; time.sleep(30)")
    assert "SYNTHETIC_CAPTURE_IO_DETAIL" not in str(excinfo.value)


def test_timeout_stops_descendants_holding_output_pipes(tmp_path, children) -> None:
    ready = tmp_path / "ready"
    go = tmp_path / "go"
    survived = tmp_path / "survived"
    descendant = (
        "from pathlib import Path\nimport time\n"
        f"Path({str(ready)!r}).write_text('ready')\n"
        f"while not Path({str(go)!r}).exists(): time.sleep(0.01)\n"
        f"Path({str(survived)!r}).write_text('survived')\n"
    )
    parent = (
        f"import subprocess, sys, time\nsubprocess.Popen([sys.executable, '-c', {descendant!r}])\ntime.sleep(30)\n"
    )
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            _run(parent, timeout=1)
        assert ready.exists(), "the test must actually start the pipe-holding descendant"
    finally:
        # Also lets a surviving test descendant finish instead of leaking it.
        go.write_text("go")
    time.sleep(0.2)
    assert not survived.exists()


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_invalid_deadline_is_rejected_before_start(children, timeout) -> None:
    with pytest.raises(ValueError, match="positive and finite"):
        _run("pass", timeout=timeout)
    assert children == []
