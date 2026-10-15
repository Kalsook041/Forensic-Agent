"""Review #8: trusted launch gating and descendant pipe cleanup."""
import os
import sys
import threading
import time
import subprocess

import pytest

from forensic_agent.tools import process


pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows Job regression")


def run_capture(tmp_path, script, **kwargs):
    return process.capture([sys.executable, "-I", "-c", script], cwd=tmp_path,
                           env=process.clean_environment(tmp_path), max_output=65536,
                           timeout=kwargs.pop("timeout", 2), **kwargs)


def test_normal_output_input_and_nonzero(tmp_path):
    out = tmp_path / "stdout.bin"
    err = tmp_path / "stderr.bin"
    result = run_capture(tmp_path,
                         "import sys; print(sys.stdin.buffer.read().decode()); "
                         "print('error', file=sys.stderr); sys.exit(7)",
                         input_bytes=b"hello", stdout_path=out, stderr_path=err)
    assert result.returncode == 7
    assert result.stopped is None
    assert result.stdout.strip() == b"hello"
    assert result.stderr.strip() == b"error"
    assert out.read_bytes() == result.stdout
    assert err.read_bytes() == result.stderr


@pytest.mark.parametrize("root_waits", [False, True])
def test_descendant_holding_pipes_is_killed(tmp_path, root_waits, process_tree_probe):
    script = process_tree_probe.script(root_waits)
    before_threads = set(threading.enumerate())
    start = time.monotonic()
    result = run_capture(tmp_path, script, timeout=2)
    assert time.monotonic() - start < 3
    assert result.stopped == ("timeout" if root_waits else None)
    assert b"started" in result.stdout
    assert set(threading.enumerate()) <= before_threads
    process_tree_probe.assert_stopped()


def test_descendant_probe_detects_live_process(process_tree_probe):
    child = subprocess.Popen([sys.executable, "-I", "-c", process_tree_probe.child_script],
                             creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        deadline = time.monotonic() + 5
        while not process_tree_probe.ready.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert process_tree_probe.ready.exists()
        with pytest.raises(AssertionError, match="Descendant survived"):
            process_tree_probe.assert_stopped()
    finally:
        child.terminate()
        child.wait(timeout=5)
    process_tree_probe.assert_stopped()


def test_assignment_failure_never_launches_target(tmp_path, monkeypatch):
    marker = tmp_path / "launched"
    closed = []
    original_close = process.WindowsJob.close

    def deny(self, pid):
        raise OSError("synthetic assignment denial")

    def close(self):
        closed.append(True)
        original_close(self)

    monkeypatch.setattr(process.WindowsJob, "assign", deny)
    monkeypatch.setattr(process.WindowsJob, "close", close)
    with pytest.raises(OSError, match="assignment denial"):
        run_capture(tmp_path, f"from pathlib import Path; Path({str(marker)!r}).touch()")
    assert closed
    assert not marker.exists()


def test_creation_failure_closes_owned_job(tmp_path, monkeypatch):
    closed = []
    original_close = process.WindowsJob.close

    def fail(*args, **kwargs):
        raise OSError("synthetic create failure")

    def close(self):
        closed.append(True)
        original_close(self)

    monkeypatch.setattr(process.subprocess, "Popen", fail)
    monkeypatch.setattr(process.WindowsJob, "close", close)
    with pytest.raises(OSError, match="create failure"):
        run_capture(tmp_path, "pass")
    assert closed


def test_timeout_unblocks_large_stdin_writer(tmp_path):
    before_threads = set(threading.enumerate())
    start = time.monotonic()
    result = run_capture(tmp_path, "import time; time.sleep(30)", timeout=0.3,
                         input_bytes=b"x" * (1024 * 1024))
    assert result.stopped == "timeout"
    assert time.monotonic() - start < 3
    assert set(threading.enumerate()) <= before_threads
