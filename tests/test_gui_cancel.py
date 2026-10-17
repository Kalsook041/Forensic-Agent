import json
from pathlib import Path
import sys
import threading
import time

import pytest

from forensic_agent.evidence import Case
from forensic_agent.gui import BusyError, Workspace
from forensic_agent.tools.process import WindowsJob
from forensic_agent.reports import generate_report


@pytest.fixture
def workspace(tmp_path):
    config = tmp_path / "gui.toml"
    config.write_text(f"work_dir = {json.dumps(str(tmp_path / 'cases'))}\n"
                      "[limits]\nreserve_disk_bytes = 0\n", encoding="utf-8")
    app = Workspace(config)
    yield app
    if app.worker and app.worker.is_alive():
        app.cancel(app.snapshot()["id"])
        app.worker.join(timeout=10)


def wait_until(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "worker did not reach the expected state"
        time.sleep(.02)


def test_cancel_kills_started_descendant_and_allows_next_task(workspace, tmp_path, process_tree_probe, monkeypatch):
    monkeypatch.setattr(workspace, "command", lambda data:
                        [sys.executable, "-I", "-c", process_tree_probe.script(True)])
    task = workspace.start({"action": "doctor"})
    wait_until(process_tree_probe.ready.exists)
    with pytest.raises(ValueError):
        workspace.cancel("wrong-task")
    assert workspace.snapshot()["status"] == "running"
    start = time.monotonic()
    workspace.cancel(task["id"])
    workspace.cancel(task["id"])
    workspace.worker.join(timeout=10)
    assert not workspace.worker.is_alive() and time.monotonic() - start < 10
    process_tree_probe.assert_stopped()
    assert workspace.snapshot()["status"] == "cancelled"
    assert sum("用户请求中止" in line for line in workspace.snapshot()["logs"]) == 1
    monkeypatch.setattr(workspace, "command", lambda data: [sys.executable, "-I", "-c", "print('{}')"])
    workspace.start({"action": "doctor"})
    workspace.worker.join(timeout=10)
    assert workspace.snapshot()["status"] == "completed"


def test_cancel_before_launch_gate_never_runs_target(workspace, tmp_path, monkeypatch):
    ready, release = threading.Event(), threading.Event()
    original = WindowsJob.assign

    def held(job, pid):
        original(job, pid)
        ready.set()
        assert release.wait(timeout=5)

    marker = tmp_path / "target-ran"
    monkeypatch.setattr(WindowsJob, "assign", held)
    monkeypatch.setattr(workspace, "command", lambda data:
                        [sys.executable, "-I", "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"])
    task = workspace.start({"action": "doctor"})
    try:
        assert ready.wait(timeout=5)
        workspace.cancel(task["id"])
        with pytest.raises(BusyError):
            workspace.start({"action": "doctor"})
    finally:
        release.set()
        workspace.worker.join(timeout=10)
    assert workspace.snapshot()["status"] == "cancelled"
    assert not marker.exists()


def test_intake_cancel_preserves_original_and_writes_diagnostics(workspace, tmp_path, monkeypatch):
    evidence = tmp_path / "original.txt"
    evidence.write_bytes(b"original")
    script = ("import json,time; from pathlib import Path; "
              "from forensic_agent.settings import load_settings; from forensic_agent.evidence import Case; "
              "Case._snapshot=lambda *args: time.sleep(30); "
              f"Case.create(Path({str(evidence)!r}),load_settings(Path({str(workspace.config)!r})),"
              "'test',progress=lambda event: print(json.dumps({'progress':'intake','progress_event':event}),flush=True))")
    monkeypatch.setattr(workspace, "command", lambda data: [sys.executable, "-I", "-u", "-c", script])
    task = workspace.start({"action": "analyze"})
    wait_until(lambda: workspace.snapshot()["case"] is not None)
    workspace.cancel(task["id"])
    workspace.worker.join(timeout=10)
    result = workspace.snapshot()
    assert result["status"] == "cancelled"
    case = Case(workspace.case_path(result["case"]), workspace.settings)
    assert case.manifest["state"] == "cancelled" and not case.manifest["answers"]
    assert (case.directory / "report.md").is_file()
    assert evidence.read_bytes() == b"original"


def test_job_assignment_failure_never_launches_task(workspace, tmp_path, monkeypatch):
    marker = tmp_path / "bad-launch"
    monkeypatch.setattr(WindowsJob, "assign", lambda *args: (_ for _ in ()).throw(OSError("denied")))
    monkeypatch.setattr(workspace, "command", lambda data:
                        [sys.executable, "-I", "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"])
    workspace.start({"action": "doctor"})
    workspace.worker.join(timeout=10)
    assert workspace.snapshot()["status"] == "failed" and not marker.exists()


def test_interrupted_report_write_preserves_previous_report(workspace, tmp_path, monkeypatch):
    source = tmp_path / "source.txt"
    source.write_text("data", encoding="utf-8")
    case = Case.create(source, workspace.settings, "question")
    report = generate_report(case)
    previous = report.read_bytes()
    original = Path.write_text

    def fail(path, *args, **kwargs):
        if path.name == "report.md.tmp":
            raise OSError("synthetic interrupted write")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail)
    with pytest.raises(OSError, match="interrupted"):
        generate_report(case)
    assert report.read_bytes() == previous


def test_cancel_during_continuation_verification_keeps_prior_case(workspace, tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("data", encoding="utf-8")
    case = Case.create(source, workspace.settings, "question")
    generate_report(case)
    before = (case.directory / "case.json").read_bytes()
    workspace.task = {"case": case.directory.name, "action": "continue", "prior_analysis_runs": 0}
    workspace._save_cancelled_case()
    assert (case.directory / "case.json").read_bytes() == before
