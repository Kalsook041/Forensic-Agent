import json
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from forensic_agent.gui import BusyError, LocalServer, Workspace


@pytest.fixture
def workspace(tmp_path):
    config = tmp_path / "gui.toml"
    config.write_text(f"work_dir = {json.dumps(str(tmp_path / 'cases'))}\n"
                      "[limits]\nreserve_disk_bytes = 0\n", encoding="utf-8")
    return Workspace(config)


@pytest.fixture
def server(workspace):
    app = LocalServer(workspace)
    thread = threading.Thread(target=app.serve_forever, daemon=True)
    thread.start()
    yield app
    app.shutdown()
    app.server_close()
    thread.join(timeout=5)
    if workspace.worker:
        workspace.worker.join(timeout=30)


def request(server, path, data=None, headers=None):
    hdrs = {"X-Session-Token": server.workspace.token, **(headers or {})}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    req = Request(server.origin + path, data=json.dumps(data).encode() if data is not None else None,
                  headers=hdrs)
    return urlopen(req, timeout=10)


def test_cancel_api_checks_session_origin_and_current_task(server):
    from collections import deque
    server.workspace.task = {"id": "current", "status": "running", "logs": deque(), "cancel_requested": False}
    for headers in ({"X-Session-Token": "wrong"}, {"Origin": "https://example.com"}):
        with pytest.raises(HTTPError) as error:
            request(server, "/api/cancel", {"id": "current"}, headers=headers)
        assert error.value.code == 403
    for payload in ({}, {"id": "old"}, {"id": ["current"]}):
        with pytest.raises(HTTPError) as error:
            request(server, "/api/cancel", payload)
        assert error.value.code == 400
    assert server.workspace.snapshot()["status"] == "running"
    with request(server, "/api/cancel", {"id": "current"}) as response:
        assert json.load(response)["task"]["status"] == "cancelling"


def test_page_assets_and_bootstrap(server):
    with request(server, "/") as response:
        html = response.read().decode()
        assert server.workspace.token in html
        assert "__SESSION_TOKEN__" not in html
        assert "895069c8" in html
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    for path in ("/app.js", "/app.css"):
        with request(server, path) as response:
            assert response.status == 200
    with request(server, "/api/bootstrap") as response:
        data = json.load(response)
        assert "search" in data["tools"] and data["max_question"] == 1000


def test_manual_guide_is_authenticated_and_confined(server):
    with request(server, "/api/manual-guide") as response:
        data = json.load(response)
        assert "人工操作指南" in data["text"] and data["needed"]
    for path, headers, status in [
        ("/api/manual-guide", {"X-Session-Token": ""}, 403),
        ("/api/manual-guide", {"Origin": "https://evil.example"}, 403),
        ("/api/manual-guide?case=..%2Foutside", {}, 400),
    ]:
        with pytest.raises(HTTPError) as error:
            request(server, path, headers=headers)
        assert error.value.code == status
    assert server.workspace.snapshot() is None


def test_case_guide_works_without_report_or_rehash(server, tmp_path, monkeypatch):
    from forensic_agent.evidence import Case

    source = tmp_path / "SYSTEM"
    source.write_bytes(b"fixture")
    case = Case.create(source, server.workspace.settings, "计算机名")
    case.manifest["state"] = "model_failed"
    case.save()
    assert not (case.directory / "report.md").exists()
    monkeypatch.setattr(Case, "record_integrity", lambda *a, **k: pytest.fail("Guide must not rehash"))
    with request(server, f"/api/manual-guide?case={case.manifest['case_id']}") as response:
        guide = json.load(response)
        assert guide["needed"] and "ComputerName" in guide["text"]
        assert guide["state"] == "model_failed"
    assert not case.manifest["steps"] and server.workspace.snapshot() is None


@pytest.mark.parametrize("headers", [
    {"X-Session-Token": "wrong"}, {"Origin": "https://example.com"},
    {"Host": "evil.example"}, {"Sec-Fetch-Site": "cross-site"},
])
def test_reject_foreign_session_and_origin(server, headers):
    with pytest.raises(HTTPError) as error:
        request(server, "/api/start", {"action": "doctor"}, headers)
    assert error.value.code == 403
    assert server.workspace.snapshot() is None


def test_static_traversal_and_unauthenticated_read(server):
    for path, headers, status in [("/../config/default.toml", {}, 404),
                                   ("/api/bootstrap", {"X-Session-Token": ""}, 403),
                                   ("/api/report?case=..", {}, 400)]:
        with pytest.raises(HTTPError) as error:
            request(server, path, headers=headers)
        assert error.value.code == status


def test_validation_before_case_creation(workspace, tmp_path):
    evidence = tmp_path / "线索.txt"
    evidence.write_text("FLAG", encoding="utf-8")
    for change in [{"question": ""}, {"question": "题" * 1001}, {"mode": "remote"},
                   {"evidence": str(tmp_path / "missing")}, {"evidence": str(tmp_path)}]:
        data = {"action": "analyze", "evidence": str(evidence), "question": "搜索关键词 FLAG", **change}
        with pytest.raises((ValueError, OSError)):
            workspace.start(data)
    assert workspace.task is None
    assert not workspace.settings.work_dir.exists()
    with pytest.raises(ValueError):
        workspace.command({"action": "tool", "evidence": str(evidence), "tool_id": "shell", "params": {}})


def test_real_rules_analysis_report_and_repeat_guard(server, tmp_path):
    evidence = tmp_path / "中文检材.txt"
    evidence.write_text("第一行\nFLAG-GUI-2026\n", encoding="utf-8")
    original = evidence.read_bytes()
    with request(server, "/api/start", {"action": "analyze", "mode": "rules",
                                       "evidence": str(evidence), "question": '搜索关键词 "FLAG"'}) as response:
        assert response.status == 202
        assert json.load(response)["task"]["status"] == "running"
    with pytest.raises(BusyError):
        server.workspace.start({"action": "doctor"})
    with pytest.raises(HTTPError) as error:
        request(server, "/api/shutdown", {})
    assert error.value.code == 409
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        with request(server, "/api/task") as response:
            task = json.load(response)["task"]
        if task["status"] != "running":
            break
        time.sleep(.1)
    assert task["status"] == "completed", task
    assert task["result"]["state"] == "completed_without_model"
    assert any("search" in line for line in task["logs"])
    with request(server, "/api/report?case=" + task["case"]) as response:
        report = json.load(response)
    assert "FLAG-GUI-2026" in report["text"]
    assert evidence.read_bytes() == original
    case = server.workspace.case_path(task["case"])
    assert (case / "case.json").is_file()
    with request(server, "/api/cases") as response:
        assert json.load(response)["cases"][0]["id"] == task["case"]
    # Rechecking an existing report detects changed evidence; the GUI preserves the CLI failure.
    evidence.write_text("changed", encoding="utf-8")
    server.workspace.start({"action": "report", "case": task["case"]})
    server.workspace.worker.join(timeout=20)
    state = server.workspace.snapshot()
    assert state["status"] == "failed"
    assert state["exit_code"] == 2
    assert state["case"] == task["case"]
    assert json.loads((case / "case.json").read_text(encoding="utf-8"))["state"] == "evidence_changed"


def test_direct_tool_args_preserve_chinese_and_json(workspace, tmp_path):
    evidence = tmp_path / "中文.txt"
    evidence.write_text("hello", encoding="utf-8")
    args = workspace.command({"action": "tool", "evidence": str(evidence), "tool_id": "search",
                              "params": {"keyword": '中文 "值"'}})
    assert json.loads(args[-1]) == {"keyword": '中文 "值"'}
    assert str(evidence) in args


def test_continue_command_reuses_an_existing_case_without_evidence(workspace, tmp_path):
    from forensic_agent.evidence import Case

    evidence = tmp_path / "线索.txt"
    evidence.write_text("SECRET", encoding="utf-8")
    case = Case.create(evidence, workspace.settings, '搜索关键词 "SECRET"')

    args = workspace.command({"action": "continue", "case": case.manifest["case_id"], "mode": "model"})

    assert args[args.index("analyze") + 1:args.index("analyze") + 3] == ["--case", str(case.directory)]
    assert str(evidence) not in args
    assert "--question" not in args and "--evidence" not in args
    with pytest.raises(ValueError, match="只支持自动规划或规则模式"):
        workspace.command({"action": "continue", "case": case.manifest["case_id"], "mode": "tool"})


def test_new_question_endpoint_uses_existing_case_and_retains_old_report(server, tmp_path):
    from forensic_agent.evidence import Case
    from forensic_agent.reports import generate_report

    evidence = tmp_path / "question.txt"
    evidence.write_text("SECRET", encoding="utf-8")
    case = Case.create(evidence, server.workspace.settings, '搜索关键词 "SECRET"')
    generate_report(case)
    previous_report = (case.directory / "report.md").read_bytes()
    snapshot = case.sources["s00001"].working_path
    with request(server, "/api/start", {"action": "new_question", "case": case.directory.name,
                                       "question": "SHA256", "mode": "rules"}) as response:
        assert response.status == 202
    server.workspace.worker.join(timeout=40)
    task = server.workspace.snapshot()
    assert task["status"] == "completed", task
    updated = Case(case.directory, server.workspace.settings)
    assert updated.manifest["question_id"] == "q0002"
    assert updated.sources["s00001"].working_path == snapshot
    assert len(list(server.workspace.settings.work_dir.iterdir())) == 1
    with request(server, f"/api/report?case={case.directory.name}&question=q0001") as response:
        report = json.load(response)
        assert report["archived"] and report["text"].encode("utf-8") == previous_report
    with pytest.raises(HTTPError) as error:
        request(server, f"/api/report?case={case.directory.name}&question=../case.json")
    assert error.value.code == 400


def test_rules_continuation_verifies_then_reuses_same_snapshot(server, tmp_path):
    from forensic_agent.evidence import Case

    evidence = tmp_path / "continuation.txt"
    evidence.write_text("SECRET-GUI-CONTINUATION", encoding="utf-8")
    case = Case.create(evidence, server.workspace.settings, '搜索关键词 "SECRET"')
    snapshot = case.sources["s00001"].working_path
    original = evidence.read_bytes()

    with request(server, "/api/start", {"action": "continue", "case": case.manifest["case_id"], "mode": "rules"}) as response:
        assert response.status == 202
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        with request(server, "/api/task") as response:
            task = json.load(response)["task"]
        if task["status"] != "running":
            break
        time.sleep(.1)

    assert task["status"] == "completed", task
    assert task["result"]["continued"] is True
    assert task["result"]["state"] == "completed_without_model"
    updated = Case(case.directory, server.workspace.settings)
    assert updated.sources["s00001"].working_path == snapshot
    assert evidence.read_bytes() == original
    assert updated.manifest["continuations"][-1]["outcome"] == "ready"
    assert [phase["stage"] for phase in updated.manifest["phases"]].count("copy_snapshot") == 1


def test_malformed_body(server):
    req = Request(server.origin + "/api/start", data=b"[]", headers={
        "X-Session-Token": server.workspace.token, "Content-Type": "application/json"})
    with pytest.raises(HTTPError) as error:
        urlopen(req, timeout=5)
    assert error.value.code == 400


def test_saved_report_does_not_follow_symlink(workspace, tmp_path):
    root = workspace.settings.work_dir
    case = root / "case-1"
    case.mkdir(parents=True)
    (case / "case.json").write_text("{}", encoding="utf-8")
    outside = tmp_path / "outside.md"
    outside.write_text("private", encoding="utf-8")
    try:
        (case / "report.md").symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation requires Windows developer mode or permission")
    with pytest.raises(ValueError):
        workspace.report("case-1")
