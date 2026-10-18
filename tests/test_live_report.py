import json
from pathlib import Path

from forensic_agent.agent.loop import analyze, prepare_next_question
from forensic_agent.agent.ollama import Claim, Decision, TaskReview
from forensic_agent.evidence import Case
from forensic_agent.gui import Workspace
from forensic_agent.models import ToolRequest
from forensic_agent.reports import generate_report
from forensic_agent.reports.live import publish_section, publish_tool


class Client:
    def __init__(self, events):
        self.events, self.calls = events, 0

    def discover(self):
        return {"test_only": True}

    def decide(self, messages):
        self.calls += 1
        if self.calls == 1:
            decision = Decision(task_review=TaskReview(targets=["SECRET原文"], scope="当前文本",
                constraints=["保留原文"], evidence_needed=["原文行及行号"], missing=[], stop_when="找到原文或说明不足"),
                plan=["目的：定位原文；工具search/s00001；范围当前文本；预期text和行号；命中后结束，未命中说明范围"],
                action="tool", request=ToolRequest(tool_id="search", source_id="s00001", params={"keyword": "SECRET"}))
        else:
            assert any(isinstance(e, dict) and e.get("type") == "report_section" and "工具结果" in e["title"]
                       for e in self.events)
            decision = Decision(action="finish", claims=[Claim(evidence_id="step0001:r00001", field="text", value="SECRET-旗标-42")])
        return decision, {"message": {"content": decision.model_dump_json()}}


def test_sections_arrive_before_finish_and_do_not_add_model_or_tool_calls(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings, '搜索关键词 "SECRET"')
    events = []
    client = Client(events)
    analyze(case, client=client, progress=events.append)
    sections = [e for e in events if isinstance(e, dict) and e.get("type") == "report_section"]
    assert [e["title"] for e in sections][:3] == ["分析已开始", "审题与证据标准", "详细分析计划"]
    assert client.calls == 2 and len(case.manifest["steps"]) == 1
    assert case.manifest["answers"][0]["value"] == "SECRET-旗标-42"
    journal = case.directory / case.manifest["analysis_runs"][-1]["live_report"]
    rows = [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == len(sections)
    report = generate_report(case).read_text(encoding="utf-8")
    assert report.index("## 答案摘要") < report.index("审题摘要与证据标准") < report.index("分步操作计划")
    assert "答案目标" in report and "完成与停止条件" in report and "未命中说明范围" in report


def test_journal_failure_preserves_primary_state_and_budgets(evidence, settings, monkeypatch):
    case = Case.create(evidence / "日志.txt", settings, "test")
    case.manifest.update(analysis_runs=[{}], state="model_failed", warnings=["first error"],
                         repair_budgets={"claim": True, "decision": True})
    original = Path.open

    def fail(path, *args, **kwargs):
        if path.name.startswith("live-run-"):
            raise PermissionError("journal denied")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail)
    events = []
    publish_section(case, "x", "部分结果", "待核验", events.append)
    assert events and case.manifest["state"] == "model_failed"
    assert case.manifest["warnings"][0] == "first error"
    assert case.manifest["repair_budgets"] == {"claim": True, "decision": True}
    assert generate_report(case).is_file()


def test_partial_preview_does_not_hide_omission(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings, "test")
    case.manifest["analysis_runs"] = [{}]
    step = {"id": "step0001", "request": {"tool_id": "pcap", "source_id": "s00001", "params": {}},
            "result": {"status": "partial", "error": None, "warnings": ["采集截断"]},
            "evidence": [{"id": f"step0001:r{i:05d}", "source_id": "s00001", "locator": {}, "data": {"count": None}}
                         for i in range(1, 5)]}
    events = []
    publish_tool(case, step, events.append)
    text = events[0]["text"]
    assert "partial" in text and "仅预览前3条" in text and "采集截断" in text
    assert '"count": null' in text


def test_new_question_keeps_previous_journal(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings, '搜索关键词 "SECRET"')
    analyze(case, no_model=True)
    first = case.directory / case.manifest["analysis_runs"][-1]["live_report"]
    previous = first.read_bytes()
    assert prepare_next_question(case, "SHA256")
    analyze(case, no_model=True)
    assert first.read_bytes() == previous
    second = case.directory / case.manifest["analysis_runs"][-1]["live_report"]
    assert second != first and all(json.loads(line)["question_id"] == "q0002"
                                  for line in second.read_text(encoding="utf-8").splitlines())


def test_gui_sections_are_bounded_and_do_not_become_answers(settings, tmp_path):
    config = tmp_path / "gui.toml"
    config.write_text(f"work_dir = {json.dumps(str(settings.work_dir))}\n", encoding="utf-8")
    workspace = Workspace(config)
    workspace.task = {"logs": [], "result": None}
    for i in range(70):
        workspace._event({"progress": "chunk", "report_section": {"id": str(i), "title": "<script>",
            "text": "x" * 12000, "status": "待核验", "question_id": "q0001"}})
    snapshot = workspace.snapshot()
    assert len(snapshot["report_sections"]) == 64
    assert len(snapshot["report_sections"][-1]["text"]) == 10000
    assert workspace.task["result"] is None
    snapshot["report_sections"][-1]["text"] = "mutated"
    assert workspace.snapshot()["report_sections"][-1]["text"] != "mutated"
