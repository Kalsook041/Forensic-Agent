import json
from pathlib import Path

import pytest

from forensic_agent.agent.loop import analyze, prepare_next_question
from forensic_agent.cli import main
from forensic_agent.evidence import Case
from forensic_agent.gui import Workspace
from forensic_agent.models import ToolRequest
from forensic_agent.reports import generate_report
from forensic_agent.tools.runner import run_tool


def previous_case(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings, '搜索关键词 "SECRET"')
    analyze(case, no_model=True)
    generate_report(case)
    return case


def test_next_question_keeps_snapshot_and_separate_question_reports(evidence, settings, monkeypatch):
    case = previous_case(evidence, settings)
    snapshot = Path(case.sources["s00001"].working_path)
    stat = snapshot.stat()
    previous_report = (case.directory / "report.md").read_bytes()
    previous_steps = json.loads(json.dumps(case.manifest["steps"]))
    case.manifest["repair_budgets"] = {"claim": True, "decision": True}
    case.save()
    monkeypatch.setattr(Case, "_snapshot", lambda *args: pytest.fail("must not create another snapshot"))

    assert prepare_next_question(case, "这份检材的SHA256是多少？")
    analyze(case, no_model=True)
    generate_report(case)

    assert case.manifest["question_id"] == "q0002"
    assert case.manifest["question_history"][0]["question"] == '搜索关键词 "SECRET"'
    assert case.manifest["steps"][0] == previous_steps[0]
    assert case.manifest["steps"][1]["question_id"] == "q0002"
    assert case.manifest["repair_budgets"] == {"claim": True, "decision": True}
    assert snapshot.stat().st_mtime_ns == stat.st_mtime_ns
    assert len(list(settings.work_dir.iterdir())) == 1
    archived = case.directory / case.manifest["question_history"][0]["report_directory"] / "report.md"
    assert archived.read_bytes() == previous_report
    assert "SHA256" in (case.directory / "report.md").read_text(encoding="utf-8")


def test_new_question_does_not_adopt_previous_answers_or_plan(evidence, settings):
    case = previous_case(evidence, settings)
    case.manifest.update(answers=[{"value": "old answer"}], plan=["old plan"])
    case.save()
    assert prepare_next_question(case, "统计另一个内容")
    assert case.manifest["answers"] == [] and case.manifest["plan"] == []
    assert not case.manifest["historical_answers"]
    assert case.manifest["question_history"][0]["answers"] == [{"value": "old answer"}]


def test_new_question_reuses_prior_effective_rule_result_without_new_tool(evidence, settings):
    case = previous_case(evidence, settings)
    assert prepare_next_question(case, '再次搜索关键词 "SECRET" 并保留来源')
    analyze(case, no_model=True)
    assert len(case.manifest["steps"]) == 1
    assert case.manifest["reused_step_ids"] == ["step0001"]
    assert case.manifest["state"] == "completed_without_model"
    assert not case.manifest["answers"]


@pytest.mark.parametrize("question", ["", "   ", "题" * 1001, None, ["new"]])
def test_invalid_next_question_does_not_change_case(evidence, settings, question):
    case = previous_case(evidence, settings)
    before = (case.directory / "case.json").read_bytes()
    with pytest.raises(ValueError):
        prepare_next_question(case, question)
    assert (case.directory / "case.json").read_bytes() == before


def test_changed_evidence_prevents_switching_question(evidence, settings):
    case = previous_case(evidence, settings)
    (evidence / "日志.txt").write_bytes(b"changed")
    assert not prepare_next_question(case, "下一道题")
    assert case.manifest["question"] == '搜索关键词 "SECRET"'
    assert not case.manifest.get("question_history")
    assert case.manifest["state"] == "evidence_changed"
    assert len(case.manifest["steps"]) == 1


def test_cli_new_question_and_archived_report_access(evidence, settings, tmp_path, capsys):
    case = previous_case(evidence, settings)
    config = tmp_path / "config.toml"
    config.write_text(f"work_dir = {json.dumps(str(settings.work_dir))}\n", encoding="utf-8")
    assert main(["--config", str(config), "analyze", "--case", str(case.directory),
                 "--new-question", "SHA256", "--no-model"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["reused"] and result["question_id"] == "q0002"
    workspace = Workspace(config)
    archived = workspace.report(case.directory.name, "q0001")
    assert archived["archived"] and 'SECRET' in archived["text"]
    assert not workspace.report(case.directory.name, "q0002")["archived"]
    with pytest.raises(ValueError):
        workspace.report(case.directory.name, "../case.json")
    with pytest.raises(ValueError):
        workspace.report(case.directory.name, "q9999")
    args = workspace.command({"action": "new_question", "case": case.directory.name,
                              "question": "新题内容", "mode": "rules"})
    assert "--new-question" in args and "--evidence" not in args


def test_archived_report_cannot_escape_case(evidence, settings, tmp_path):
    case = previous_case(evidence, settings)
    assert prepare_next_question(case, "下一题")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "report.md").write_text("private", encoding="utf-8")
    case.manifest["question_history"][0]["report_directory"] = str(outside)
    case.save()
    workspace = Workspace()
    workspace.settings = settings
    with pytest.raises(ValueError, match="越界"):
        workspace.report(case.directory.name, "q0001")


def test_failed_prior_result_is_not_reused_as_success(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings, "旧题")
    step = run_tool(case, ToolRequest(tool_id="hash", source_id="s00001"))
    step["result"]["status"] = "failed"
    case.manifest["state"] = "tool_failed"
    case.save()
    assert prepare_next_question(case, "SHA256")
    analyze(case, no_model=True)
    assert case.manifest["state"] == "stopped_duplicate"
    assert not case.manifest.get("reused_step_ids")
