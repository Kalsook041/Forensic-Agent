import pytest

from forensic_agent.agent.loop import validate_claims
from forensic_agent.agent.ollama import Claim
from forensic_agent.evidence import Case
from forensic_agent.models import ToolRequest
from forensic_agent.reports import generate_report
from forensic_agent.tools.runner import run_tool


def test_verified_answer_precedes_plan_and_evidence(evidence, settings):
    case = Case.create(evidence / "记录.sqlite", settings, "messages 表有多少条记录")
    run_tool(case, ToolRequest(tool_id="sqlite", source_id="s00001",
                               params={"query": "count", "table": "messages"}))
    answers, errors = validate_claims(case, [Claim(evidence_id="step0001:r00001", field="values[0]", value=3)])
    assert not errors
    case.manifest.update(answers=answers, state="completed", plan=["统计记录数"])
    report = generate_report(case).read_text(encoding="utf-8")
    summary = report.split("## 答案摘要", 1)[1].split("## 解题计划", 1)[0]
    assert "```json\n3\n```" in summary
    assert "step0001:r00001" in summary and "values\\[0\\]" in summary
    assert "人工" in summary
    assert report.index("## 答案摘要") < report.index("## 解题计划") < report.index("## 证据与定位")
    assert case.manifest["answers"] == answers


@pytest.mark.parametrize("reason", ["missing", "changed", "cancelled"])
def test_unverified_or_invalidated_answer_is_not_presented_as_current(evidence, settings, reason):
    case = Case.create(evidence / "日志.txt", settings, "查找答案")
    if reason != "missing":
        case.manifest["answers"] = [{"evidence_id": "step0001:r00001", "field": "value", "value": "STALE"}]
    if reason == "changed":
        (evidence / "日志.txt").write_text("changed", encoding="utf-8")
    report = generate_report(case, verify_integrity=reason != "cancelled").read_text(encoding="utf-8")
    summary = report.split("## 答案摘要", 1)[1].split("## 解题计划", 1)[0]
    assert "尚未得出可验证答案" in summary and "STALE" not in summary
    assert not case.manifest["answers"]
