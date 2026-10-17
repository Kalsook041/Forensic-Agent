import json

import httpx
import pytest

from forensic_agent.agent import loop
from forensic_agent.agent.ollama import Decision, OllamaClient, TaskReview, decision_schema
from forensic_agent.evidence import Case
from forensic_agent.models import ToolRequest
from forensic_agent.reports import generate_report
from forensic_agent.settings import ModelSettings


def review(target="查找SECRET记录"):
    return TaskReview(targets=[target], scope="仅当前文本；时间和时区未说明", constraints=["仅当前文本"],
                      evidence_needed=["含关键词的原始行及行号"], missing=[], stop_when="命中后引用原文；未命中说明范围")


class Client:
    def __init__(self):
        self.calls = 0
        self.contexts = []

    def discover(self):
        return {"test_only": True}

    def decide(self, messages):
        self.contexts.append(json.loads(messages[1]["content"]))
        self.calls += 1
        if self.calls == 1:
            assert self.require_task_review
            decision = Decision(task_review=review(), plan=["定位关键词→search/s00001→原始行和行号"],
                                action="tool", request=ToolRequest(tool_id="search", source_id="s00001",
                                                                   params={"keyword": "SECRET"}))
        else:
            assert not self.require_task_review
            decision = Decision(action="finish", uncertainties=["合成测试不自动回答复杂问题"])
        return decision, {"message": {"content": decision.model_dump_json()}}


def test_review_saved_before_tool_and_reused_in_context_report(evidence, settings, monkeypatch):
    case = Case.create(evidence / "日志.txt", settings, '搜索关键词 "SECRET"')
    original = loop.run_tool

    def checked(case, request):
        assert case.manifest["analysis_runs"][-1]["task_review"] == review().model_dump()
        disk = json.loads((case.directory / "case.json").read_text(encoding="utf-8"))
        assert disk["analysis_runs"][-1]["guidance_version"] == "task-review-v2"
        return original(case, request)

    monkeypatch.setattr(loop, "run_tool", checked)
    client = Client()
    loop.analyze(case, client=client)
    assert client.calls == 2 and len(case.manifest["steps"]) == 1
    assert client.contexts[-1]["task_review"] == review().model_dump()
    report = generate_report(case).read_text(encoding="utf-8")
    assert "审题摘要" in report and "仅当前文本" in report
    assert report.index("## 答案摘要") < report.index("审题摘要")


@pytest.mark.parametrize("missing", ["review", "plan"])
def test_real_client_missing_review_or_plan_is_rejected_before_tools(missing):
    payloads = []

    def response(request):
        payloads.append(json.loads(request.content))
        decision = (Decision(action="finish") if missing == "review" else
                    Decision(task_review=review(), action="tool",
                             request=ToolRequest(tool_id="hash", source_id="s00001")))
        return httpx.Response(200, json={"message": {"content": decision.model_dump_json()}})

    client = OllamaClient(ModelSettings(), transport=httpx.MockTransport(response))
    client.model_info = {}
    client.require_task_review = True
    try:
        with pytest.raises(ValueError, match="首轮"):
            client.decide([])
    finally:
        client.close()
    for branch in payloads[0]["format"]["anyOf"]:
        assert "task_review" in branch["required"]
        assert branch["properties"]["task_review"] == {"$ref": "#/$defs/TaskReview"}


def test_missing_review_stops_real_client_loop_without_running_tools(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings, "读取当前文件哈希")
    response = Decision(action="tool", plan=["读取哈希"], request=ToolRequest(tool_id="hash", source_id="s00001"))
    client = OllamaClient(ModelSettings(), transport=httpx.MockTransport(lambda request:
        httpx.Response(200, json={"message": {"content": response.model_dump_json()}})))
    client.model_info = {}
    client.discover = lambda: {"test_only": True}
    try:
        loop.analyze(case, client=client)
    finally:
        client.close()
    assert case.manifest["state"] == "model_failed" and not case.manifest["steps"]
    assert (case.directory / "model-001-0-failed.json").is_file()
    assert (case.directory / "model-001-1-failed.json").is_file()


def test_new_question_gets_new_review_not_previous_targets(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings, '搜索关键词 "SECRET"')
    loop.analyze(case, client=Client())
    assert loop.prepare_next_question(case, "再次搜索但限定下一题")
    client = Client()
    loop.analyze(case, client=client)
    assert "task_review" not in client.contexts[0]
    assert case.manifest["analysis_runs"][0]["question_id"] == "q0001"
    assert case.manifest["analysis_runs"][1]["question_id"] == "q0002"


@pytest.mark.parametrize("change", [{"targets": [" "]}, {"scope": " "}, {"stop_when": " "},
                                   {"evidence_needed": ["a" * 201]}, {"targets": ["题" * 200] * 5}])
def test_review_is_bounded_and_not_blank(change):
    with pytest.raises(ValueError):
        TaskReview.model_validate({**review().model_dump(), **change})


def test_legacy_schema_and_finish_only_remain_compatible():
    assert Decision(action="finish").task_review is None
    assert "task_review" not in decision_schema({})["anyOf"][0]["required"]
    assert len(decision_schema({}, require_task_review=True)["anyOf"]) == 1
