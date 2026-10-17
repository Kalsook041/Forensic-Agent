import json

import pytest

from forensic_agent.agent.loop import analyze
from forensic_agent.agent.ollama import Claim, Decision, decision_schema
from forensic_agent.evidence import Case
from forensic_agent.models import ToolRequest


class Client:
    def __init__(self, decisions, mutate=None):
        self.decisions = iter(decisions)
        self.messages = []
        self.mutate = mutate

    def discover(self):
        return {"test_only": True}

    def decide(self, messages):
        self.messages.append(messages)
        if len(self.messages) == 2 and self.mutate:
            self.mutate()
        decision = next(self.decisions)
        if isinstance(decision, Exception):
            raise decision
        return decision, {"message": {"content": decision.model_dump_json()}}


def search(keyword="SECRET"):
    return Decision(action="tool", request=ToolRequest(tool_id="search", source_id="s00001",
                                                       params={"keyword": keyword}))


def finish(value="SECRET-旗标-42", field="text"):
    return Decision(action="finish", claims=[Claim(evidence_id="step0001:r00001", field=field, value=value,
                                                   interpretation="工具定位到题目要求的关键词记录")])


def setup_case(evidence, settings):
    settings.model.max_steps = 1
    return Case.create(evidence / "日志.txt", settings, '搜索关键词 "SECRET"')


def test_last_tool_is_reviewed_before_answering(evidence, settings):
    case = setup_case(evidence, settings)
    client = Client([search(), finish()])
    analyze(case, client=client)
    assert len(client.messages) == 2 and len(case.manifest["steps"]) == 1
    observations = json.loads(client.messages[-1][1]["content"])["observations"]
    assert observations[0]["records"][0]["data"]["text"] == "SECRET-旗标-42"
    assert client.allowed_tool_sources == {}
    assert case.manifest["state"] == "completed"
    assert case.manifest["answers"][0]["value"] == "SECRET-旗标-42"
    assert case.manifest["analysis_runs"][-1]["final_review"]["status"] == "validated"
    assert (case.directory / "model-002-final-review.json").is_file()


@pytest.mark.parametrize("response", [search(), ValueError("invalid final JSON")])
def test_final_review_cannot_execute_tools_or_retry_parse_failure(evidence, settings, response):
    case = setup_case(evidence, settings)
    client = Client([search(), response])
    analyze(case, client=client)
    assert len(client.messages) == 2 and len(case.manifest["steps"]) == 1
    assert case.manifest["state"] == "stopped_budget" and not case.manifest["answers"]
    assert case.manifest["analysis_runs"][-1]["final_review"]["status"] in {"failed", "rejected_tool"}


def test_final_claim_repair_uses_existing_one_shot_budget(evidence, settings):
    case = setup_case(evidence, settings)
    client = Client([search(), finish("wrong"), finish()])
    analyze(case, client=client)
    assert len(client.messages) == 3 and len(case.manifest["steps"]) == 1
    assert case.manifest["repair_budgets"]["claim"]
    assert not case.manifest["repair_budgets"]["decision"]
    assert case.manifest["state"] == "completed"
    original = (case.directory / "model-002-final-review.json").read_text(encoding="utf-8")
    assert "wrong" in original
    assert (case.directory / "model-002-claim-repair.json").is_file()


def test_used_claim_budget_is_not_reset_for_final_review(evidence, settings):
    case = setup_case(evidence, settings)
    case.manifest["repair_budgets"] = {"claim": True, "decision": True}
    client = Client([search(), finish("wrong")])
    analyze(case, client=client)
    assert len(client.messages) == 2 and not case.manifest["answers"]
    assert case.manifest["state"] == "insufficient_evidence"


def test_changed_source_during_final_review_rejects_answer(evidence, settings):
    case = setup_case(evidence, settings)
    client = Client([search(), finish()], lambda: (evidence / "日志.txt").write_text("changed", encoding="utf-8"))
    analyze(case, client=client)
    assert case.manifest["state"] == "evidence_changed" and not case.manifest["answers"]
    assert case.manifest["analysis_runs"][-1]["final_review"]["status"] == "evidence_changed"


def test_no_progress_still_allows_read_only_final_review(evidence, settings):
    case = setup_case(evidence, settings)
    settings.model.max_steps = 5
    client = Client([search("missing1"), search("missing2"), Decision(action="finish", uncertainties=["无足够证据"])])
    analyze(case, client=client)
    assert len(client.messages) == 3 and len(case.manifest["steps"]) == 2
    assert case.manifest["state"] == "insufficient_evidence"
    assert case.manifest["analysis_runs"][-1]["final_review"]["reason"] == "stopped_no_progress"


def test_explicit_no_model_never_calls_client(evidence, settings):
    case = setup_case(evidence, settings)
    client = Client([])
    analyze(case, no_model=True, client=client)
    assert not client.messages and "final_review" not in case.manifest["analysis_runs"][-1]


def test_final_generation_grammar_only_accepts_finish():
    schema = decision_schema({})
    assert len(schema["anyOf"]) == 1
    assert schema["anyOf"][0]["properties"]["action"]["const"] == "finish"
    assert schema["anyOf"][0]["properties"]["request"] == {"type": "null"}
