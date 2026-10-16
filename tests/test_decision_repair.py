import json

import pytest

from forensic_agent.agent.loop import analyze, request_signature
from forensic_agent.agent.ollama import Claim, Decision
from forensic_agent.evidence import Case
from forensic_agent.models import ToolRequest


class Client:
    def __init__(self, decisions, mutate=None):
        self.decisions = iter(decisions)
        self.calls = 0
        self.mutate = mutate

    def discover(self):
        return {"test_only": True}

    def decide(self, messages):
        self.calls += 1
        if self.calls == 3 and self.mutate:
            self.mutate()
        decision = next(self.decisions)
        if isinstance(decision, Exception):
            raise decision
        return decision, {"message": {"content": decision.model_dump_json()}}


def search(explicit=False):
    params = {"keyword": "SECRET"}
    if explicit:
        params.update(limit=200, encoding="auto", case_sensitive=False)
    return Decision(action="tool", request=ToolRequest(tool_id="search", source_id="s00001", params=params))


def finish():
    return Decision(action="finish", claims=[Claim(evidence_id="step0001:r00001", field="text", value="SECRET-旗标-42")])


def test_defaults_have_one_effective_signature():
    assert request_signature(search().request) == request_signature(search(True).request)
    first = ToolRequest(tool_id="pcap", source_id="s00001")
    second = ToolRequest(tool_id="pcap", source_id="s00001", params={"protocol": "overview", "limit": 200})
    assert request_signature(first) == request_signature(second)
    assert request_signature(first) != request_signature(first.model_copy(update={"source_id": "s00002"}))


def test_duplicate_can_finish_without_executing_again(evidence, settings):
    settings.model.max_steps = 2
    case = Case.create(evidence / "日志.txt", settings, '搜索关键词 "SECRET"')
    client = Client([search(), search(True), finish()])
    analyze(case, client=client)
    assert client.calls == 3 and len(case.manifest["steps"]) == 1
    assert case.manifest["state"] == "completed"
    assert case.manifest["answers"][0]["value"] == "SECRET-旗标-42"
    original = json.loads((case.directory / "model-002-0.json").read_text(encoding="utf-8"))
    assert json.loads(original["response"]["message"]["content"])["request"]["params"]["limit"] == 200
    assert (case.directory / "model-002-decision-repair.json").is_file()


@pytest.mark.parametrize("correction", [search(True), ValueError("bad correction JSON")])
def test_duplicate_correction_is_bounded(evidence, settings, correction):
    case = Case.create(evidence / "日志.txt", settings, "search")
    client = Client([search(), search(True), correction])
    analyze(case, client=client)
    assert client.calls == 3 and len(case.manifest["steps"]) == 1
    assert case.manifest["state"] == "stopped_duplicate"
    assert not case.manifest["answers"]


def test_correction_may_choose_one_new_tool_but_not_retry_forever(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings, "search")
    new_tool = Decision(action="tool", request=ToolRequest(tool_id="hash", source_id="s00001"))
    client = Client([search(), search(True), new_tool, search()])
    analyze(case, client=client)
    assert client.calls == 4 and len(case.manifest["steps"]) == 2
    assert case.manifest["steps"][1]["request"]["tool_id"] == "hash"
    assert case.manifest["state"] == "stopped_duplicate"


@pytest.mark.parametrize("throws", [False, True])
def test_source_change_during_decision_correction_blocks_answers(evidence, settings, throws):
    case = Case.create(evidence / "日志.txt", settings, "search")
    client = Client([search(), search(True), ValueError("bad JSON") if throws else finish()],
                    lambda: (evidence / "日志.txt").write_text("changed", encoding="utf-8"))
    analyze(case, client=client)
    assert client.calls == 3 and len(case.manifest["steps"]) == 1
    assert case.manifest["state"] == "evidence_changed"
    assert not case.manifest["answers"]


def test_bad_claim_after_decision_repair_still_uses_strict_validator(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings, "search")
    bad = Decision(action="finish", claims=[Claim(evidence_id="step0001:r00001", field="text", value="guessed")])
    client = Client([search(), search(True), bad, bad])
    analyze(case, client=client)
    assert client.calls == 4 and len(case.manifest["steps"]) == 1
    assert case.manifest["state"] == "insufficient_evidence"
    assert not case.manifest["answers"]
    assert (case.directory / "model-002-decision-repair.json").exists()
    assert (case.directory / "model-002-claim-repair.json").exists()
