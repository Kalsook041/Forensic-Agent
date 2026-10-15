import json

import pytest

from forensic_agent.agent.loop import analyze
from forensic_agent.agent.ollama import Claim, Decision
from forensic_agent.evidence import Case
from forensic_agent.models import ToolRequest
from forensic_agent.tools.runner import run_tool


class FinishClient:
    def __init__(self, decisions, mutate=None):
        self.decisions = iter(decisions)
        self.calls = 0
        self.mutate = mutate

    def discover(self):
        return {"test_only": True}

    def decide(self, messages):
        self.calls += 1
        if self.calls == 2 and self.mutate:
            self.mutate()
        decision = next(self.decisions)
        if isinstance(decision, Exception):
            raise decision
        return decision, {"message": {"content": decision.model_dump_json()}}


def finish(field="n", value=3):
    return Decision(action="finish", claims=[Claim(evidence_id="step0001:r00001", field=field, value=value)])


def count_case(evidence, settings):
    case = Case.create(evidence / "记录.sqlite", settings, "messages 表有多少条记录")
    run_tool(case, ToolRequest(tool_id="sqlite", source_id="s00001", params={"query": "count", "table": "messages"}))
    return case


def test_missing_sql_field_corrected_once_and_audited(evidence, settings):
    case = count_case(evidence, settings)
    client = FinishClient([finish(), finish("values[0]")])
    analyze(case, client=client)
    assert client.calls == 2 and len(case.manifest["steps"]) == 1
    assert case.manifest["state"] == "completed"
    assert case.manifest["answers"][0]["value"] == 3
    assert any("不存在的字段" in warning for warning in case.manifest["warnings"])
    original = json.loads((case.directory / "model-002-0.json").read_text(encoding="utf-8"))
    assert '"field":"n"' in original["response"]["message"]["content"]
    assert (case.directory / "model-002-claim-repair.json").exists()


@pytest.mark.parametrize("second", [finish(), finish("values[0]", 4),
    Decision(action="tool", request=ToolRequest(tool_id="hash", source_id="s00001")), ValueError("invalid JSON")])
def test_second_bad_finish_stops_without_extra_tools(evidence, settings, second):
    case = count_case(evidence, settings)
    client = FinishClient([finish(), second])
    analyze(case, client=client)
    assert client.calls == 2 and len(case.manifest["steps"]) == 1
    assert case.manifest["state"] == "insufficient_evidence"
    assert not case.manifest["answers"]


def test_exploratory_result_stays_rejected(evidence, settings):
    case = count_case(evidence, settings)
    case.manifest["steps"][0]["evidence"][0]["grounding"] = "exploratory"
    client = FinishClient([finish("values[0]"), finish("values[0]")])
    analyze(case, client=client)
    assert client.calls == 2
    assert not case.manifest["answers"]
    assert case.manifest["state"] == "insufficient_evidence"


@pytest.mark.parametrize("during_repair", [False, True])
def test_changed_source_never_accepted(evidence, settings, during_repair):
    case = count_case(evidence, settings)
    def mutate():
        with (evidence / "记录.sqlite").open("ab") as stream:
            stream.write(b"changed")
    if not during_repair:
        mutate()
    client = FinishClient([finish(), finish("values[0]")], mutate if during_repair else None)
    analyze(case, client=client)
    assert case.manifest["state"] == "evidence_changed"
    assert not case.manifest["answers"]
    assert client.calls == (2 if during_repair else 1)
