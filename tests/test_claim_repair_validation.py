import importlib.util
from pathlib import Path

import pytest

from forensic_agent.agent.loop import validate_claims
from forensic_agent.agent.ollama import Claim
from forensic_agent.evidence import Case
from forensic_agent.models import ToolRequest
from forensic_agent.tools.runner import run_tool


spec = importlib.util.spec_from_file_location("verify_claim_repair", Path(__file__).resolve().parents[1]
                                             / "scripts/verify-claim-repair.py")
validation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validation)


@pytest.fixture
def completed_count(evidence, settings):
    case = Case.create(evidence / "记录.sqlite", settings, "messages count")
    run_tool(case, ToolRequest(tool_id="sqlite", source_id="s00001", params={"query": "count", "table": "messages"}))
    case.manifest["answers"], errors = validate_claims(case,
        [Claim(evidence_id="step0001:r00001", field="values[0]", value=3)])
    assert not errors
    case.manifest["state"] = "completed"
    return case


def test_live_check_accepts_verified_final_result(completed_count):
    result = validation.case_result(completed_count, "count", 3, "sqlite")
    assert result["passed"] and result["answers"] == [3]
    assert not result["integrity_issues"]


@pytest.mark.parametrize("changed", ["original", "working", "raw"])
def test_live_check_rejects_changes_before_report(completed_count, changed):
    case = completed_count
    source = case.sources["s00001"]
    target = {"original": source.original_path, "working": source.working_path,
              "raw": case.manifest["steps"][0]["raw_output_path"]}[changed]
    with Path(target).open("ab") as stream:
        stream.write(b"changed validation evidence")
    result = validation.case_result(case, "count", 3, "sqlite")
    assert not result["passed"] and result["state"] == "evidence_changed"
    assert not result["answers"] and result["integrity_issues"]


def test_live_check_rejects_answer_invalidated_by_report(completed_count):
    completed_count.manifest["answers"][0]["value"] = 4
    result = validation.case_result(completed_count, "count", 4, "sqlite")
    assert not result["passed"] and result["state"] == "insufficient_evidence"
    assert not result["answers"]


def test_live_check_requires_expected_tool(completed_count):
    assert not validation.case_result(completed_count, "keyword", 3, "search")["passed"]
