"""Exercise the actual acceptance entry point without a model or native process."""
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest


@pytest.fixture
def verifier(monkeypatch, tmp_path):
    path = Path(__file__).resolve().parents[1] / "scripts/verify-pcap-workflow.py"
    spec = importlib.util.spec_from_file_location("pcap_verifier", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "__file__", str(tmp_path / "scripts/verify.py"))
    sample = tmp_path / "sample.pcap"
    sample.write_bytes(b"unchanged")
    monkeypatch.setattr(sys, "argv", ["verify", "--sample", str(sample)])
    settings = SimpleNamespace(tools=SimpleNamespace(tshark="unused"), limits=SimpleNamespace(output_bytes=10000))
    monkeypatch.setattr(module, "load_settings", lambda path: settings)
    raw = (b"frame.number\tip.src\tip.dst\tipv6.src\tipv6.dst\ttcp.stream\n"
           b"1\t192.0.2.1\t192.0.2.2\t\t\t0\n2\t192.0.2.2\t192.0.2.1\t\t\t0\n")
    monkeypatch.setattr(module, "capture", lambda *a, **kw: SimpleNamespace(returncode=0, stopped=False, stdout=raw))
    data = {"packet_count": 2, "ip_addresses": ["192.0.2.1", "192.0.2.2"], "tcp_session_count": 1,
            "ip_statistics_complete": True, "ip_addresses_complete": True, "tcp_statistics_complete": True,
            "statistics_complete": True,
            "scope": {"kind": "capture", "protocol": "overview", "ip_address": "", "tcp_stream": None}}
    step = {"request": {"tool_id": "pcap", "source_id": "s00001", "params": {"protocol": "overview"}},
            "result": {"status": "partial", "truncated": True}, "integrity": {"issues": []},
            "evidence": [{"id": "step0001:r00001", "source_id": "s00001", "grounding": "derived",
                          "locator": {"kind": "pcap_summary"}, "data": data}]}
    monkeypatch.setattr(module, "run_tool", lambda *a, **kw: copy.deepcopy(step))
    cases = []

    def create(*args):
        case = SimpleNamespace(directory=tmp_path / f"case{len(cases)}", verify_current=lambda: [],
                               manifest={"root_id": "s00001", "state": "completed", "answers": [],
                                         "warnings": [], "steps": [copy.deepcopy(step)]})
        cases.append(case)
        return case

    monkeypatch.setattr(module, "Case", SimpleNamespace(create=create))
    monkeypatch.setattr(module, "generate_report", lambda case: case.directory / "report.md")
    return module, cases


@pytest.mark.parametrize("mutation,expected", [
    ("baseline", True), ("array_positions", True), ("address_order", True), ("filtered", False), ("hidden_filter", False),
    ("ip_incomplete", False), ("list_incomplete", False), ("tcp_incomplete", False),
    ("wrong_source", False), ("wrong_request_source", False), ("wrong_kind", False),
    ("mismatch", False), ("arbitrary_field", False), ("boolean_count", False),
    ("report_voided", False), ("integrity_changed", False),
])
def test_acceptance_requires_full_capture_evidence(verifier, monkeypatch, mutation, expected):
    module, cases = verifier
    calls = []

    def analyze(case, **kwargs):
        calls.append(case)
        step = case.manifest["steps"][0]
        row = step["evidence"][0]
        data = row["data"]
        q1 = len(calls) == 1
        field = "ip_addresses" if q1 else "tcp_session_count"
        case.manifest["answers"] = [{"evidence_id": row["id"], "field": field, "value": copy.deepcopy(data[field])}]
        if mutation == "array_positions" and q1:
            case.manifest["answers"] = [{"evidence_id": row["id"], "field": f"ip_addresses[{i}]", "value": value}
                                        for i, value in enumerate(data["ip_addresses"])]
        if mutation == "address_order" and q1:
            data["ip_addresses"].reverse()
            case.manifest["answers"][0]["value"] = copy.deepcopy(data["ip_addresses"])
        if mutation == "filtered":
            data["scope"].update(kind="filtered", tcp_stream=0)
            step["request"]["params"]["tcp_stream"] = 0
        if mutation == "hidden_filter":
            step["request"]["params"]["ip_address"] = "192.0.2.1"
        if mutation in {"ip_incomplete", "list_incomplete", "tcp_incomplete"}:
            key = {"ip_incomplete": "ip_statistics_complete", "list_incomplete": "ip_addresses_complete",
                   "tcp_incomplete": "tcp_statistics_complete"}[mutation]
            data[key] = False
        if mutation == "wrong_source":
            row["source_id"] = "s00002"
        if mutation == "wrong_request_source":
            step["request"]["source_id"] = "s00002"
        if mutation == "wrong_kind":
            row["locator"]["kind"] = "pcap"
        if mutation == "mismatch":
            data[field] = [] if q1 else 9
        if mutation == "arbitrary_field" and q1:
            data["comment"] = data[field]
            case.manifest["answers"][0]["field"] = "comment"
        if mutation == "boolean_count" and not q1:
            data[field] = True
            case.manifest["answers"][0]["value"] = True
        if mutation == "integrity_changed":
            case.verify_current = lambda: ["changed"]

    monkeypatch.setattr(module, "analyze", analyze)
    if mutation == "report_voided":
        def report(case):
            case.manifest.update(state="evidence_changed", answers=[])
            return case.directory / "report.md"
        monkeypatch.setattr(module, "generate_report", report)
    assert module.main() == (0 if expected else 2)
    assert len(calls) == 2  # One analyze per question, including unsuccessful acceptance.
    assert len(cases) == 3


def test_unknown_question_is_not_scored_as_q3(verifier):
    module, _ = verifier
    assert not module.answers_pass(SimpleNamespace(), "unknown", {})


@pytest.mark.parametrize("has_ip_claim", [True, False])
def test_empty_complete_ip_list_requires_an_ip_claim(verifier, has_ip_claim):
    module, _ = verifier
    case = module.Case.create()
    row = case.manifest["steps"][0]["evidence"][0]
    row["data"]["ip_addresses"] = []
    row["data"]["ip_address_count"] = 0
    field = "ip_addresses" if has_ip_claim else "ip_address_count"
    case.manifest["answers"] = [{"evidence_id": row["id"], "field": field, "value": row["data"][field]}]
    reference = {"ip_addresses": [], "tcp_session_count": 0}
    assert module.answers_pass(case, "honeynet-q1", reference) is has_ip_claim
