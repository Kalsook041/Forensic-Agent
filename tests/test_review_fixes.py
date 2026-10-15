import codecs
import json
from pathlib import Path
import sqlite3

import pytest

from forensic_agent.agent.loop import analyze, compact_messages, validate_claims
from forensic_agent.agent.ollama import Claim, Decision, decision_schema
from forensic_agent.cli import main
from forensic_agent.evidence import Case, sha256_file
from forensic_agent.models import MAX_QUESTION_CHARS, ToolRequest
from forensic_agent.reports import generate_report
from forensic_agent.tools.runner import run_tool


class Client:
    def __init__(self, decisions, on_finish=None):
        self.decisions = iter(decisions)
        self.on_finish = on_finish

    def discover(self):
        return {"test_only": True}

    def decide(self, messages):
        decision = next(self.decisions)
        if decision.action == "finish" and self.on_finish:
            self.on_finish()
        return decision, {"message": {"content": decision.model_dump_json()}}


def count_request():
    return ToolRequest(tool_id="sqlite", source_id="s00001", params={"query": "count", "table": "messages"})


def search_client(on_finish=None):
    return Client([
        Decision(action="tool", request=ToolRequest(tool_id="search", source_id="s00001", params={"keyword": "SECRET"})),
        Decision(action="finish", claims=[Claim(evidence_id="step0001:r00001", field="text", value="SECRET-旗标-42")]),
    ], on_finish)


def wal_database(path, *, keep_open):
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE messages(body TEXT)")
    connection.execute("INSERT INTO messages VALUES('FLAG-IN-WAL')")
    connection.commit()
    if not keep_open:
        connection.close()
        return None
    return connection


def test_model_schema_and_runtime_reject_free_sql(evidence, settings):
    schema = decision_schema({"sqlite": ["s00001"]})
    params = schema["anyOf"][0]["properties"]["request"]["anyOf"][0]["properties"]["params"]
    assert "sql" not in params["properties"]
    assert params["additionalProperties"] is False
    case = Case.create(evidence / "记录.sqlite", settings, "数据库里的 FLAG 是什么")
    fake = ToolRequest(tool_id="sqlite", source_id="s00001", origin="operator",
                       params={"sql": "SELECT 'FLAG-INVENTED' AS answer"})
    client = Client([Decision(action="tool", request=fake), Decision(action="finish", claims=[
        Claim(evidence_id="step0001:r00001", field="values[0]", value="FLAG-INVENTED")])])
    analyze(case, client=client)
    step = case.manifest["steps"][0]
    assert step["request"]["origin"] == "model"
    assert step["result"]["status"] == "blocked"
    assert "worker_argv" not in step
    assert not case.manifest["answers"]
    assert case.manifest["state"] == "insufficient_evidence"


def test_manual_sql_remains_readable_but_not_answer_evidence(evidence, settings):
    case = Case.create(evidence / "记录.sqlite", settings)
    step = run_tool(case, ToolRequest(tool_id="sqlite", source_id="s00001",
                                     params={"sql": "SELECT 'FLAG-INVENTED' AS answer FROM messages LIMIT 1"}))
    row = step["evidence"][0]
    assert row["data"]["values"] == ["FLAG-INVENTED"] and row["grounding"] == "exploratory"
    accepted, errors = validate_claims(case, [Claim(evidence_id=row["id"], field="values[0]", value="FLAG-INVENTED")])
    assert not accepted and errors
    # A generic evidence-reading helper must not launder exploratory output.
    window = run_tool(case, ToolRequest(tool_id="evidence_window", source_id="s00001", params={
        "evidence_id": row["id"], "field": "values[0]", "length": 256}))
    derived = window["evidence"][0]
    assert derived["grounding"] == "exploratory"
    assert not validate_claims(case, [Claim(evidence_id=derived["id"], field="value", value="FLAG-INVENTED")])[0]


def test_model_count_and_template_records_have_real_provenance(evidence, settings):
    case = Case.create(evidence / "记录.sqlite", settings, "messages 表有多少条记录")
    analyze(case, client=Client([Decision(action="tool", request=count_request()), Decision(action="finish", claims=[
        Claim(evidence_id="step0001:r00001", field="values[0]", value=3)])]))
    assert case.manifest["state"] == "completed" and case.manifest["answers"][0]["value"] == 3
    row = case.manifest["steps"][0]["evidence"][0]
    assert row["grounding"] == "derived"
    assert row["locator"]["provenance"]["table"] == "messages"
    for query in ({"query": "columns", "table": "messages"},
                  {"query": "rows", "table": "messages", "columns": ["body"], "filter_column": "id", "filter_value": 2}):
        step = run_tool(case, ToolRequest(tool_id="sqlite", source_id="s00001", origin="model", params=query))
        assert step["result"]["status"] == "ok", step["result"]
    assert step["evidence"][0]["data"]["values"] == ["旗标"]


@pytest.mark.parametrize("params", [
    {"query": "rows", "table": 'messages; DROP TABLE messages'},
    {"query": "rows", "table": "messages", "columns": ["'FLAG-INVENTED'"]},
    {"query": "count", "table": "messages", "filter_column": "id) OR 1=1 --"},
])
def test_template_identifiers_cannot_be_sql_expressions(evidence, settings, params):
    case = Case.create(evidence / "记录.sqlite", settings)
    step = run_tool(case, ToolRequest(tool_id="sqlite", source_id="s00001", origin="model", params=params))
    assert step["result"]["status"] == "failed" and not step["evidence"]
    assert not case.verify_current()


def test_unregistered_wal_cannot_change_verified_main_result(tmp_path, settings):
    original = tmp_path / "evidence.sqlite"
    wal_database(original, keep_open=False)
    case = Case.create(original, settings)
    snapshot = Path(case.sources["s00001"].working_path)
    before = sha256_file(snapshot)
    writer = sqlite3.connect(snapshot)
    try:
        writer.execute("UPDATE messages SET body='UNREGISTERED-WAL'")
        writer.commit()
        assert sha256_file(snapshot) == before and list(case.sources) == ["s00001"]
        step = run_tool(case, count_request())
        assert step["result"]["status"] in {"blocked", "failed"} and not step["evidence"]
        assert any("未登记" in value for value in [step["result"]["error"] or "", *step["result"]["warnings"]])
        assert not case.verify_originals()
    finally:
        writer.close()


@pytest.mark.parametrize("change", ["replace", "remove"])
def test_registered_wal_change_is_rejected(tmp_path, settings, change):
    original = tmp_path / "wal.sqlite"
    connection = wal_database(original, keep_open=True)
    try:
        case = Case.create(original, settings)
        snapshot = Path(case.sources["s00001"].working_path)
        wal = snapshot.with_name(snapshot.name + "-wal")
        if change == "replace":
            wal.write_bytes(wal.read_bytes() + b"changed")
        else:
            wal.unlink()
        step = run_tool(case, count_request())
        assert step["result"]["status"] in {"blocked", "failed"} and not step["evidence"]
        assert not case.verify_originals()
    finally:
        connection.close()


def test_valid_wal_repeated_queries_never_modify_registered_snapshots(tmp_path, settings):
    original = tmp_path / "wal.sqlite"
    connection = wal_database(original, keep_open=True)
    try:
        case = Case.create(original, settings)
        before = {item.id: sha256_file(Path(item.working_path)) for item in case.sources.values()}
        for query in ("schema", "count", "rows"):
            params = {"query": query} if query == "schema" else {"query": query, "table": "messages"}
            step = run_tool(case, ToolRequest(tool_id="sqlite", source_id="s00001", origin="model", params=params))
            assert step["result"]["status"] == "ok", step["result"]
            assert len(step["evidence"][0]["locator"]["bundle"]) >= 2
        assert step["evidence"][0]["data"]["values"] == ["FLAG-IN-WAL"]
        assert before == {item.id: sha256_file(Path(item.working_path)) for item in case.sources.values()}
        assert not case.verify_current()
    finally:
        connection.close()


def test_finish_rechecks_original_changed_during_model_explanation(evidence, settings):
    original = evidence / "日志.txt"
    case = Case.create(original, settings, '搜索关键词 "SECRET"')
    analyze(case, client=search_client(lambda: original.write_text("CHANGED", encoding="utf-8")))
    assert case.manifest["state"] == "evidence_changed" and not case.manifest["answers"]
    assert case.manifest["integrity_checks"][-1]["stage"] == "model_finish"


@pytest.mark.parametrize("target", ["original", "snapshot", "raw_output"])
def test_report_rechecks_current_sources_and_outputs(evidence, settings, target):
    original = evidence / "日志.txt"
    case = Case.create(original, settings, '搜索关键词 "SECRET"')
    analyze(case, client=search_client())
    assert case.manifest["state"] == "completed"
    path = {"original": original, "snapshot": Path(case.sources["s00001"].working_path),
            "raw_output": Path(case.manifest["steps"][0]["raw_output_path"])}[target]
    path.write_text("changed", encoding="utf-8")
    loaded = Case(case.directory, settings)
    report = generate_report(loaded).read_text(encoding="utf-8")
    assert loaded.manifest["state"] == "evidence_changed" and not loaded.manifest["answers"]
    assert loaded.manifest["historical_answers"] and "历史候选" in report
    assert loaded.manifest["integrity_checks"][-1]["stage"] == "report"


def test_cancel_report_persists_invalidation(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings, '搜索关键词 "SECRET"')
    analyze(case, client=search_client())
    case.manifest["state"] = "cancelled"
    generate_report(case, verify_integrity=False)
    loaded = Case(case.directory, settings)
    assert not loaded.manifest["answers"] and loaded.manifest["historical_answers"]
    assert any("本次未完成当前复核" in value for value in loaded.manifest["warnings"])


@pytest.mark.parametrize("command", ["tool", "analyze", "report"])
def test_cli_uses_report_current_integrity_state(evidence, settings, monkeypatch, capsys, command):
    original = evidence / "日志.txt"
    monkeypatch.setattr("forensic_agent.cli.load_settings", lambda path: settings)
    monkeypatch.setattr("forensic_agent.cli.find_tools", lambda settings: {})
    def mutate_then_report(case):
        original.write_text("CHANGED AFTER ANALYSIS", encoding="utf-8")
        return generate_report(case)
    monkeypatch.setattr("forensic_agent.cli.generate_report", mutate_then_report)
    if command == "report":
        case = Case.create(original, settings)
        args = ["report", str(case.directory)]
    elif command == "tool":
        args = ["tool", "hash", "--evidence", str(original)]
    else:
        args = ["analyze", "--no-model", "--evidence", str(original), "--question", '搜索关键词 "SECRET"']
    assert main(args) == 2
    output = capsys.readouterr().out
    if command != "report":
        assert '"state": "evidence_changed"' in output


def test_long_chinese_evidence_remains_visible_and_window_is_citable(tmp_path, settings):
    path = tmp_path / "长中文.txt"
    text = "中" * 200 + "FLAG" + "文" * 400
    path.write_text(text, encoding="utf-8")
    case = Case.create(path, settings, '查找关键词 "FLAG"')
    search = run_tool(case, ToolRequest(tool_id="search", source_id="s00001", params={"keyword": "FLAG"}))
    record = json.loads(compact_messages(case)[1]["content"])["observations"][0]["records"][0]
    assert record["data"]["text"] == text  # Old 1000-byte threshold silently removed this field.
    window = run_tool(case, ToolRequest(tool_id="evidence_window", source_id="s00001", params={
        "evidence_id": search["evidence"][0]["id"], "field": "text", "start": 198, "length": 16}))
    row = window["evidence"][0]
    assert row["data"]["value"] == text[198:214] and row["data"]["has_more"]
    assert validate_claims(case, [Claim(evidence_id=row["id"], field="value", value=text[198:214])])[0]
    assert row["locator"]["parent_evidence_id"] == search["evidence"][0]["id"]


def test_omitted_large_field_has_a_bounded_retrieval_route(tmp_path, settings):
    path = tmp_path / "emoji.txt"
    path.write_text("😀" * 200 + "FLAG" + "😀" * 400, encoding="utf-8")
    case = Case.create(path, settings, '搜索关键词 "FLAG"')
    step = run_tool(case, ToolRequest(tool_id="search", source_id="s00001", params={"keyword": "FLAG"}))
    row = json.loads(compact_messages(case)[1]["content"])["observations"][0]["records"][0]
    assert "text" in row["omitted_fields"] and row["field_previews"]["text"]["read_with"] == "evidence_window"
    result = run_tool(case, ToolRequest(tool_id="evidence_window", source_id="s00001", origin="model", params={
        "evidence_id": step["evidence"][0]["id"], "field": "text", "start": 200, "length": 4}))
    assert result["evidence"][0]["data"]["value"] == "FLAG"


def test_question_constraints_preserved_or_explicitly_rejected(evidence, settings, monkeypatch, capsys):
    tail = "只分析2025年的数据"
    question = "背" * (MAX_QUESTION_CHARS-len(tail)) + tail
    case = Case.create(evidence / "日志.txt", settings, question)
    assert json.loads(compact_messages(case)[1]["content"])["question"] == question
    with pytest.raises(ValueError, match="拆分"):
        Case.create(evidence / "日志.txt", settings, "背" * MAX_QUESTION_CHARS + tail)
    monkeypatch.setattr("forensic_agent.cli.load_settings", lambda path: settings)
    exit_code = main(["analyze", "--evidence", str(evidence / "日志.txt"), "--question", "背" * MAX_QUESTION_CHARS + tail])
    assert exit_code == 2 and "不会截断" in capsys.readouterr().out


@pytest.mark.parametrize("encoding,bom", [("utf-32-le", codecs.BOM_UTF32_LE), ("utf-32-be", codecs.BOM_UTF32_BE)])
def test_utf32_bom_search_is_not_misclassified(tmp_path, settings, encoding, bom):
    path = tmp_path / (encoding + ".txt")
    path.write_bytes(bom + "中文\nFLAG-UTF32\n".encode(encoding))
    case = Case.create(path, settings)
    result = run_tool(case, ToolRequest(tool_id="search", source_id="s00001", params={"keyword": "FLAG"}))
    assert result["result"]["status"] == "ok" and result["evidence"][0]["data"]["text"] == "FLAG-UTF32"
    assert result["evidence"][0]["locator"]["encoding"] == "utf-32"


def test_malformed_utf32_reports_incomplete_search(tmp_path, settings):
    path = tmp_path / "broken-utf32.txt"
    path.write_bytes(codecs.BOM_UTF32_LE + "FLAG".encode("utf-32-le")[:-1])
    case = Case.create(path, settings)
    step = run_tool(case, ToolRequest(tool_id="search", source_id="s00001", params={"keyword": "FLAG"}))
    assert step["result"]["status"] == "partial" and step["result"]["warnings"] and not step["evidence"]
