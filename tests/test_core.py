import json
from pathlib import Path

from forensic_agent.evidence import Case, sha256_file
from forensic_agent.models import ToolRequest
from forensic_agent.reports import generate_report
from forensic_agent.tools.runner import run_tool


def test_search_real_worker_and_report(evidence, settings):
    original = {str(path): sha256_file(path) for path in evidence.iterdir()}
    case = Case.create(evidence, settings, '查找关键词 "SECRET"')
    step = run_tool(case, ToolRequest(tool_id="search", source_id="s00001", params={"keyword": "SECRET"}))
    assert step["result"]["status"] == "partial", step["result"]
    assert any("非文本格式" in warning for warning in step["result"]["warnings"])
    assert len(step["evidence"]) == 2
    assert {row["locator"]["line"] for row in step["evidence"]} == {2}
    assert all(row["raw_output_path"] for row in step["evidence"])
    report = generate_report(case)
    assert "SECRET" in report.read_text(encoding="utf-8")
    assert original == {str(path): sha256_file(path) for path in evidence.iterdir()}
    assert not case.verify_originals()


def test_text_only_search_complete(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings)
    step = run_tool(case, ToolRequest(tool_id="search", source_id="s00001", params={"keyword": "SECRET"}))
    assert step["result"]["status"] == "ok"
    assert step["evidence"][0]["locator"]["line"] == 2


def test_gb18030_chinese_keyword(evidence, settings):
    case = Case.create(evidence / "GB18030.txt", settings)
    step = run_tool(case, ToolRequest(tool_id="search", source_id="s00001", params={"keyword": "关键词"}))
    assert step["result"]["status"] == "ok", step["result"]
    assert step["evidence"][0]["data"]["text"] == "关键词测试"
    assert step["evidence"][0]["locator"]["encoding"] == "gb18030"
    assert "推断" in step["evidence"][0]["data"]["encoding_basis"]


def test_sqlite_count_and_writes_denied(evidence, settings):
    path = evidence / "记录.sqlite"
    before = sha256_file(path)
    case = Case.create(path, settings)
    result = run_tool(case, ToolRequest(tool_id="sqlite", source_id="s00001",
                                      params={"sql": "SELECT COUNT(*) AS n FROM messages"}))
    assert result["result"]["status"] == "ok", result["result"]
    assert result["evidence"][0]["data"] == {"columns": ["n"], "values": [3]}
    for sql in ("DELETE FROM messages", "ATTACH DATABASE 'bad.db' AS bad", "SELECT load_extension('bad')",
                "PRAGMA writable_schema=ON", "SELECT 1; DROP TABLE messages"):
        rejected = run_tool(case, ToolRequest(tool_id="sqlite", source_id="s00001", params={"sql": sql}))
        assert rejected["result"]["status"] == "failed", rejected["result"]
    assert before == sha256_file(path)
    assert not (case.directory / "bad.db").exists()


def test_metadata_real_exiftool(evidence, settings):
    case = Case.create(evidence / "图片.png", settings)
    step = run_tool(case, ToolRequest(tool_id="metadata", source_id="s00001", params={"fields": ["Author"]}))
    assert step["result"]["status"] == "ok", step["result"]
    assert step["evidence"][0]["data"]["value"] == "Forensic Fixture"
    commands = (case.directory / "steps/step0001/commands.jsonl").read_text(encoding="utf-8")
    assert "exiftool.exe" in commands
    assert "snapshots" in commands
    assert not case.verify_originals()


def test_whitelist_and_parameter_paths_rejected(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings)
    for request in (ToolRequest(tool_id="powershell", source_id="s00001"),
                    ToolRequest(tool_id="hash", source_id="s00001", params={"command": "calc.exe"}),
                    ToolRequest(tool_id="hash", source_id="../../")):
        step = run_tool(case, request)
        assert step["result"]["status"] == "blocked"
        assert not step.get("worker_argv")
    assert not case.verify_originals()


def test_original_changes_detected(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings)
    (evidence / "日志.txt").write_text("外部修改", encoding="utf-8")
    step = run_tool(case, ToolRequest(tool_id="hash", source_id="s00001"))
    assert step["result"]["status"] == "failed"
    assert case.manifest["state"] == "evidence_changed"


def test_serialized_manifest_load(evidence, settings):
    case = Case.create(evidence, settings)
    loaded = Case(case.directory, settings)
    assert loaded.sources == case.sources
    assert json.loads((case.directory / "case.json").read_text(encoding="utf-8"))["schema_version"] == 1
    assert all(Path(x.working_path).is_absolute() for x in loaded.sources.values())
