from forensic_agent.evidence import Case
from forensic_agent.models import ToolRequest
from forensic_agent.tools.runner import run_tool


def test_case_phase_records_copy_verify_and_tool_boundaries(evidence, settings):
    events = []
    case = Case.create(evidence / "日志.txt", settings, '搜索关键词 "SECRET"', progress=events.append)

    intake = {item["stage"]: item for item in case.manifest["phases"]}
    assert intake["copy_snapshot"]["status"] == "finished"
    assert intake["copy_snapshot"]["copy_bytes"] == (evidence / "日志.txt").stat().st_size
    assert intake["copy_snapshot"]["hash_passes"] >= 2
    assert intake["verify_originals"]["hash_passes"] >= 1

    step = run_tool(case, ToolRequest(tool_id="search", source_id="s00001", params={"keyword": "SECRET"}))

    stages = {item["stage"]: item for item in case.manifest["phases"]}
    assert step["result"]["status"] == "ok"
    assert all(stages[name]["status"] == "finished" for name in
               ("tool_verify_before", "tool_execute", "tool_verify_after", "hash_output"))
    assert stages["tool_execute"]["elapsed_seconds"] >= 0
    assert any(event["event"] == "start" and event["stage"] == "copy_snapshot" for event in events)
    assert any(event["event"] == "end" and event["stage"] == "hash_output" for event in events)


def test_progress_callback_failure_does_not_change_forensic_operation(evidence, settings):
    def broken_callback(_):
        raise RuntimeError("display unavailable")

    case = Case.create(evidence / "日志.txt", settings, progress=broken_callback)
    result = run_tool(case, ToolRequest(tool_id="hash", source_id="s00001"))

    assert result["result"]["status"] == "ok"
    assert case.manifest["steps"][0]["integrity"]["issues"] == []
