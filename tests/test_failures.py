from pathlib import Path
import subprocess

import pytest

from forensic_agent.evidence import Case, sha256_file
from forensic_agent.models import ToolRequest
from forensic_agent.tools.runner import run_tool


@pytest.mark.parametrize("name,header,tool_id", [
    ("broken.evtx", b"ElfFile\x00", "evtx"),
    ("broken.pcap", b"\xd4\xc3\xb2\xa1", "pcap"),
    ("broken.sqlite", b"SQLite format 3\x00", "sqlite"),
    ("broken.zip", b"PK\x03\x04", "archive"),
])
def test_damaged_files_are_not_success(tmp_path, settings, name, header, tool_id):
    path = tmp_path / name
    path.write_bytes(header)
    original = sha256_file(path)
    case = Case.create(path, settings)
    step = run_tool(case, ToolRequest(tool_id=tool_id, source_id="s00001"))
    assert step["result"]["status"] in {"failed", "blocked"}, step["result"]
    assert not case.verify_originals()
    assert sha256_file(path) == original


def test_actual_7z_listing_and_extract_unsupported(tmp_path, settings):
    item = tmp_path / "flag.txt"
    item.write_text("FLAG-7Z", encoding="utf-8")
    package = tmp_path / "fixture.7z"
    result = subprocess.run([settings.tools.seven_zip, "a", str(package), str(item)], shell=False,
                            capture_output=True, timeout=15)
    assert result.returncode == 0
    case = Case.create(package, settings)
    step = run_tool(case, ToolRequest(tool_id="archive", source_id="s00001"))
    assert step["result"]["status"] == "ok", step["result"]
    assert step["evidence"][0]["data"]["Path"] == "flag.txt"
    unsupported = run_tool(case, ToolRequest(tool_id="archive", source_id="s00001", params={"action": "extract"}))
    assert unsupported["result"]["status"] == "unsupported"


def test_missing_external_tool_isolated(evidence, settings):
    settings.tools.exiftool = str(Path(settings.work_dir) / "missing.exe")
    case = Case.create(evidence / "图片.png", settings)
    failed = run_tool(case, ToolRequest(tool_id="metadata", source_id="s00001"))
    assert failed["result"]["status"] == "blocked"
    worked = run_tool(case, ToolRequest(tool_id="hash", source_id="s00001"))
    assert worked["result"]["status"] == "ok"


def test_keyboard_interrupt_logged(evidence, settings, monkeypatch):
    case = Case.create(evidence / "日志.txt", settings)
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr("forensic_agent.tools.runner.capture", interrupt)
    with pytest.raises(KeyboardInterrupt):
        run_tool(case, ToolRequest(tool_id="hash", source_id="s00001"))
    step = case.manifest["steps"][0]
    assert "取消" in step["result"]["error"]
    assert step["integrity"]["issues"] == []
    assert (case.directory / "operations.jsonl").is_file()


def test_snapshot_mutation_blocked(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings)
    Path(case.sources["s00001"].working_path).write_text("changed", encoding="utf-8")
    step = run_tool(case, ToolRequest(tool_id="hash", source_id="s00001"))
    assert step["result"]["status"] in {"blocked", "failed"}
    assert "内容发生变化" in step["result"]["error"]
    assert not case.verify_originals()


def test_interrupt_during_integrity_check(evidence, settings, monkeypatch):
    case = Case.create(evidence / "日志.txt", settings)
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(case, "verify_originals", interrupt)
    with pytest.raises(KeyboardInterrupt):
        run_tool(case, ToolRequest(tool_id="hash", source_id="s00001"))
    assert case.manifest["state"] == "verification_interrupted"
    assert case.manifest["steps"][0]["result"]["status"] == "failed"


def test_pcap_overview_statistics(tmp_path, settings):
    from forensic_agent.samples import create_pcap
    path = tmp_path / "stats.pcap"
    create_pcap(path)
    case = Case.create(path, settings)
    step = run_tool(case, ToolRequest(tool_id="pcap", source_id="s00001"))
    assert step["result"]["status"] == "ok", step["result"]
    summary = step["evidence"][0]
    assert summary["data"]["packet_count"] == 2
    assert summary["data"]["protocol_counts"] == {"DNS": 1, "HTTP": 1}
