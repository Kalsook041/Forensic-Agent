import copy
import errno
import json
from pathlib import Path

import pytest

from forensic_agent.evidence import Case
from forensic_agent.manual import build_manual_guidance
from forensic_agent.models import ToolRequest
from forensic_agent.reports import generate_report
from forensic_agent.tools.runner import run_tool


def workflow_ids(guide):
    return [x["id"] for x in guide["workflows"]]


def test_pre_copy_failure_keeps_input_and_targeted_guide(tmp_path, settings):
    source = tmp_path / "分卷目录"
    source.mkdir()
    (source / "part.001").write_bytes(b"123456")
    (source / "part.002").write_bytes(b"abcdef")
    settings.limits.snapshot_bytes = 8
    with pytest.raises(ValueError) as error:
        Case.create(source, settings, "DEMO 镜像的计算机名")
    case = Case(Path(error.value.case_directory), settings)
    report = generate_report(case)
    guide = json.loads((case.directory / "report.json").read_text(encoding="utf-8"))["manual_guidance"]
    assert guide["input_path"] == str(source.resolve())
    assert guide["snapshot_plan"] == {"files": 2, "bytes": 12}
    assert workflow_ids(guide) == ["storage", "archive", "windows"]
    assert guide["needed"] and not case.manifest["answers"]
    assert "人工操作指南" in report.read_text(encoding="utf-8")
    assert "ControlSet001" in (case.directory / "manual-guide.md").read_text(encoding="utf-8")
    assert not [p for p in (case.directory / "snapshots").rglob("*") if p.is_file()]


def test_guide_is_advisory_and_does_not_mutate_or_read_evidence(tmp_path, settings, monkeypatch):
    source = tmp_path / "memory.dmp"
    source.write_bytes(b"not a real memory image")
    case = Case.create(source, settings, "分析内存进程")
    case.manifest.update(state="model_unavailable", planning_repair_used=True, claim_repair_used=True)
    before = copy.deepcopy(case.manifest)
    original_open = Path.open

    def guarded_open(path, *args, **kwargs):
        if path == source or path == Path(case.sources["s00001"].working_path):
            raise AssertionError("Viewing guidance must not read or hash evidence")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("Guide must not execute a process"))
    guide = build_manual_guidance(case, inventory={})
    assert workflow_ids(guide) == ["memory", "planning"]
    assert case.manifest == before and not case.manifest["steps"]
    assert "未固定内存" in guide["text"]


def test_partial_real_worker_gets_guide_without_changing_result(evidence, settings):
    case = Case.create(evidence, settings, "搜索 SECRET")
    step = run_tool(case, ToolRequest(tool_id="search", source_id="s00001", params={"keyword": "SECRET"}))
    assert step["result"]["status"] == "partial"
    case.manifest["state"] = "completed_without_model"
    first = copy.deepcopy(step)
    generate_report(case)
    guide = json.loads((case.directory / "report.json").read_text(encoding="utf-8"))["manual_guidance"]
    assert guide["needed"] and "partial" in guide["text"]
    assert step == first and len(case.manifest["steps"]) == 1
    assert case.manifest["state"] == "completed_without_model"


def test_integrity_failure_takes_priority_over_domain_steps(tmp_path, settings):
    source = tmp_path / "SYSTEM"
    source.write_bytes(b"original")
    case = Case.create(source, settings, "计算机名和内存进程")
    source.write_bytes(b"changed")
    generate_report(case)
    guide = build_manual_guidance(case, inventory={})
    assert case.manifest["state"] == "evidence_changed"
    assert workflow_ids(guide) == ["integrity"]
    assert "不要改写案件 JSON" in guide["text"]
    assert not case.manifest["answers"]


def test_old_case_without_new_fields_uses_registered_source(tmp_path, settings):
    source = tmp_path / "example.pcap"
    source.write_bytes(b"fixture")
    case = Case.create(source, settings)
    case.manifest.pop("input_path")
    case.manifest.pop("snapshot_plan")
    case.manifest["state"] = "stopped_budget"
    guide = build_manual_guidance(case, inventory={})
    assert guide["input_path"] == str(source.resolve())
    assert workflow_ids(guide) == ["pcap", "planning"]
    assert "Limit to display filter" in guide["text"] and "完整 0" in guide["text"]


def test_missing_tool_does_not_claim_installed_or_supported(tmp_path, settings):
    source = tmp_path / "SYSTEM"
    source.write_bytes(b"fixture")
    case = Case.create(source, settings, "计算机名")
    guide = build_manual_guidance(case, inventory={"ftk_imager": {"executable": str(tmp_path / "missing.exe")}})
    tool = next(x for w in guide["workflows"] for x in w["tools"] if x["id"] == "ftk_imager")
    assert not tool["entry_found"] and tool["path"] is None
    assert "未检测到配置入口" in tool["status"]
    assert "高熵不能单独证明" in guide["text"]


def test_auxiliary_guide_write_failure_preserves_main_diagnostic(tmp_path, settings, monkeypatch):
    source = tmp_path / "note.txt"
    source.write_text("fixture", encoding="utf-8")
    case = Case.create(source, settings)
    case.manifest["state"] = "model_unavailable"
    case.manifest["warnings"] = ["first model error"]
    original = Path.write_text

    def fail_guide(path, *args, **kwargs):
        if path.name == "manual-guide.md":
            raise OSError("guide file locked")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_guide)
    report = generate_report(case)
    data = json.loads((case.directory / "report.json").read_text(encoding="utf-8"))
    assert "first model error" in report.read_text(encoding="utf-8")
    assert "人工操作指南" in report.read_text(encoding="utf-8")
    assert "guide file locked" in data["manual_guidance"]["file_error"]
    assert case.manifest["state"] == "model_unavailable"
    assert case.manifest["warnings"] == ["first model error"]


def test_names_are_quoted_and_not_interpolated_into_commands(tmp_path, settings):
    source = tmp_path / "note.txt"
    source.write_text("fixture", encoding="utf-8")
    case = Case.create(source, settings, "计算机名")
    case.manifest["input_path"] = 'bad\n# injected\n```\n<script>execute()</script>'
    guide = build_manual_guidance(case, inventory={})
    assert '\n# injected\n' not in guide["text"]
    assert "\\u0060" in guide["text"]
    assert all("execute()" not in c for w in guide["workflows"] for c in w.get("commands", []))


def test_success_guide_does_not_present_a_failure(tmp_path, settings):
    source = tmp_path / "note.txt"
    source.write_text("fixture", encoding="utf-8")
    case = Case.create(source, settings)
    case.manifest["state"] = "tool_completed"
    guide = build_manual_guidance(case, inventory={})
    assert not guide["needed"] and not guide["workflows"]
    assert "未重新核验" in guide["text"]


def test_general_guide_and_invalid_legacy_budget_do_not_crash(tmp_path, settings):
    general = build_manual_guidance(settings=settings, inventory={})
    assert general["needed"] and {"storage", "archive", "windows", "pcap", "memory", "mobile", "recovery"} <= set(
        workflow_ids(general))
    source = tmp_path / "note.txt"
    source.write_text("fixture", encoding="utf-8")
    case = Case.create(source, settings)
    case.manifest["settings"]["limits"]["snapshot_bytes"] = "invalid legacy metadata"
    assert build_manual_guidance(case, inventory={})["snapshot_bytes"] is None


@pytest.mark.parametrize("name", ["evidence.001", "evidence.002", "evidence.7z.001"])
def test_numeric_first_volume_gets_container_instructions(tmp_path, settings, name):
    source = tmp_path / name
    source.write_bytes(b"fixture")
    case = Case.create(source, settings, "分析检材")
    case.manifest["state"] = "model_unavailable"
    guide = build_manual_guidance(case, inventory={})
    assert "archive" in workflow_ids(guide)
    assert "格式仍未知" in guide["text"] and "后续卷不分别解压" in guide["text"]
    assert "不能仅凭后缀认定压缩包" in guide["text"]


@pytest.mark.parametrize("general", [True, False])
def test_root_only_tool_path_does_not_break_guide(tmp_path, settings, general):
    settings.tools.tshark = tmp_path.anchor
    source = tmp_path / "capture.pcap"
    source.write_bytes(b"fixture")
    case = None if general else Case.create(source, settings, "统计 IP")
    guide = build_manual_guidance(case, settings=settings, inventory={})
    tool = next(t for w in guide["workflows"] for t in w["tools"] if t["id"] == "wireshark")
    assert guide["needed"] and not tool["entry_found"] and tool["path"] is None
    assert "Wireshark" in guide["text"]


def test_growth_before_first_source_registration_prioritizes_integrity(tmp_path, settings, monkeypatch):
    source = tmp_path / "capture.pcap"
    source.write_bytes(b"x")
    original_open, reads = Path.open, 0

    def growing_open(path, mode="r", *args, **kwargs):
        nonlocal reads
        if path == source and mode == "rb":
            reads += 1
            if reads == 2:
                with original_open(source, "ab") as stream:
                    stream.write(b"GROW")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", growing_open)
    with pytest.raises(OSError, match="源文件增长") as error:
        Case.create(source, settings, "统计流量 IP")
    case = Case(Path(error.value.case_directory), settings)
    first_warnings = list(case.manifest["warnings"])
    assert source.stat().st_size == 5 and not case.sources
    assert case.manifest["snapshot_plan"]["available_bytes"] > 5
    generate_report(case)
    guide = json.loads((case.directory / "report.json").read_text(encoding="utf-8"))["manual_guidance"]
    assert workflow_ids(guide) == ["integrity"]
    assert case.manifest["state"] == "intake_failed" and not case.manifest["answers"]
    assert case.manifest["warnings"] == first_warnings


def test_actual_space_failure_keeps_storage_workflow(tmp_path, settings, monkeypatch):
    from types import SimpleNamespace

    source = tmp_path / "note.txt"
    source.write_bytes(b"fixture")
    monkeypatch.setattr("forensic_agent.evidence.store.shutil.disk_usage", lambda _: SimpleNamespace(free=0))
    with pytest.raises(OSError, match="工作磁盘空间不足") as error:
        Case.create(source, settings)
    case = Case(Path(error.value.case_directory), settings)
    assert workflow_ids(build_manual_guidance(case, inventory={})) == ["storage"]


def test_pure_text_partial_has_manual_search_without_widening_limits(tmp_path, settings, monkeypatch):
    source = tmp_path / "large.txt"
    source.write_bytes(b"needle\n")
    settings.limits.text_file_bytes = 1
    before_limits = settings.limits.model_dump()
    case = Case.create(source, settings, "搜索 needle")
    step = run_tool(case, ToolRequest(tool_id="search", source_id="s00001", params={"keyword": "needle"}))
    assert step["result"]["status"] == "partial"
    case.manifest["state"] = "tool_completed"
    first = copy.deepcopy(step)
    generate_report(case)
    guide = json.loads((case.directory / "report.json").read_text(encoding="utf-8"))["manual_guidance"]
    assert workflow_ids(guide) == ["search"]
    assert guide["workflows"][0]["tools"][0]["id"] == "powershell_search"
    assert "Select-String" in guide["text"] and "Export-Csv" in guide["text"]
    assert "LineNumber" in guide["text"] and "partial" in guide["text"]
    assert settings.limits.model_dump() == before_limits and step == first
    before = copy.deepcopy(case.manifest)
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("Guide cannot execute its command"))
    build_manual_guidance(case, inventory={})
    assert case.manifest == before and case.manifest["state"] == "tool_completed"
    assert not case.manifest["answers"]


def test_optional_guide_cannot_consume_space_needed_by_primary_reports(tmp_path, settings, monkeypatch):
    from forensic_agent.reports import writer

    source = tmp_path / "note.txt"
    source.write_bytes(b"fixture")
    case = Case.create(source, settings)
    case.manifest.update(state="model_unavailable", warnings=["first model error"])
    # Keep report content stable while modelling only the available bytes for report files.
    monkeypatch.setattr(case, "record_integrity", lambda _: None)
    generate_report(case)
    primary_size = sum((case.directory / name).stat().st_size for name in ["report.md", "report.json"])
    allocated, order = {}, []
    original_text, original_json = Path.write_text, writer.write_json

    def reserve(name, data):
        proposed = sum(allocated.values()) - allocated.get(name, 0) + len(data)
        order.append(name)
        if proposed > primary_size:
            raise OSError(errno.ENOSPC, "simulated report quota")
        allocated[name] = len(data)

    def limited_text(path, text, *args, **kwargs):
        if path.parent == case.directory and path.name in {"report.md", "manual-guide.md"}:
            reserve(path.name, text.encode("utf-8"))
        return original_text(path, text, *args, **kwargs)

    def limited_json(path, value):
        if path == case.directory / "report.json":
            reserve(path.name, json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8"))
        return original_json(path, value)

    monkeypatch.setattr(Path, "write_text", limited_text)
    monkeypatch.setattr(writer, "write_json", limited_json)
    report = generate_report(case)
    data = json.loads((case.directory / "report.json").read_text(encoding="utf-8"))
    assert report.is_file() and data["case"]["state"] == "model_unavailable"
    assert data["case"]["warnings"] == ["first model error"]
    assert {"report.md", "report.json"} <= allocated.keys()
    assert order.index("report.json") < order.index("manual-guide.md")


def test_failed_auxiliary_error_update_cannot_fail_primary_report(tmp_path, settings, monkeypatch):
    from forensic_agent.reports import writer

    source = tmp_path / "note.txt"
    source.write_bytes(b"fixture")
    case = Case.create(source, settings)
    case.manifest.update(state="model_unavailable", warnings=["first model error"])
    original_text, original_json = Path.write_text, writer.write_json

    def fail_guide(path, *args, **kwargs):
        if path.name == "manual-guide.md":
            raise OSError("guide locked")
        return original_text(path, *args, **kwargs)

    def fail_metadata_update(path, value):
        if value.get("manual_guidance", {}).get("file_error"):
            raise OSError("metadata update unavailable")
        return original_json(path, value)

    monkeypatch.setattr(Path, "write_text", fail_guide)
    monkeypatch.setattr(writer, "write_json", fail_metadata_update)
    report = generate_report(case)
    data = json.loads((case.directory / "report.json").read_text(encoding="utf-8"))
    assert report.is_file() and "first model error" in report.read_text(encoding="utf-8")
    assert data["case"]["state"] == "model_unavailable"
    assert data["case"]["warnings"] == ["first model error"]
