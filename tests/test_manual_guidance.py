import copy
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
