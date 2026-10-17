import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from forensic_agent.cli import main
from forensic_agent.evidence import Case


def source_pair(tmp_path):
    source = tmp_path / "分卷目录"
    source.mkdir()
    (source / "part.001").write_bytes(b"123456")
    (source / "part.002").write_bytes(b"abcdef")
    return source


def copied_files(case_directory):
    return [path for path in (Path(case_directory) / "snapshots").rglob("*") if path.is_file()]


def test_total_limit_rejects_before_copying_any_file(tmp_path, settings):
    source = source_pair(tmp_path)
    settings.limits.snapshot_bytes = 8
    with pytest.raises(ValueError) as error:
        Case.create(source, settings, "查找计算机名")
    assert not copied_files(error.value.case_directory)
    manifest = json.loads((Path(error.value.case_directory) / "case.json").read_text(encoding="utf-8"))
    assert manifest["state"] == "intake_failed" and not manifest["steps"]
    assert "12" in str(error.value) and "8" in str(error.value)
    assert (source / "part.001").read_bytes() == b"123456"


def test_total_space_rejects_before_copying_any_file(tmp_path, settings, monkeypatch):
    source = source_pair(tmp_path)

    def available(_):
        copied = sum(path.stat().st_size for path in settings.work_dir.glob("*/snapshots/root/*") if path.is_file())
        return SimpleNamespace(free=10 - copied)

    monkeypatch.setattr("forensic_agent.evidence.store.shutil.disk_usage", available)
    with pytest.raises(OSError) as error:
        Case.create(source, settings)
    assert not copied_files(error.value.case_directory)


def config_for_limit(tmp_path):
    config = tmp_path / "limited.toml"
    config.write_text(f"work_dir = {json.dumps(str(tmp_path / 'cases'))}\n"
                      "[limits]\nsnapshot_bytes = 8\nreserve_disk_bytes = 0\n", encoding="utf-8")
    return config


def test_cli_intake_failure_has_readable_report_and_original_error(tmp_path, capsys):
    source = source_pair(tmp_path)
    code = main(["--config", str(config_for_limit(tmp_path)), "analyze", "--evidence", str(source),
                 "--question", "查找计算机名", "--no-model"])
    result = json.loads(capsys.readouterr().out)
    assert code == 2 and result["state"] == "intake_failed"
    assert "上限" in result["error"] and result["case"]
    report = Path(result["report"])
    assert report.is_file()
    text = report.read_text(encoding="utf-8")
    assert "intake" in text and "上限" in text
    assert not copied_files(report.parent)


def test_failure_report_error_keeps_original_intake_error(tmp_path, capsys, monkeypatch):
    def report_fails(_):
        raise OSError("report write refused")

    monkeypatch.setattr("forensic_agent.cli.generate_report", report_fails)
    code = main(["--config", str(config_for_limit(tmp_path)), "analyze", "--evidence", str(source_pair(tmp_path)),
                 "--question", "查找计算机名", "--no-model"])
    result = json.loads(capsys.readouterr().out)
    assert code == 2 and "上限" in result["error"]
    assert "report write refused" in result["report_error"] and result["case"]
