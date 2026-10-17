from pathlib import Path

import pytest

from forensic_agent.agent.loop import analyze, prepare_continuation
from forensic_agent.agent.ollama import Decision
from forensic_agent.evidence import Case, sha256_file
from forensic_agent.evidence.store import CaseBusyError
from forensic_agent.models import ToolRequest
from forensic_agent.tools.runner import run_tool


class Client:
    def __init__(self, decisions):
        self.decisions = iter(decisions)
        self.calls = 0

    def discover(self):
        return {"test_only": True}

    def decide(self, messages):
        self.calls += 1
        decision = next(self.decisions)
        return decision, {"message": {"content": decision.model_dump_json()}}


def search_request():
    return ToolRequest(tool_id="search", source_id="s00001", params={"keyword": "SECRET"})


def test_continuation_reuses_snapshot_and_preserves_previous_answers(evidence, settings):
    original = evidence / "日志.txt"
    case = Case.create(original, settings, '搜索关键词 "SECRET"')
    snapshot = Path(case.sources["s00001"].working_path)
    snapshot_digest = sha256_file(snapshot)
    case.manifest["answers"] = [{"evidence_id": "old", "field": "text", "value": "old",
                                  "interpretation": "old", "classification": "candidate"}]
    case.manifest["state"] = "completed"
    case.save()
    (case.directory / "report.md").write_text("previous report", encoding="utf-8")

    loaded = Case(case.directory, settings)
    assert prepare_continuation(loaded)

    assert loaded.manifest["state"] == "ready"
    assert Path(loaded.sources["s00001"].working_path) == snapshot
    assert sha256_file(snapshot) == snapshot_digest
    assert not loaded.manifest["answers"]
    assert loaded.manifest["historical_answers"][0]["answers"][0]["value"] == "old"
    assert loaded.manifest["continuations"][-1]["mode"] == "reuse_snapshot"
    assert loaded.manifest["integrity_checks"][-1]["stage"] == "resume"
    history = loaded.directory / loaded.manifest["continuations"][-1]["prior_reports"]
    assert (history / "report.md").read_text(encoding="utf-8") == "previous report"


def test_continuation_stops_when_original_or_copy_has_changed(evidence, settings):
    original = evidence / "日志.txt"
    case = Case.create(original, settings, '搜索关键词 "SECRET"')
    snapshot = Path(case.sources["s00001"].working_path)
    original.write_text("changed", encoding="utf-8")

    loaded = Case(case.directory, settings)
    assert not prepare_continuation(loaded)
    assert loaded.manifest["state"] == "evidence_changed"
    assert loaded.manifest["continuations"][-1]["outcome"] == "integrity_failed"
    assert sha256_file(snapshot) == case.sources["s00001"].sha256


def test_continuation_does_not_repeat_requests_or_one_shot_repair(evidence, settings):
    settings.model.max_steps = 2
    case = Case.create(evidence / "日志.txt", settings, '搜索关键词 "SECRET"')
    first = Client([
        Decision(action="tool", request=search_request()),
        Decision(action="tool", request=search_request()),
        Decision(action="finish"),
    ])
    analyze(case, client=first)
    assert first.calls == 3 and case.manifest["repair_budgets"]["decision"]
    assert len(case.manifest["steps"]) == 1

    assert prepare_continuation(Case(case.directory, settings))
    loaded = Case(case.directory, settings)
    second = Client([Decision(action="tool", request=search_request())])
    analyze(loaded, client=second)

    assert second.calls == 1
    assert loaded.manifest["state"] == "stopped_duplicate"
    assert len(loaded.manifest["steps"]) == 1
    assert len(list(loaded.directory.glob("model-*-decision-repair.json"))) == 1


def test_old_case_without_budget_inferrs_a_used_correction_from_audit_file(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings, '搜索关键词 "SECRET"')
    (case.directory / "model-001-decision-repair.json").write_text("{}", encoding="utf-8")
    case.manifest.pop("repair_budgets", None)
    case.save()

    loaded = Case(case.directory, settings)
    assert prepare_continuation(loaded)
    assert loaded.manifest["repair_budgets"]["decision"] is True
    assert loaded.manifest["repair_budgets"]["claim"] is False


@pytest.mark.parametrize("target", ["copy", "output", "directory_addition"])
def test_continuation_rejects_changes_to_prior_case(evidence, settings, target):
    case = Case.create(evidence, settings, "hash")
    step = run_tool(case, ToolRequest(tool_id="hash", source_id=case.manifest["root_id"]))
    if target == "copy":
        path = next(Path(item.working_path) for item in case.sources.values() if item.kind == "file")
    elif target == "output":
        path = case.directory / next(iter(step["output_hashes"]))
    else:
        path = evidence / "new.txt"
    path.write_bytes(b"changed")

    assert not prepare_continuation(case)
    assert case.manifest["state"] == "evidence_changed"
    assert len(case.manifest["steps"]) == 1


def test_continuation_preserves_model_log_at_the_same_step(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings, "hash")
    analyze(case, client=Client([Decision(action="finish")]))
    path = case.directory / "model-001-0.json"
    previous = path.read_bytes()
    assert prepare_continuation(case)
    analyze(case, client=Client([Decision(action="finish")]))
    assert path.read_bytes() == previous
    assert (case.directory / "model-001-0-resume001.json").is_file()


def test_continuation_from_exhausted_budget_can_add_bounded_new_steps(evidence, settings):
    settings.model.max_steps = 1
    case = Case.create(evidence / "日志.txt", settings, "hash")
    analyze(case, client=Client([Decision(action="tool", request=search_request())]))
    assert case.manifest["state"] == "stopped_budget"
    assert prepare_continuation(case)
    analyze(case, client=Client([Decision(action="tool", request=ToolRequest(tool_id="hash", source_id="s00001"))]))
    assert len(case.manifest["steps"]) == 2
    assert case.manifest["state"] == "stopped_budget"


def test_failed_legacy_correction_consumes_budget(evidence, settings):
    case = Case.create(evidence / "日志.txt", settings, "hash")
    (case.directory / "model-001-claim-repair-failed.json").write_text("{}", encoding="utf-8")
    assert prepare_continuation(case)
    assert case.manifest["repair_budgets"]["claim"] is True


def test_concurrent_case_operation_is_rejected_without_writes(evidence, settings, tmp_path, capsys):
    import json
    from forensic_agent.cli import main

    case = Case.create(evidence / "日志.txt", settings, "hash")
    config = tmp_path / "config.toml"
    config.write_text(f"work_dir = {json.dumps(str(settings.work_dir))}\n", encoding="utf-8")
    with case.exclusive_operation():
        before = (case.directory / "case.json").read_bytes()
        with pytest.raises(CaseBusyError):
            with Case(case.directory, settings).exclusive_operation():
                pytest.fail("Concurrent operation entered")
        assert main(["--config", str(config), "analyze", "--case", str(case.directory), "--no-model"]) == 2
        assert "已有操作" in json.loads(capsys.readouterr().out)["error"]
        assert (case.directory / "case.json").read_bytes() == before
        assert not (case.directory / "report.md").exists()
    with case.exclusive_operation():
        pass


def test_failure_to_acquire_lock_keeps_case_and_report_untouched(evidence, settings, tmp_path, capsys, monkeypatch):
    from contextlib import contextmanager
    import json
    from forensic_agent.cli import main

    case = Case.create(evidence / "日志.txt", settings, "hash")
    config = tmp_path / "config.toml"
    config.write_text(f"work_dir = {json.dumps(str(settings.work_dir))}\n", encoding="utf-8")
    before = (case.directory / "case.json").read_bytes()

    @contextmanager
    def denied(_):
        raise OSError("lock denied")
        yield

    monkeypatch.setattr(Case, "exclusive_operation", denied)
    assert main(["--config", str(config), "analyze", "--case", str(case.directory), "--no-model"]) == 2
    assert "lock denied" in json.loads(capsys.readouterr().out)["error"]
    assert (case.directory / "case.json").read_bytes() == before
    assert not (case.directory / "report.md").exists()


def test_new_analysis_still_accepts_interactive_evidence_path(evidence, settings, tmp_path, capsys, monkeypatch):
    import json
    from forensic_agent.cli import main

    config = tmp_path / "config.toml"
    config.write_text(f"work_dir = {json.dumps(str(settings.work_dir))}\n", encoding="utf-8")
    monkeypatch.setattr("builtins.input", lambda _: str(evidence / "日志.txt"))
    assert main(["--config", str(config), "analyze", "--question", "hash", "--no-model"]) == 0
    assert json.loads(capsys.readouterr().out)["reused"] is False


def test_report_backup_failure_preserves_prior_report_and_first_error(evidence, settings, tmp_path, capsys, monkeypatch):
    import json
    from forensic_agent.cli import main

    case = Case.create(evidence / "日志.txt", settings, "hash")
    report = case.directory / "report.md"
    report.write_bytes(b"prior report")
    config = tmp_path / "config.toml"
    config.write_text(f"work_dir = {json.dumps(str(settings.work_dir))}\n", encoding="utf-8")
    original_mkdir = Path.mkdir

    def denied_history(path, *args, **kwargs):
        if "report-history" in path.parts:
            raise OSError("archive write denied")
        return original_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", denied_history)
    assert main(["--config", str(config), "analyze", "--case", str(case.directory), "--no-model"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert "archive write denied" in result["error"] and "report_error" not in result
    assert report.read_bytes() == b"prior report"
    assert not Case(case.directory, settings).manifest["steps"]
