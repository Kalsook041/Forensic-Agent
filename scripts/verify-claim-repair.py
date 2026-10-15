"""Replay the saved SQL citation failure, then run two live local model cases once."""
from datetime import datetime, timezone
import argparse
import json
from pathlib import Path
import shutil

from forensic_agent.agent.loop import analyze
from forensic_agent.agent.ollama import Claim, Decision
from forensic_agent.evidence import Case
from forensic_agent.evidence.store import write_json
from forensic_agent.reports import generate_report
from forensic_agent.settings import load_settings


ROOT = Path(__file__).resolve().parents[1]


class ReplayClient:
    def __init__(self, original):
        self.original = original

    def discover(self):
        return {"replay_of": str(self.original)}

    def decide(self, messages):
        self.calls = getattr(self, "calls", 0) + 1
        if self.calls == 1:
            raw = json.loads((self.original / "model-003-0.json").read_text(encoding="utf-8"))["response"]
            return Decision.model_validate_json(raw["message"]["content"]), raw
        decision = Decision(action="finish", claims=[Claim(evidence_id="step0002:r00001", field="values[0]", value=3)])
        return decision, {"message": {"content": decision.model_dump_json()}}



def case_result(case, filename, expected, tool_id):
    # Reporting rechecks integrity and citations and can invalidate old answers.
    # Calculate the verdict only from that final state, including working/raw copies.
    report = generate_report(case)
    issues = case.verify_current()
    values = [answer["value"] for answer in case.manifest["answers"]]
    return {"test": filename, "passed": case.manifest["state"] == "completed"
            and expected in values and not issues
            and any(step["request"]["tool_id"] == tool_id for step in case.manifest["steps"]),
            "state": case.manifest["state"], "answers": values, "integrity_issues": issues,
            "warnings": list(case.manifest["warnings"]), "report": str(report)}


def main():
    output = ROOT / "local-state" / "claim-repair-checks" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output.mkdir(parents=True)
    settings = load_settings(ROOT / "config/default.toml")
    parser = argparse.ArgumentParser()
    parser.add_argument("--sqlite-case", type=Path, help="Record an existing live SQL attempt without rerunning it")
    parser.add_argument("--keyword-case", type=Path, help="Record an existing live keyword attempt without rerunning it")
    options = parser.parse_args()
    original = Path("E:/ForensicWork/20261015T124003Z-b36808e9")
    replay_dir = output / "saved-case-replay"
    shutil.copytree(original, replay_dir)
    manifest_path = replay_dir / "case.json"
    manifest_text = manifest_path.read_text(encoding="utf-8")
    manifest_text = manifest_text.replace(json.dumps(str(original))[1:-1], json.dumps(str(replay_dir))[1:-1])
    manifest_path.write_text(manifest_text, encoding="utf-8")
    # Preserve original outputs in the saved case; write this replay's decisions separately.
    for path in replay_dir.glob("model-*.json"):
        path.rename(path.with_name("before-repair-" + path.name))
    case = Case(replay_dir, settings)
    case.manifest["answers"] = []
    client = ReplayClient(original)
    analyze(case, client=client)
    replay = case_result(case, "saved-n-to-values-replay", 3, "sqlite")
    replay["passed"] = replay["passed"] and client.calls == 2
    results = [replay]
    write_json(output / "replay-result.json", replay)
    for filename, question, expected, tool_id, existing in (
        ("聊天记录.sqlite", "请查询 SQLite 数据库，messages 表一共有多少条记录？回答计数并引用证据。", 3, "sqlite", options.sqlite_case),
        ("线索.txt", '搜索关键词 "FLAG"，回答命中的完整原始文本行并引用证据。', "FLAG-TEXT-2026", "search", options.keyword_case),
    ):
        if existing:
            case = Case(existing, settings)
        else:
            case = Case.create(ROOT / "examples/检材" / filename, settings, question)
            analyze(case, progress=lambda line: print(line, flush=True))
        result = case_result(case, filename, expected, tool_id)
        result["reused_case"] = bool(existing)
        results.append(result)
        write_json(output / ("sqlite-result.json" if tool_id == "sqlite" else "keyword-result.json"), result)
        print(json.dumps(result, ensure_ascii=False), flush=True)
    print(str(output), flush=True)
    write_json(output / "results.json", results)
    return not all(item["passed"] for item in results)


if __name__ == "__main__":
    raise SystemExit(main())
