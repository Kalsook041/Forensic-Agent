"""Real local Ollama end-to-end tests. Does not claim physical offline validation."""
import json
from pathlib import Path
import sys

from forensic_agent.agent.loop import analyze
from forensic_agent.evidence import Case
from forensic_agent.evidence.store import utc_now, write_json
from forensic_agent.reports import generate_report
from forensic_agent.settings import load_settings


def main():
    project = Path(__file__).resolve().parents[1]
    settings = load_settings(project / "config/default.toml")
    cases = [
        ("线索.txt", '搜索关键词 "FLAG"，回答命中的完整原始文本行并引用证据。', "search", "FLAG-TEXT-2026"),
        ("作者图片.png", "提取这张图片的 Author 作者字段，回答该字段原值并引用证据。", "metadata", "Forensic Fixture"),
        ("聊天记录.sqlite", "请查询 SQLite 数据库，messages 表一共有多少条记录？回答计数并引用证据。", "sqlite", 3),
    ]
    outcomes = []
    for filename, question, expected_tool, expected_value in cases:
        case = Case.create(project / "examples/检材" / filename, settings, question)
        analyze(case, progress=lambda line: print(json.dumps({"progress": line}, ensure_ascii=False), flush=True))
        actual = [answer["value"] for answer in case.manifest["answers"]]
        normalized = [value[0] if isinstance(value, list) and len(value) == 1 else value for value in actual]
        passed = (case.manifest["state"] == "completed" and expected_value in normalized
                  and any(step["request"]["tool_id"] == expected_tool for step in case.manifest["steps"])
                  and not case.verify_originals())
        outcomes.append({"question": question, "passed": passed, "state": case.manifest["state"],
                         "answers": actual, "expected": expected_value, "model": case.manifest.get("model"),
                         "report": str(generate_report(case)), "warnings": case.manifest["warnings"]})
        print(json.dumps(outcomes[-1], ensure_ascii=False, indent=2), flush=True)
    result = {"tested_utc": utc_now(), "passed": all(item["passed"] for item in outcomes),
              "cases": outcomes, "physical_offline_restart_tested": False}
    write_json(project / "local-state/live-model-acceptance.json", result)
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
