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
OUT = ROOT / "local-state" / "claim-repair-checks" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
OUT.mkdir(parents=True)
settings = load_settings(ROOT / "config/default.toml")
parser = argparse.ArgumentParser()
parser.add_argument("--sqlite-case", type=Path, help="Record an already completed first live SQL attempt without rerunning it")
options = parser.parse_args()
original = Path("E:/ForensicWork/20261015T124003Z-b36808e9")
results = []


class ReplayClient:
    def discover(self):
        return {"replay_of": str(original)}

    def decide(self, messages):
        self.calls = getattr(self, "calls", 0) + 1
        if self.calls == 1:
            raw = json.loads((original / "model-003-0.json").read_text(encoding="utf-8"))["response"]
            return Decision.model_validate_json(raw["message"]["content"]), raw
        decision = Decision(action="finish", claims=[Claim(evidence_id="step0002:r00001", field="values[0]", value=3)])
        return decision, {"message": {"content": decision.model_dump_json()}}


replay_dir = OUT / "saved-case-replay"
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
client = ReplayClient()
analyze(case, client=client)
results.append({"test": "saved-n-to-values-replay", "passed": client.calls == 2
                and case.manifest["state"] == "completed" and case.manifest["answers"][0]["value"] == 3,
                "case": str(replay_dir), "warnings": case.manifest["warnings"]})
write_json(OUT / "replay-result.json", results[-1])
for filename, question, expected in (
    ("聊天记录.sqlite", "请查询 SQLite 数据库，messages 表一共有多少条记录？回答计数并引用证据。", 3),
    ("线索.txt", '搜索关键词 "FLAG"，回答命中的完整原始文本行并引用证据。', "FLAG-TEXT-2026"),
):
    if filename.endswith("sqlite") and options.sqlite_case:
        case = Case(options.sqlite_case, settings)
    else:
        case = Case.create(ROOT / "examples/检材" / filename, settings, question)
        analyze(case, progress=lambda line: print(line, flush=True))
    values = [answer["value"] for answer in case.manifest["answers"]]
    results.append({"test": filename, "passed": case.manifest["state"] == "completed"
                    and expected in values and not case.verify_originals(), "state": case.manifest["state"],
                    "answers": values, "warnings": case.manifest["warnings"], "report": str(generate_report(case))})
    write_json(OUT / ("sqlite-result.json" if filename.endswith("sqlite") else "keyword-result.json"), results[-1])
    print(json.dumps(results[-1], ensure_ascii=False), flush=True)
print(str(OUT), flush=True)
write_json(OUT / "results.json", results)
raise SystemExit(not all(item["passed"] for item in results))
