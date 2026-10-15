"""Real installed-tool acceptance; no LLM mocks and no network requests."""
import json
from pathlib import Path
import sys

from forensic_agent.evidence import Case
from forensic_agent.models import ToolRequest
from forensic_agent.reports import generate_report
from forensic_agent.settings import load_settings
from forensic_agent.tools.runner import run_tool


def smoke():
    project = Path(__file__).resolve().parents[1]
    settings = load_settings(project / "config/default.toml")
    case = Case.create(project / "examples/检材", settings, "样例验收：检索、作者、数据库、流量与压缩包")
    sources = {Path(item.original_path).name: item.id for item in case.sources.values()
               if item.original_path and item.kind == "file"}
    checks = [
        ("inventory", "s00001", {}, lambda row: row["result"]["status"] == "ok"),
        ("hash", sources["线索.txt"], {}, lambda row: len(row["evidence"][0]["data"]["sha256"]) == 64),
        ("search", sources["线索.txt"], {"keyword": "FLAG"},
         lambda row: row["evidence"][0]["data"]["text"] == "FLAG-TEXT-2026"),
        ("metadata", sources["作者图片.png"], {"fields": ["Author"]},
         lambda row: row["evidence"][0]["data"]["value"] == "Forensic Fixture"),
        ("sqlite", sources["聊天记录.sqlite"], {"query": "count", "table": "messages"},
         lambda row: row["evidence"][0]["data"]["values"] == [3]),
        ("pcap", sources["DNS_HTTP.pcap"], {"protocol": "dns"},
         lambda row: row["evidence"][0]["data"]["dns.qry.name"] == "contest.test"),
        ("archive", sources["安全压缩包.zip"], {"action": "extract"},
         lambda row: len(row.get("derived_source_ids", [])) == 1),
    ]
    results = []
    for tool_id, source_id, params, verify in checks:
        step = run_tool(case, ToolRequest(tool_id=tool_id, source_id=source_id, params=params))
        passed = step["result"]["status"] in {"ok", "partial"} and verify(step)
        results.append({"tool": tool_id, "passed": passed, "status": step["result"]["status"]})
    match = next(row for step in case.manifest["steps"] if step["request"]["tool_id"] == "search" for row in step["evidence"])
    window = run_tool(case, ToolRequest(tool_id="evidence_window", source_id=match["source_id"], params={
        "evidence_id": match["id"], "field": "text", "start": 0, "length": 256}))
    results.append({"tool": "evidence_window", "passed": window["result"]["status"] == "ok"
                    and window["evidence"][0]["data"]["value"] == "FLAG-TEXT-2026", "status": window["result"]["status"]})
    case.manifest["state"] = "smoke_passed" if all(x["passed"] for x in results) else "smoke_failed"
    case.manifest["plan"] = ["使用明确已知答案的物理样例文件验证各适配器；本次没有调用模型"]
    case.save()
    report = generate_report(case)
    evtx_case = Case.create(project / "tests/fixtures/system.evtx", settings, "公共 EVTX 样本解析冒烟测试")
    evtx = run_tool(evtx_case, ToolRequest(tool_id="evtx", source_id="s00001", params={"limit": 2}))
    evtx_case.manifest["state"] = "smoke_passed" if len(evtx["evidence"]) == 2 else "smoke_failed"
    evtx_case.save()
    evtx_report = generate_report(evtx_case)
    results.append({"tool": "evtx", "passed": len(evtx["evidence"]) == 2, "status": evtx["result"]["status"]})
    if settings.tools.evtxecmd and Path(settings.tools.evtxecmd).is_file():
        native = run_tool(evtx_case, ToolRequest(tool_id="evtxecmd", source_id="s00001",
                                               params={"event_ids": [6005], "limit": 20}))
        passed = native["result"]["status"] == "ok" and len(native["evidence"]) == 5
        results.append({"tool": "evtxecmd", "passed": passed, "status": native["result"]["status"]})
        evtx_report = generate_report(evtx_case)
    else:
        results.append({"tool": "evtxecmd", "passed": True, "status": "disabled",
                        "reason": "可选本机 EvtxECmd 未安装；python-evtx 能力另行验证"})
    payload = {"checks": results, "report": str(report), "evtx_report": str(evtx_report),
               "integrity_issues": case.verify_current() + evtx_case.verify_current(),
               "live_model_tested": False, "physical_offline_restart_tested": False}
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return payload


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    result = smoke()
    raise SystemExit(0 if all(x["passed"] for x in result["checks"]) and not result["integrity_issues"] else 1)
