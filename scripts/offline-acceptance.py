"""Requires the user to disconnect networking and restart Ollama before invocation."""
import json
from pathlib import Path
import sys

from forensic_agent.agent.loop import analyze
from forensic_agent.doctor import network_interfaces
from forensic_agent.evidence import Case
from forensic_agent.evidence.store import utc_now, write_json
from forensic_agent.reports import generate_report
from forensic_agent.settings import load_settings
from smoke_test import smoke


def main():
    project = Path(__file__).resolve().parents[1]
    network = network_interfaces()
    if not network.get("verified") or network.get("up_adapters"):
        print(json.dumps({"passed": False, "reason": "需要先关闭所有外部网络适配器；未自动断网",
                          "network": network}, ensure_ascii=False, indent=2))
        return 2
    record_path = project / "local-state/ollama-session.json"
    if not record_path.is_file():
        print("缺少 Ollama 冷启动记录；断网后使用 scripts/start-ollama.ps1 启动服务。")
        return 2
    startup = json.loads(record_path.read_text(encoding="utf-8-sig"))
    import subprocess
    powershell = str(Path(__import__("os").environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    probe = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command",
        "@(Get-NetTCPConnection -LocalPort 11434 -State Listen -ErrorAction Stop | Select-Object OwningProcess,LocalAddress) | ConvertTo-Json -Compress"],
        shell=False, capture_output=True, timeout=15, creationflags=subprocess.CREATE_NO_WINDOW)
    listeners = json.loads(probe.stdout.decode("utf-8-sig").strip() or "[]")
    listeners = listeners if isinstance(listeners, list) else [listeners]
    if (startup.get("network_adapter_count") != 0 or not listeners
            or any(item.get("OwningProcess") != startup.get("pid") or item.get("LocalAddress") != "127.0.0.1"
                   for item in listeners)):
        print("服务不是本次记录的断网后回环冷启动实例；请按 README 重新启动。")
        return 2
    settings = load_settings(project / "config/default.toml")
    evidence = project / "examples/检材"
    outcomes = []
    for filename, question, expected_tool, expected_value in (
            ("线索.txt", '搜索关键词 "FLAG" 并给出该行文本', "search", "FLAG-TEXT-2026"),
            ("作者图片.png", "提取图片 Author 作者字段", "metadata", "Forensic Fixture"),
            ("聊天记录.sqlite", "messages 表中有多少条记录？请查询数据库", "sqlite", 3)):
        case = Case.create(evidence / filename, settings, question)
        analyze(case)
        values = [item["value"] for item in case.manifest["answers"]]
        values = [value[0] if isinstance(value, list) and len(value) == 1 else value for value in values]
        outcomes.append({"question": question, "state": case.manifest["state"],
                         "expected_answer_found": expected_value in values, "answers": values,
                         "expected_tool_called": any(step["request"]["tool_id"] == expected_tool
                                                     for step in case.manifest["steps"]),
                         "report": str(generate_report(case)), "integrity": case.verify_originals()})
    real_tools = smoke()
    after = network_interfaces()
    passed = (after.get("verified") and not after.get("up_adapters")
              and all(x["state"] == "completed" and x["expected_tool_called"] and x["expected_answer_found"]
                      and not x["integrity"] for x in outcomes)
              and all(x["passed"] for x in real_tools["checks"]) and not real_tools["integrity_issues"])
    result = {"tested_utc": utc_now(), "passed": bool(passed), "network_before": network,
              "network_after": after, "model_cases": outcomes, "tool_smoke": real_tools,
              "ollama_startup": startup,
              "restart_note": "验证断网前后状态、回环服务 PID 与断网后冷启动记录；结果依赖本机可信记录"}
    destination = project / "local-state/offline-acceptance.json"
    destination.parent.mkdir(exist_ok=True)
    write_json(destination, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if passed else 2


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
