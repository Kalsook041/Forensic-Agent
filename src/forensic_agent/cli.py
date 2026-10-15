import argparse
import json
from pathlib import Path
import sys

from .agent.loop import analyze
from .doctor import find_tools, inspect_environment
from .evidence import Case
from .models import MAX_QUESTION_CHARS, ToolRequest
from .reports import generate_report
from .settings import load_settings
from .tools.registry import catalog
from .tools.runner import run_tool


def display(value):
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
        sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser(description="完全本地运行、证据优先的 Windows 取证 CLI")
    parser.add_argument("--config", type=Path, help="TOML 配置文件绝对路径")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("doctor", help="只读检查环境、工具与本地模型")
    subparsers.add_parser("tools", help="查看白名单适配器、参数和可用性")
    tool = subparsers.add_parser("tool", help="直接执行适配器，不依赖模型")
    tool.add_argument("tool_id")
    tool.add_argument("--evidence", type=Path)
    tool.add_argument("--case", type=Path, help="继续已有案件；与 --evidence 二选一")
    tool.add_argument("--source-id", default="s00001")
    tool.add_argument("--params", default="{}", help="工具参数 JSON")
    analysis = subparsers.add_parser("analyze", help="输入自然语言题目，进行有限调查")
    analysis.add_argument("--evidence", type=Path)
    analysis.add_argument("--question")
    analysis.add_argument("--no-model", action="store_true", help="明确使用简单规则流程，不使用模型")
    report = subparsers.add_parser("report", help="重新生成已有案件的中文报告")
    report.add_argument("case", type=Path)
    args = parser.parse_args(argv)
    case = None
    try:
        settings = load_settings(args.config)
        # Discovery selects only fixed supported programs; it never adds arbitrary executables to the registry.
        for key, value in find_tools(settings).items():
            if value:
                setattr(settings.tools, key, value)
        if args.command == "doctor":
            display(inspect_environment(settings))
            return 0
        if args.command == "tools":
            display(catalog(settings))
            return 0
        if args.command == "report":
            case = Case(args.case, settings)
            display({"report": str(generate_report(case))})
            return 2 if case.manifest["state"] == "evidence_changed" else 0
        if args.command == "tool":
            if bool(args.evidence) == bool(args.case):
                raise ValueError("--evidence 与 --case 必须选择且只能选择一个")
            case = Case(args.case, settings) if args.case else Case.create(args.evidence, settings)
            step = run_tool(case, ToolRequest(tool_id=args.tool_id, source_id=args.source_id,
                                              params=json.loads(args.params)))
            if case.manifest["state"] != "evidence_changed":
                case.manifest["state"] = "tool_completed" if step["result"]["status"] in {"ok", "partial"} else "tool_failed"
            case.save()
            report_path = generate_report(case)
            display({"case": str(case.directory), "status": step["result"]["status"],
                     "state": case.manifest["state"],
                     "records": len(step["evidence"]), "error": step["result"]["error"],
                     "warnings": step["result"]["warnings"], "report": str(report_path)})
            return 0 if step["result"]["status"] in {"ok", "partial"} and case.manifest["state"] != "evidence_changed" else 2
        evidence = args.evidence or Path(input("检材文件或目录的本地路径：").strip().strip('"'))
        question = args.question or input("请输入取证题目：").strip()
        if not question or len(question) > MAX_QUESTION_CHARS:
            raise ValueError(f"题目长度应为 1..{MAX_QUESTION_CHARS} 字符，请拆分；不会截断尾部约束")
        case = Case.create(evidence, settings, question)
        analyze(case, no_model=args.no_model, progress=lambda line: display({"progress": line}))
        report_path = generate_report(case)
        display({"case": str(case.directory), "state": case.manifest["state"],
                 "report": str(report_path), "warnings": case.manifest["warnings"]})
        return 0 if case.manifest["state"] in {"completed", "completed_without_model"} else 2
    except KeyboardInterrupt:
        if case:
            case.manifest["state"] = "cancelled"
            case.save()
            generate_report(case, verify_integrity=False)
        print("已取消；工作进程树已终止，原件未作为写入目标。", file=sys.stderr)
        return 130
    except Exception as exc:
        display({"error": f"{type(exc).__name__}: {exc}",
                 "case": str(case.directory) if case else getattr(exc, "case_directory", None)})
        if case:
            try:
                generate_report(case)
            except OSError as report_error:
                display({"report_error": str(report_error), "note": "报告写入失败；已持久化的操作记录保留在案件目录"})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
