import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import sys

from .agent.loop import analyze, prepare_continuation, prepare_next_question
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
    analysis.add_argument("--case", type=Path, help="复用已登记案件；添加新题请配合 --new-question")
    analysis.add_argument("--question")
    analysis.add_argument("--new-question", help="在 --case 指定的同案件中添加新题，复用原副本")
    analysis.add_argument("--no-model", action="store_true", help="明确使用简单规则流程，不使用模型")
    analysis.add_argument("--progress", action="store_true", help="逐条输出进度 JSON（工作台使用）")
    report = subparsers.add_parser("report", help="重新生成已有案件的中文报告")
    report.add_argument("case", type=Path)
    args = parser.parse_args(argv)
    case = None
    operations = ExitStack()
    operation_started = False
    continuation_setup = False

    def lock_case(target):
        nonlocal operation_started
        operations.enter_context(target.exclusive_operation())
        operation_started = True
    try:
        settings = load_settings(args.config)

        def progress(value):
            if isinstance(value, dict):
                if value.get("type") == "report_section":
                    display({"progress": value["title"], "report_section": value})
                    return
                event = value.get("event", "progress")
                stage = value.get("stage", "处理")
                elapsed = value.get("elapsed_seconds")
                suffix = f"（{elapsed:.1f} 秒）" if isinstance(elapsed, (int, float)) else ""
                display({"progress": f"{stage}：{event}{suffix}", "progress_event": value})
            else:
                display({"progress": str(value)})

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
            lock_case(case)
            display({"report": str(generate_report(case))})
            return 2 if case.manifest["state"] == "evidence_changed" else 0
        if args.command == "tool":
            if bool(args.evidence) == bool(args.case):
                raise ValueError("--evidence 与 --case 必须选择且只能选择一个")
            case = Case(args.case, settings) if args.case else Case.create(args.evidence, settings)
            lock_case(case)
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
        if args.evidence and args.case:
            raise ValueError("analyze 的 --evidence 与 --case 不能同时指定")
        if args.new_question is not None and not args.case:
            raise ValueError("--new-question 必须与 --case 一起使用")
        if args.case:
            if args.question:
                raise ValueError("继续案件使用其已保存题目；不接受 --question，以免混淆案件记录")
            case = Case(args.case, settings, progress=progress if args.progress else None)
            lock_case(case)
            continuation_setup = True
            prepared = (prepare_next_question(case, args.new_question) if args.new_question is not None
                        else prepare_continuation(case))
            continuation_setup = False
            if not prepared:
                report_path = generate_report(case)
                display({"case": str(case.directory), "state": case.manifest["state"], "reused": True,
                         "continued": False, "report": str(report_path), "warnings": case.manifest["warnings"]})
                return 2
        else:
            evidence = args.evidence or Path(input("检材文件或目录的本地路径：").strip().strip('"'))
            question = args.question or input("请输入取证题目：").strip()
            if not question or len(question) > MAX_QUESTION_CHARS:
                raise ValueError(f"题目长度应为 1..{MAX_QUESTION_CHARS} 字符，请拆分；不会截断尾部约束")
            case = Case.create(evidence, settings, question, progress=progress if args.progress else None)
            lock_case(case)
        analyze(case, no_model=args.no_model, progress=progress if args.progress else None)
        report_path = generate_report(case)
        from .reports.live import publish_section
        publish_section(case, "report", "最终报告已生成",
                        f"最终状态：{case.manifest['state']}\n报告已保存，答案与限制以最终报告为准。",
                        progress if args.progress else None, status="报告已生成")
        display({"case": str(case.directory), "state": case.manifest["state"], "reused": bool(args.case),
                 "question_id": case.manifest.get("question_id", "q0001"),
                 "continued": bool(args.case),
                 "report": str(report_path), "warnings": case.manifest["warnings"]})
        return 0 if case.manifest["state"] in {"completed", "completed_without_model"} else 2
    except KeyboardInterrupt:
        if case and operation_started:
            case.manifest["state"] = "cancelled"
            case.save()
            if not continuation_setup:
                generate_report(case, verify_integrity=False)
        print("已取消；工作进程树已终止，原件未作为写入目标。", file=sys.stderr)
        return 130
    except Exception as exc:
        failed_directory = str(case.directory) if case else getattr(exc, "case_directory", None)
        result = {"error": f"{type(exc).__name__}: {exc}", "case": failed_directory}
        # create() persists an intake_failed case before raising. Assignment to
        # 'case' never completes on that path, but its diagnostic report is useful.
        if case is None and failed_directory:
            try:
                case = Case(Path(failed_directory), settings)
            except Exception as load_error:
                result["report_error"] = f"无法读取失败案件：{type(load_error).__name__}: {load_error}"
        if case and (operation_started or getattr(exc, "case_directory", None)):
            if not continuation_setup:
                try:
                    result["report"] = str(generate_report(case))
                except Exception as report_error:
                    result["report_error"] = f"{type(report_error).__name__}: {report_error}"
            result["state"] = case.manifest["state"]
            result["warnings"] = case.manifest["warnings"]
        display(result)
        return 2
    finally:
        operations.close()


if __name__ == "__main__":
    raise SystemExit(main())
