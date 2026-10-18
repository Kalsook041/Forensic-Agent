"""Bounded, advisory report sections. Never execute tools or validate answers here."""
import json

from ..evidence.paths import local_path
from ..evidence.store import utc_now


def review_text(review):
    lines = []
    for key, label in (("targets", "答案目标"), ("scope", "分析范围"), ("constraints", "题目约束"),
                       ("evidence_needed", "所需证据"), ("missing", "缺失条件"), ("stop_when", "完成与停止条件")):
        value = review.get(key, [])
        lines.append(label + "：")
        if isinstance(value, list):
            lines.extend("  - " + str(item) for item in value)
        else:
            lines.append(str(value))
        if value == []:
            lines.append("  （模型未列出；需结合题目核对）")
    return "\n".join(lines)


def publish_section(case, identity, title, text, progress=None, *, status="待核验"):
    runs = case.manifest.get("analysis_runs", [])
    if not runs:
        return
    run = runs[-1]
    if len(text) > 10000:
        text = text[:10000] + "\n（预览已省略，完整证据以案件原始工具输出为准）"
    event = {"id": f"run{len(runs):04d}:{identity}", "title": title, "text": text,
             "status": status, "question_id": case.manifest.get("question_id", "q0001"), "time": utc_now()}
    try:
        path = local_path(case.directory / f"live-run-{len(runs):04d}.jsonl", must_exist=False)
        mode = "a" if run.get("live_report") == path.name else "x"
        with path.open(mode, encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(event, ensure_ascii=False, allow_nan=False) + "\n")
        run["live_report"] = path.name
    except (OSError, ValueError) as exc:
        warning = f"阶段报告辅助保存失败：{type(exc).__name__}: {exc}"
        if warning not in case.manifest["warnings"]:
            case.manifest["warnings"].append(warning)
    if progress:
        try:
            progress({"type": "report_section", **event})
        except Exception as exc:
            warning = f"阶段报告推送失败：{type(exc).__name__}: {exc}"
            if warning not in case.manifest["warnings"]:
                case.manifest["warnings"].append(warning)


def publish_tool(case, step, progress=None):
    result = step["result"]
    preview = [{"id": row["id"], "source_id": row["source_id"],
                "locator": row["locator"], "data": row["data"]} for row in step["evidence"][:3]]
    text = (f"工具：{step['request']['tool_id']}；来源：{step['request']['source_id']}\n"
            f"参数：{json.dumps(step['request']['params'], ensure_ascii=False)}\n"
            f"工具状态：{result['status']}；本步骤已记录证据：{len(step['evidence'])} 条\n"
            "以下是工具事实预览，尚非模型答案；失败、不完整及未知结果不能当完整结论。\n"
            + json.dumps(preview, ensure_ascii=False, indent=2))
    if len(step["evidence"]) > 3:
        text += "\n（仅预览前3条，其余证据保存在案件中）"
    if result.get("error"):
        text += "\n错误：" + result["error"]
    if result.get("warnings"):
        text += "\n警告：" + "；".join(result["warnings"])
    publish_section(case, step["id"], "工具结果 · " + step["id"], text, progress,
                    status="工具结果 · 待最终核验")
