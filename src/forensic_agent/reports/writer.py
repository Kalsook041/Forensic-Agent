import json
import re
from types import SimpleNamespace

from ..evidence.store import write_json
from ..manual import build_manual_guidance
from .live import review_text


def inline(value):
    text = str(value)
    text = re.sub(r"[\x00-\x1f\x7f]", lambda m: f"\\u{ord(m.group()):04x}", text)
    return "".join("\\" + ch if ch in "\\`*_{}[]()#+-.!|<>" else ch for ch in text)


def code_json(value):
    text = json.dumps(value, ensure_ascii=False, indent=2)
    fence = "`" * max(3, max((len(x) + 1 for x in re.findall(r"`+", text)), default=3))
    return f"{fence}json\n{text}\n{fence}"


def original_lineage(case, source):
    lineage = []
    visited = set()
    while source:
        if source.id in visited:
            raise ValueError("来源链形成循环")
        visited.add(source.id)
        lineage.append(source.model_dump())
        source = case.sources.get(source.parent_id)
    return lineage


def generate_report(case, *, verify_integrity=True):
    for step in case.manifest["steps"]:
        if "result" not in step:
            step["result"] = {"status": "failed", "warnings": ["步骤未完成，可能被外部终止；结果未验证"],
                              "error": "操作记录不完整"}
            step["integrity"] = {"issues": ["完整性复核未完成"]}
            step.setdefault("evidence", [])
    if verify_integrity:
        case.record_integrity("report")
        from ..agent.loop import validate_claims
        claims = [SimpleNamespace(**answer) for answer in case.manifest.get("answers", [])]
        accepted, errors = validate_claims(case, claims)
        if errors:
            case.invalidate_answers("报告重建时答案来源校验未通过")
            case.manifest["answers"] = accepted
            case.manifest["warnings"].extend(errors)
            if not accepted and case.manifest["state"] != "evidence_changed":
                case.manifest["state"] = "insufficient_evidence"
    else:
        case.invalidate_answers("取消时未执行当前完整性复核")
        case.manifest["warnings"].append("取消报告沿用历史完整性记录，本次未完成当前复核")
    case.save()
    guidance = build_manual_guidance(case)
    evidence = [row for step in case.manifest["steps"] for row in step["evidence"]]
    lines = ["# 取证分析报告", "", f"题目：{inline(case.manifest['question'])}", "",
             "## 答案摘要", ""]
    if case.manifest.get("answers"):
        for i, answer in enumerate(case.manifest["answers"], 1):
            lines += [f"### 答案 {i}", "", code_json(answer["value"]), "",
                      f"证据引用：{inline(answer['evidence_id'])}；字段：{inline(answer['field'])}。", ""]
            if answer.get("interpretation"):
                lines += [f"候选解释（需要人工核对）：{inline(answer['interpretation'])}", ""]
        lines += ["以上值已通过来源与字段引用校验；是否完整回答题目仍需人工结合证据核对。"]
    else:
        lines += ["**尚未得出可验证答案。**",
                  "没有经引用校验的模型候选答案。下列内容为工具直接输出；不能据此自动确认复杂问题。"]
    lines += ["", f"案件：{inline(case.manifest['case_id'])}", "",
              f"状态：{inline(case.manifest['state'])}", "", "## 解题计划", ""]
    runs = [run for run in case.manifest.get("analysis_runs", [])
            if run.get("question_id", "q0001") == case.manifest.get("question_id", "q0001")
            and run.get("task_review")]
    if runs:
        lines += ["### 审题摘要与证据标准", "", "以下为模型对题意的理解，需结合题目核对：", ""]
        lines += [inline(line) + "  " for line in review_text(runs[-1]["task_review"]).splitlines()]
        lines += ["", "### 分步操作计划", ""]
    plan = runs[-1].get("plan", case.manifest.get("plan", [])) if runs else case.manifest.get("plan", [])
    lines += [f"{i}. {inline(line)}" for i, line in enumerate(plan, 1)] or [
        "未提出可执行工具计划；请核对缺失条件与停止说明。" if runs else "直接工具调用。"]
    if case.manifest.get("question_id"):
        lines += ["", "题目记录：", code_json({"question_id": case.manifest["question_id"],
            "new_step_ids": [step["id"] for step in case.manifest["steps"]
                             if step.get("question_id", "q0001") == case.manifest["question_id"]],
            "reused_step_ids": case.manifest.get("reused_step_ids", []),
            "previous_questions": [{"id": item["id"], "question": item["question"],
                                    "report_directory": item.get("report_directory")}
                                   for item in case.manifest.get("question_history", [])]}),
            "下列证据库保留全部题目的工具证据；当前候选答案仅针对本页题目。"]
    lines += ["", "## 校验与历史记录", ""]
    if case.manifest.get("historical_answers"):
        lines += ["", "历史候选（已失效或需要重新核查，不能作为当前答案）：",
                  code_json(case.manifest["historical_answers"])]
    if case.manifest.get("integrity_checks"):
        lines += ["", "当前完整性检查：", code_json(case.manifest["integrity_checks"][-1])]
    lines += ["", "## 检材来源清单", "",
              code_json([{"id": source.id, "original_path": source.original_path,
                          "working_path": source.working_path, "sha256": source.sha256,
                          "parent_id": source.parent_id, "member": source.member,
                          "filesystem": source.filesystem} for source in case.sources.values()]),
              "", "## 证据与定位", ""]
    failed_steps = {step["id"] for step in case.manifest["steps"]
                    if step["result"]["status"] not in {"ok", "partial"} or step["integrity"]["issues"]}
    for row in evidence:
        source = case.sources[row["source_id"]]
        lines += [f"### {inline(row['id'])}", "",
                  f"来源：{inline(source.original_path or '派生文件，见来源链')}", "",
                  f"SHA256：{source.sha256 or '目录无单一文件哈希'}", "",
                  f"工作副本：{inline(source.working_path)}", "",
                  f"原始工具输出：{inline(row['raw_output_path'])}", "",
                  code_json({"locator": row["locator"], "grounding": row.get("grounding", "legacy"), "data": row["data"]}), ""]
        if row.get("grounding") == "exploratory":
            lines += ["本条为人工探索性 SQL 结果，可能含自行构造的常量，不能作为模型答案依据。", ""]
        if row["id"].split(":")[0] in failed_steps:
            lines += ["本条来自失败或完整性检查不通过的步骤，仅供诊断，不能支持答案。", ""]
        if source.parent_id:
            lines += ["来源链：", code_json(original_lineage(case, source)), ""]
    lines += ["## 操作记录", ""]
    for step in case.manifest["steps"]:
        lines += [f"### {inline(step['id'])}：{inline(step['request']['tool_id'])}", "",
                  code_json({key: step.get(key) for key in ("question_id", "request", "started_utc", "finished_utc",
                                                           "worker_argv", "worker_exit_code", "runtime_versions", "execution_limits",
                                                           "output_hashes", "integrity")}), "",
                  f"状态：{inline(step['result']['status'])}", ""]
        command_file = case.directory / "steps" / step["id"] / "commands.jsonl"
        if command_file.is_file():
            commands = [json.loads(line) for line in command_file.read_text(encoding="utf-8").splitlines()]
            lines += [code_json(commands), ""]
    warnings = list(case.manifest["warnings"])
    for step in case.manifest["steps"]:
        warnings.extend(step["result"]["warnings"])
        if step["result"]["error"]:
            warnings.append(step["result"]["error"])
    lines += ["## 不确定性与限制", ""]
    lines += [f"- {inline(warning)}" for warning in dict.fromkeys(warnings)] or ["本次工具未报告额外警告；这不等于已穷尽全部取证方向。"]
    lines += ["", "所有时间字段保留工具原值；UTC 字段明确标注，缺少时区的元数据不自动转换。",
              "原始检材以只读方式读取，外部解析器使用工作副本；哈希检查验证内容，不保证访问时间等系统元数据不变。", ""]
    if guidance["needed"]:
        lines += [guidance["text"].replace("\n## ", "\n### ").replace("# 人工操作指南", "## 人工操作指南", 1)]
    report_path = case.directory / "report.md"
    pending_report = report_path.with_suffix(".md.tmp")
    pending_report.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    pending_report.replace(report_path)
    report_data = {"case": case.manifest, "evidence": evidence,
                   "warnings": list(dict.fromkeys(warnings)), "manual_guidance": guidance}
    json_path = case.directory / "report.json"
    # Commit the primary diagnostics before an optional duplicate uses disk space.
    write_json(json_path, report_data)
    try:
        (case.directory / "manual-guide.md").write_text(guidance["text"], encoding="utf-8", newline="\n")
    except OSError as exc:
        guidance["file_error"] = f"{type(exc).__name__}: {exc}"
        try:
            write_json(json_path, report_data)
        except OSError:
            # The primary JSON is already saved atomically. Failure to add an
            # auxiliary diagnostic must not turn that success into a report error.
            pass
    return report_path
