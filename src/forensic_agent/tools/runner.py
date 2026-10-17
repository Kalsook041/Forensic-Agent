import json
import importlib.metadata
from pathlib import Path
import sqlite3
import sys

from .. import __version__
from ..evidence.paths import local_path, within
from ..evidence.store import sha256_file, utc_now, write_json
from ..evidence.values import evidence_value, supports_answer
from ..models import ToolRequest, ToolResult
from .process import WindowsJob, capture, clean_environment
from .registry import validate_request


def run_tool(case, request: ToolRequest):
    step_id = f"step{len(case.manifest['steps']) + 1:04d}"
    directory = case.directory / "steps" / step_id
    directory.mkdir()
    step = {"id": step_id, "request": request.model_dump(), "started_utc": utc_now(), "state": "running",
            "raw_output_path": str(directory / "worker.stdout.bin"), "evidence": []}
    step["runtime_versions"] = {"python": sys.version, "sqlite": sqlite3.sqlite_version,
                                "forensic_agent": __version__, **{name: importlib.metadata.version(name)
                                for name in ("pydantic", "charset-normalizer", "python-evtx", "defusedxml")}}
    case.manifest["steps"].append(step)
    case.save()
    job = None
    cancelled = False
    try:
        adapter, params = validate_request(request)
        sources = case.select(request.source_id)
        if request.tool_id == "sqlite":
            sources = case.expand_sqlite_sources(sources)
        reference = None
        if request.tool_id == "evidence_window":
            found = [(step, row) for step in case.manifest["steps"] for row in step["evidence"]
                     if row["id"] == params.evidence_id]
            if len(found) != 1:
                raise ValueError("证据窗口引用不存在或不唯一")
            previous, row = found[0]
            if previous["result"]["status"] not in {"ok", "partial"} or previous["integrity"]["issues"]:
                raise ValueError("不能读取失败或不稳定的证据作为窗口")
            if row["source_id"] not in {source.id for source in sources}:
                raise ValueError("证据窗口来源不在本次授权范围")
            value = evidence_value(row["data"], params.field)
            if not isinstance(value, str) or params.start > len(value):
                raise ValueError("证据窗口只接收文本字段和有效字符位置")
            sources = [case.sources[row["source_id"]]]
            reference = {"source_id": row["source_id"], "locator": row["locator"],
                "grounding": row.get("grounding", "evidence") if supports_answer(previous, row) else "exploratory",
                "data": {"value": value[params.start:params.start + params.length],
                         "total_length": len(value), "start": params.start}}
        with case.phase("tool_verify_before", tool_id=request.tool_id, source_id=request.source_id):
            for source in sources:
                path = local_path(source.working_path)
                if not within(path, case.directory) or sha256_file(path) != source.sha256:
                    raise ValueError(f"工作副本越界或内容发生变化：{source.id}")
        if adapter.external_tool and not Path(getattr(case.settings.tools, adapter.external_tool)).is_file():
            raise FileNotFoundError(f"缺少工具：{adapter.external_tool}")
        payload = {"request": request.model_copy(update={"params": params.model_dump()}).model_dump(),
                   "settings": case.settings.model_dump(mode="json"),
                   "sources": [x.model_dump() for x in sources], "step_dir": str(directory), "reference": reference}
        step["execution_limits"] = case.settings.limits.model_dump()
        timeout = case.settings.limits.pcap_timeout_seconds if request.tool_id == "pcap" else case.settings.limits.timeout_seconds
        job = WindowsJob(case.settings.limits)
        argv = [sys.executable, "-I", "-m", "forensic_agent.worker"]
        step["worker_argv"] = argv
        case.save()
        with case.phase("tool_execute", tool_id=request.tool_id, source_id=request.source_id):
            captured = capture(argv, cwd=directory, env=clean_environment(directory), timeout=timeout,
                               max_output=case.settings.limits.output_bytes, job=job,
                               input_bytes=json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n",
                               stdout_path=directory / "worker.stdout.bin", stderr_path=directory / "worker.stderr.bin")
        step["worker_exit_code"] = captured.returncode
        if captured.stopped or captured.returncode:
            result = ToolResult(status="failed", truncated=bool(captured.stopped),
                                error=f"工作进程被中止或异常退出：{captured.stopped or captured.returncode}")
        else:
            result = ToolResult.model_validate_json(captured.stdout)
        allowed = {x.id for x in sources}
        if any(record.source_id not in allowed for record in result.records):
            raise ValueError("工具返回未授权的来源 ID")
        for artifact in result.artifacts:
            if artifact.parent_id not in allowed:
                raise ValueError("工具返回未授权的派生父来源")
            added = case.add_artifact(Path(artifact.path), artifact.parent_id, artifact.member, directory)
            step.setdefault("derived_source_ids", []).append(added.id)
        for index, record in enumerate(result.records, 1):
            step["evidence"].append({"id": f"{step_id}:r{index:05d}", **record.model_dump(),
                                     "raw_output_path": step["raw_output_path"]})
    except KeyboardInterrupt:
        cancelled = True
        result = ToolResult(status="failed", error="用户取消；已终止工作进程树")
    except Exception as exc:
        result = ToolResult(status="blocked", error=f"{type(exc).__name__}: {exc}")
    finally:
        if job:
            job.close()
    try:
        with case.phase("tool_verify_after", tool_id=request.tool_id, source_id=request.source_id):
            integrity = case.verify_current()
    except KeyboardInterrupt:
        cancelled = True
        integrity = ["用户中断了原件哈希复核，完整性未验证；不等同于已确认原件变化"]
        result.status = "failed"
        result.error = "用户取消完整性复核"
    if integrity:
        result.status = "failed"
        result.warnings.extend(integrity)
        case.manifest["warnings"].extend(integrity)
        case.manifest["state"] = "verification_interrupted" if cancelled else "evidence_changed"
        case.invalidate_answers("工具结束时完整性检查未通过")
    step["integrity"] = {"verified_utc": utc_now(), "issues": integrity}
    step["result"] = result.model_dump()
    step["state"] = "finished"
    step["finished_utc"] = utc_now()
    output_files = [*directory.glob("*.stdout.bin"), *directory.glob("*.stderr.bin")]
    output_files += [directory / "commands.jsonl"] if (directory / "commands.jsonl").is_file() else []
    output_files += [Path(row["locator"]["json_path"]) for row in step["evidence"] if "json_path" in row["locator"]]
    step["output_hashes"] = {}
    try:
        with case.phase("hash_output", tool_id=request.tool_id, source_id=request.source_id):
            for output in dict.fromkeys(output_files):
                path = local_path(output)
                if not within(path, directory):
                    raise ValueError("原始输出路径越界")
                step["output_hashes"][str(path.relative_to(case.directory))] = sha256_file(path)
    except (OSError, ValueError) as exc:
        result.status = "failed"
        result.warnings.append(f"原始工具输出摘要记录失败：{exc}")
        step["result"] = result.model_dump()
        case.invalidate_answers("原始输出无法核验")
    write_json(directory / "result.json", step)
    with (case.directory / "operations.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(step, ensure_ascii=False) + "\n")
    case.save()
    if cancelled:
        raise KeyboardInterrupt
    return step
