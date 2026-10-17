"""Loopback-only browser UI; forensic operations continue through the existing CLI."""

import argparse
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import re
import subprocess
import sys
import threading
from urllib.parse import parse_qs, urlsplit
import webbrowser

from .agent.loop import CONTINUABLE_STATES
from .evidence import Case
from .evidence.paths import local_path, within
from .models import MAX_QUESTION_CHARS, ToolRequest
from .settings import load_settings
from .manual import build_manual_guidance
from .tools.registry import catalog

ASSETS = Path(__file__).with_name("web")


class BusyError(ValueError):
    pass


class Workspace:
    def __init__(self, config=None):
        self.config = Path(config).resolve() if config else None
        self.settings = load_settings(self.config)
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.task = None
        self.worker = None
        self.picker_lock = threading.Lock()

    def case_path(self, identity):
        if not isinstance(identity, str) or not identity or Path(identity).name != identity:
            raise ValueError("案件名称无效，请从历史案件中选择")
        root = local_path(self.settings.work_dir)
        path = local_path(root / identity)
        if path.parent != root or not within(path, root) or not path.is_dir():
            raise ValueError("案件目录越界")
        local_path(path / "case.json")
        return path

    def cases(self):
        root = self.settings.work_dir
        if not root.exists():
            return []
        result = []
        for item in sorted(root.iterdir(), key=lambda p: p.name, reverse=True):
            if len(result) >= 40:
                break
            try:
                path = self.case_path(item.name)
                data = json.loads((path / "case.json").read_text(encoding="utf-8"))
                result.append({"id": item.name, "question": data.get("question") or "直接工具分析",
                                "state": data.get("state", "unknown"), "created": data.get("created_utc", ""),
                                "questions": [{"id": row["id"], "question": row["question"],
                                               "has_report": bool(row.get("report_directory"))}
                                              for row in data.get("question_history", [])],
                                "can_continue": bool(data.get("question") and data.get("root_id")
                                                     and data.get("sources") and data.get("state") in CONTINUABLE_STATES)})
            except (OSError, ValueError):
                continue
        return result

    def report(self, identity, question_id=None):
        directory = self.case_path(identity)
        archived = False
        path = directory / "report.md"
        if question_id is not None:
            if not re.fullmatch(r"q[0-9]{4,}", question_id):
                raise ValueError("题目编号无效")
            manifest = json.loads((directory / "case.json").read_text(encoding="utf-8"))
            if question_id != manifest.get("question_id", "q0001"):
                rows = [row for row in manifest.get("question_history", []) if row["id"] == question_id]
                if len(rows) != 1 or not rows[0].get("report_directory"):
                    raise ValueError("该题目没有已保存报告")
                path = directory / rows[0]["report_directory"] / "report.md"
                archived = True
        path = local_path(path)
        if not within(path, directory):
            raise ValueError("题目报告路径越界")
        if path.stat().st_size > 8 * 1024**2:
            raise ValueError("报告超过 8 MiB，请在案件目录中打开 report.md")
        return {"id": identity, "question_id": question_id, "archived": archived,
                "path": str(path), "text": path.read_text(encoding="utf-8"),
                "saved_at": datetime.fromtimestamp(path.stat().st_mtime).astimezone().isoformat()}

    def manual_guide(self, identity=None):
        # Read manifests only; viewing help never rehashes a large image or runs a tool.
        case = Case(self.case_path(identity), self.settings) if identity is not None else None
        return build_manual_guidance(case, settings=self.settings)

    def bootstrap(self):
        examples = Path.cwd() / "examples" / "检材"
        return {"work_dir": str(self.settings.work_dir), "model": self.settings.model.name,
                "max_question": MAX_QUESTION_CHARS, "tools": catalog(self.settings),
                "sample": str(examples / "线索.txt") if (examples / "线索.txt").is_file() else None,
                "cases": self.cases(), "task": self.snapshot()}

    def command(self, data):
        action = data.get("action")
        args = [sys.executable, "-u", "-m", "forensic_agent"]
        if self.config:
            args += ["--config", str(self.config)]
        if action == "doctor":
            return args + ["doctor"]
        if action == "report":
            return args + ["report", str(self.case_path(data.get("case")))]
        if action in {"continue", "new_question"}:
            mode = data.get("mode", "model")
            if mode not in {"model", "rules"}:
                raise ValueError("继续案件只支持自动规划或规则模式")
            extra = []
            if action == "new_question":
                question = data.get("question")
                if not isinstance(question, str) or not 1 <= len(question.strip()) <= MAX_QUESTION_CHARS:
                    raise ValueError(f"请输入 1..{MAX_QUESTION_CHARS} 字符的新题目；不会截断")
                extra = ["--new-question", question.strip()]
            return args + ["analyze", "--case", str(self.case_path(data.get("case"))), "--progress", *extra] + (
                ["--no-model"] if mode == "rules" else [])
        if action not in {"analyze", "tool"}:
            raise ValueError("请选择分析、直接工具或环境检查")
        evidence = data.get("evidence", "")
        if not isinstance(evidence, str) or not evidence.strip():
            raise ValueError("请先选择检材文件或目录")
        path = local_path(Path(evidence.strip().strip('"')))
        if not path.is_file() and not path.is_dir():
            raise ValueError("检材必须是普通文件或目录")
        work = local_path(self.settings.work_dir, must_exist=False)
        if within(path, work) or within(work, path):
            raise ValueError("检材和案件工作目录不能包含彼此，请缩小检材范围")
        if action == "analyze":
            question = data.get("question", "")
            if not isinstance(question, str) or not 1 <= len(question.strip()) <= MAX_QUESTION_CHARS:
                raise ValueError(f"请输入 1..{MAX_QUESTION_CHARS} 字符的题目；超长题目请拆分")
            mode = data.get("mode", "model")
            if mode not in {"model", "rules"}:
                raise ValueError("分析模式无效")
            return args + ["analyze", "--evidence", str(path), "--question", question.strip(), "--progress"] + (
                ["--no-model"] if mode == "rules" else [])
        params = data.get("params", {})
        request = ToolRequest(tool_id=data.get("tool_id", ""), source_id="s00001", params=params)
        if request.tool_id not in catalog(self.settings):
            raise ValueError("请选择已支持的白名单工具")
        # The CLI/runner validates the adapter-specific parameter schema and discovers installed tools.
        return args + ["tool", request.tool_id, "--evidence", str(path),
                       "--params", json.dumps(request.params, ensure_ascii=False)]

    def start(self, data):
        args = self.command(data)
        with self.lock:
            if self.task and self.task["status"] == "running":
                raise BusyError("已有任务正在执行，请等待完成后再开始")
            self.task = {"id": secrets.token_hex(8), "action": data["action"], "status": "running",
                         "started": datetime.now().astimezone().isoformat(), "logs": deque(maxlen=160),
                         "result": None, "case": None, "error": None}
            if data["action"] in {"continue", "new_question"}:
                self.task["logs"].append("正在核验原件、已有副本和既有工具输出；通过后继续分析，不复制检材。")
            elif data["action"] in {"analyze", "tool"}:
                self.task["logs"].append("任务已开始；登记检材、复制和哈希核对可能需要一些时间。")
            else:
                self.task["logs"].append("任务已开始。")
            self.worker = threading.Thread(target=self._run, args=(args,), name="forensic-gui-task")
            self.worker.start()
        return self.snapshot()

    def snapshot(self):
        with self.lock:
            return {**self.task, "logs": list(self.task["logs"])} if self.task else None

    def _event(self, value):
        with self.lock:
            if "progress" in value:
                text = str(value["progress"])
                event = value.get("progress_event")
                if isinstance(event, dict) and isinstance(event.get("details"), dict):
                    copied = event.get("copy_bytes")
                    if isinstance(copied, int) and copied:
                        text += f"；已复制 {copied:,} 字节"
                self.task["logs"].append(text)
            else:
                self.task["result"] = value
                if value.get("case"):
                    path = Path(value["case"])
                    self.task["case"] = path.name
                elif value.get("report"):
                    self.task["case"] = Path(value["report"]).parent.name

    def _run(self, args):
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            decoder, pending, received = json.JSONDecoder(), "", 0
            with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, encoding="utf-8", errors="replace", creationflags=flags) as process:
                for line in process.stdout:
                    received += len(line)
                    if received > 2 * 1024**2:
                        # Keep draining stdout so a noisy child cannot deadlock on its pipe.
                        continue
                    pending += line
                    while pending.strip():
                        pending = pending.lstrip()
                        try:
                            value, end = decoder.raw_decode(pending)
                        except json.JSONDecodeError:
                            break
                        if isinstance(value, dict):
                            self._event(value)
                        pending = pending[end:]
                code = process.wait()
            with self.lock:
                result = self.task["result"] or {}
                self.task["status"] = "completed" if code == 0 else "failed"
                self.task["exit_code"] = code
                if code != 0:
                    self.task["error"] = (result.get("error") or
                                          "任务未正常完成，请查看报告中的状态、警告与不确定性。")
                if pending.strip():
                    self.task["logs"].append(pending[-4000:])
                self.task["logs"].append("任务完成。" if code == 0 else f"任务结束，退出码 {code}。")
        except Exception as exc:
            with self.lock:
                self.task["status"] = "failed"
                self.task["error"] = f"{type(exc).__name__}: {exc}"

    def pick(self, kind):
        if kind not in {"file", "directory"}:
            raise ValueError("选择类型无效")
        if not self.picker_lock.acquire(blocking=False):
            raise BusyError("文件选择窗口已打开，请先完成选择")
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            result = subprocess.run([sys.executable, "-m", "forensic_agent.gui_picker", kind],
                                    capture_output=True, text=True, encoding="utf-8", errors="replace",
                                    creationflags=flags, timeout=300)
            if result.returncode:
                raise ValueError("无法打开文件选择窗口，请直接粘贴本地绝对路径")
            return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            raise ValueError("文件选择未完成，请重试或直接粘贴路径") from exc
        finally:
            self.picker_lock.release()


class LocalServer(ThreadingHTTPServer):
    def __init__(self, workspace, port=0):
        super().__init__(("127.0.0.1", port), Handler)
        self.workspace = workspace
        self.origin = f"http://127.0.0.1:{self.server_port}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # No paths, evidence text or session tokens in request logs.

    def reply(self, status, value, content_type="application/json; charset=utf-8", download=False):
        body = json.dumps(value, ensure_ascii=False).encode("utf-8") if isinstance(value, (dict, list)) else value
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; "
                         "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
                         "form-action 'self'; object-src 'none'")
        if download:
            self.send_header("Content-Disposition", 'attachment; filename="report.md"')
        self.end_headers()
        self.wfile.write(body)

    def allowed(self, api=False):
        origin = self.server.origin
        if self.headers.get("Host") != origin.removeprefix("http://"):
            return False
        if self.headers.get("Origin") not in {None, origin}:
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            return False
        return not api or secrets.compare_digest(self.headers.get("X-Session-Token", ""),
                                                self.server.workspace.token)

    def do_GET(self):
        target = urlsplit(self.path)
        if not self.allowed(target.path.startswith("/api/")):
            return self.reply(403, {"error": "本地会话无效，请刷新界面"})
        workspace = self.server.workspace
        try:
            if target.path == "/":
                body = (ASSETS / "index.html").read_text(encoding="utf-8").replace("__SESSION_TOKEN__", workspace.token)
                return self.reply(200, body.encode("utf-8"), "text/html; charset=utf-8")
            if target.path in {"/app.css", "/app.js"}:
                content_type = "text/css" if target.path.endswith("css") else "text/javascript"
                return self.reply(200, (ASSETS / target.path[1:]).read_bytes(), content_type + "; charset=utf-8")
            if target.path == "/api/bootstrap":
                return self.reply(200, workspace.bootstrap())
            if target.path == "/api/task":
                return self.reply(200, {"task": workspace.snapshot()})
            if target.path == "/api/cases":
                return self.reply(200, {"cases": workspace.cases()})
            if target.path == "/api/report":
                query = parse_qs(target.query)
                return self.reply(200, workspace.report(query.get("case", [""])[0],
                                                        query.get("question", [None])[0]))
            if target.path == "/api/manual-guide":
                identity = parse_qs(target.query).get("case", [None])[0]
                return self.reply(200, workspace.manual_guide(identity))
            return self.reply(404, {"error": "页面不存在"})
        except (OSError, ValueError) as exc:
            return self.reply(400, {"error": str(exc)})

    def do_POST(self):
        if not self.allowed(api=True):
            return self.reply(403, {"error": "本地会话无效，请刷新界面"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                return self.reply(413, {"error": "请求过大或为空"})
            if self.headers.get_content_type() != "application/json":
                return self.reply(415, {"error": "请求必须使用 JSON"})
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError("请求应为 JSON 对象")
            workspace = self.server.workspace
            if self.path == "/api/start":
                return self.reply(202, {"task": workspace.start(data)})
            if self.path == "/api/pick":
                return self.reply(200, workspace.pick(data.get("kind")))
            if self.path == "/api/shutdown":
                with workspace.lock:
                    if workspace.task and workspace.task["status"] == "running":
                        raise BusyError("请等待当前任务结束后再退出服务")
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return self.reply(200, {"message": "本地服务已退出，可以关闭页面"})
            return self.reply(404, {"error": "操作不存在"})
        except BusyError as exc:
            return self.reply(409, {"error": str(exc)})
        except (OSError, ValueError, TypeError) as exc:
            return self.reply(400, {"error": str(exc)})


def main(argv=None):
    parser = argparse.ArgumentParser(description="Forensic Agent 本地浏览器界面")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--port", type=int, default=0, help="默认自动选择空闲本地端口")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)
    workspace = Workspace(args.config)
    server = LocalServer(workspace, args.port)
    print(f"Forensic Agent GUI: {server.origin}", flush=True)
    if not args.no_browser:
        webbrowser.open(server.origin)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print("正在退出；等待当前取证任务保存结果。", flush=True)
    finally:
        server.server_close()
        if workspace.worker:
            workspace.worker.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
