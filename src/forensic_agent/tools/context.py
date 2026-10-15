from dataclasses import dataclass
import json
import os
from pathlib import Path

from ..evidence.paths import local_path, within
from ..evidence.store import sha256_file, utc_now
from ..models import Source, ToolRecord
from ..settings import Settings
from .process import capture, clean_environment


@dataclass
class Context:
    settings: Settings
    sources: list[Source]
    step_dir: Path
    command_number: int = 0
    reference: ToolRecord | None = None

    def files(self):
        return [item for item in self.sources if item.kind == "file"]

    def external(self, key: str, arguments: list[str], *, artifact_root: Path | None = None):
        executable = getattr(self.settings.tools, key)
        if not executable:
            raise FileNotFoundError(f"未配置工具：{key}")
        executable = str(local_path(executable))
        if Path(executable).suffix.lower() != ".exe":
            raise ValueError("外部工具必须为已配置的 .exe")
        argv = [executable, *arguments]
        if artifact_root is not None:
            artifact_root = local_path(artifact_root)
            if not within(artifact_root, self.step_dir):
                raise ValueError("工具产物目录必须位于当前步骤目录")
        self.command_number += 1
        stem = f"external-{self.command_number:03d}"
        started = utc_now()
        env = clean_environment(self.step_dir)
        env["PATH"] = os.pathsep.join([str(Path(executable).parent),
                                      str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32"),
                                      os.environ.get("SystemRoot", "C:/Windows")])
        from ..doctor import VERSION_ARGUMENTS
        version = capture([executable, *VERSION_ARGUMENTS[key]], cwd=self.step_dir, env=env,
                          timeout=5, max_output=65536)
        version_text = (version.stdout + version.stderr).decode("utf-8", errors="replace")[:2000]
        entry = {"argv": argv, "started_utc": started, "state": "started",
                 "version_argv": [executable, *VERSION_ARGUMENTS[key]], "version_output": version_text,
                 "executable_sha256": sha256_file(Path(executable))}
        with (self.step_dir / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
            stream.flush()
        if version.stopped or version.returncode:
            raise RuntimeError("工具版本探测失败或超限，拒绝继续解析检材")
        captured = capture(argv, cwd=self.step_dir, env=env,
                           timeout=self.settings.limits.pcap_timeout_seconds if key == "tshark"
                           else self.settings.limits.timeout_seconds,
                           max_output=self.settings.limits.output_bytes,
                           stdout_path=self.step_dir / f"{stem}.stdout.bin",
                           stderr_path=self.step_dir / f"{stem}.stderr.bin",
                           artifact_root=artifact_root, artifact_bytes=self.settings.limits.output_bytes,
                           reserve_disk_bytes=self.settings.limits.reserve_disk_bytes)
        entry = {**entry, "state": "finished", "finished_utc": utc_now(),
                 "exit_code": captured.returncode, "stopped": captured.stopped,
                 "stdout_path": str(self.step_dir / f"{stem}.stdout.bin"),
                 "stderr_path": str(self.step_dir / f"{stem}.stderr.bin")}
        with (self.step_dir / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
        if captured.stopped:
            raise RuntimeError(f"外部工具被限额中止：{captured.stopped}；原始输出已保存")
        if captured.returncode:
            raise RuntimeError(f"工具退出码 {captured.returncode}: "
                               + captured.stderr.decode("utf-8", errors="replace")[:2000])
        return captured.stdout, captured.stderr
