from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import uuid

from ..models import MAX_QUESTION_CHARS, Source
from ..settings import Settings
from .paths import is_reparse, local_path, within


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
    os.replace(temporary, path)


SQLITE_SUFFIXES = ("-wal", "-shm", "-journal")


def is_sqlite(path: Path):
    with path.open("rb") as stream:
        return stream.read(16) == b"SQLite format 3\x00"


class Case:
    def __init__(self, directory: Path, settings: Settings):
        self.directory = local_path(directory)
        self.settings = settings
        self.manifest = json.loads((directory / "case.json").read_text(encoding="utf-8"))
        self.sources = {x["id"]: Source.model_validate(x) for x in self.manifest["sources"]}

    @classmethod
    def create(cls, evidence: Path, settings: Settings, question: str = ""):
        if len(question) > MAX_QUESTION_CHARS:
            raise ValueError(f"题目最多 {MAX_QUESTION_CHARS} 字符，请拆分题目；不会截断尾部约束")
        source = local_path(evidence)
        if not source.is_file() and not source.is_dir():
            raise ValueError("检材必须为普通文件或目录")
        work = local_path(settings.work_dir, must_exist=False)
        if within(source, work) or within(work, source):
            raise ValueError("工作目录与原件不能包含彼此")
        work.mkdir(parents=True, exist_ok=True)
        case_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
        directory = work / case_id
        directory.mkdir()
        (directory / "snapshots").mkdir()
        (directory / "steps").mkdir()
        manifest = {"schema_version": 1, "case_id": case_id, "created_utc": utc_now(),
                    "question": question, "root_id": "s00001", "sources": [], "steps": [],
                    "warnings": [], "answers": [], "state": "intake", "settings": settings.model_dump(mode="json")}
        write_json(directory / "case.json", manifest)
        case = cls(directory, settings)
        try:
            case._snapshot(source)
            issues = case.verify_originals()
            if issues:
                raise ValueError("检材在复制期间变化或不可复核：" + "; ".join(issues))
            case.manifest["state"] = "ready"
            case.save()
            return case
        except BaseException as exc:
            case.manifest["state"] = "intake_failed"
            case.manifest["warnings"].append(f"检材登记失败：{type(exc).__name__}: {exc}")
            case.save()
            exc.case_directory = str(directory)
            raise

    def _snapshot(self, source: Path):
        total = 0
        files = []
        if source.is_dir():
            self._add_source(source, self.directory / "snapshots" / "root", "directory")
            root = self.directory / "snapshots" / "root"
            root.mkdir()
            for current, dirs, names in os.walk(source, followlinks=False):
                current = Path(current)
                skipped = [name for name in dirs if is_reparse(current / name)]
                for name in skipped:
                    self.manifest["warnings"].append(f"跳过重解析点：{current / name}")
                dirs[:] = sorted(name for name in dirs if name not in skipped)
                for name in sorted(names):
                    original = current / name
                    if is_reparse(original):
                        self.manifest["warnings"].append(f"跳过链接：{original}")
                        continue
                    if not original.is_file():
                        self.manifest["warnings"].append(f"跳过非普通文件：{original}")
                        continue
                    files.append((original, root / original.relative_to(source), "s00001"))
                    if len(files) > self.settings.limits.max_files:
                        raise ValueError("检材文件数超过配置上限")
        else:
            files.append((source, self.directory / "snapshots" / "root" / source.name, None))
            with source.open("rb") as stream:
                sqlite = stream.read(16) == b"SQLite format 3\x00"
            if sqlite:
                for suffix in SQLITE_SUFFIXES:
                    companion = source.with_name(source.name + suffix)
                    if companion.exists():
                        local_path(companion)
                        files.append((companion, files[0][1].with_name(companion.name), "s00001"))
        for original, target, parent in files:
            size = original.stat().st_size
            total += size
            if total > self.settings.limits.snapshot_bytes:
                raise ValueError("检材副本总量超过配置上限；未退回直接分析原件")
            if shutil.disk_usage(self.directory).free < size + self.settings.limits.reserve_disk_bytes:
                raise OSError("工作磁盘空间不足，停止复制")
            original = local_path(original)
            target.parent.mkdir(parents=True, exist_ok=True)
            before = original.stat()
            digest = hashlib.sha256()
            count = 0
            with original.open("rb") as src, target.open("xb") as dst:
                while chunk := src.read(1024 * 1024):
                    count += len(chunk)
                    if count > size or shutil.disk_usage(self.directory).free < self.settings.limits.reserve_disk_bytes:
                        raise OSError("源文件增长或工作磁盘余量不足")
                    digest.update(chunk)
                    dst.write(chunk)
            after = original.stat()
            if count != size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError(f"复制期间源文件变化：{original}")
            actual = digest.hexdigest()
            if sha256_file(target) != actual:
                raise OSError(f"副本哈希验证失败：{target}")
            item = self._add_source(original, target, "file", actual, size, parent)
            item.filesystem = {"OriginalName": original.name, "OriginalDirectory": str(original.parent),
                               "ModifyTimeUtc": datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat(),
                               "AccessTimeUtcAtIntake": datetime.fromtimestamp(before.st_atime, timezone.utc).isoformat(),
                               "Size": before.st_size}
            if hasattr(before, "st_birthtime"):
                item.filesystem["CreateTimeUtc"] = datetime.fromtimestamp(before.st_birthtime, timezone.utc).isoformat()
            self.save()

    def _add_source(self, original, working, kind, digest=None, size=0, parent=None, member=None):
        source_id = f"s{len(self.sources) + 1:05d}"
        item = Source(id=source_id, original_path=str(original) if original else None,
                      working_path=str(working), kind=kind, sha256=digest, size=size,
                      parent_id=parent, member=member)
        self.sources[source_id] = item
        return item

    def save(self):
        self.manifest["sources"] = [x.model_dump() for x in self.sources.values()]
        write_json(self.directory / "case.json", self.manifest)

    def select(self, source_id: str):
        if source_id not in self.sources:
            raise ValueError("未知检材 ID")
        target = self.sources[source_id]
        if target.kind == "file":
            return [target]
        root = local_path(target.working_path)
        return [item for item in self.sources.values()
                if item.kind == "file" and within(Path(item.working_path), root)]

    def verify_originals(self, source_ids: list[str] | None = None):
        issues = []
        items = self.sources.values() if source_ids is None else [self.sources[x] for x in source_ids]
        for item in items:
            if item.original_path and item.kind == "file" and item.sha256:
                try:
                    path = local_path(item.original_path)
                    if sha256_file(path) != item.sha256:
                        issues.append(f"原件内容变化：{item.id} {item.original_path}")
                except (OSError, ValueError) as exc:
                    issues.append(f"原件无法复核：{item.id}: {exc}")
        try:
            self.sqlite_bundles(list(items), original=True)
        except (OSError, ValueError) as exc:
            issues.append(f"原件 SQLite 文件集合变化：{exc}")
        return issues

    def sqlite_bundles(self, sources, *, original=False):
        """Validate presence of the complete registered companion set, including absences."""
        attribute = "original_path" if original else "working_path"
        registered = {Path(getattr(item, attribute)): item for item in self.sources.values()
                      if item.kind == "file" and getattr(item, attribute)}
        bundles = {}
        for source in sources:
            if source.kind != "file" or (original and not source.original_path):
                continue
            if not is_sqlite(local_path(Path(getattr(source, attribute)))):
                continue
            path = Path(getattr(source, attribute))
            bundle = [source]
            for suffix in SQLITE_SUFFIXES:
                companion = path.with_name(path.name + suffix)
                item = registered.get(companion)
                present = companion.exists() or companion.is_symlink()
                if present and item is None:
                    raise ValueError(f"未登记的 SQLite 伴随文件：{companion}")
                if item is not None and not present:
                    raise ValueError(f"已登记 SQLite 伴随文件缺失：{companion}")
                if present:
                    local_path(companion)
                    bundle.append(item)
            bundles[source.id] = bundle
        return bundles

    def expand_sqlite_sources(self, sources):
        bundles = self.sqlite_bundles(sources)
        expanded = {item.id: item for item in sources}
        for bundle in bundles.values():
            expanded.update({item.id: item for item in bundle})
        return list(expanded.values())

    def verify_current(self):
        issues = self.verify_originals()
        for source in self.sources.values():
            if source.kind != "file":
                continue
            try:
                path = local_path(source.working_path)
                if not within(path, self.directory) or sha256_file(path) != source.sha256:
                    issues.append(f"工作副本内容变化或越界：{source.id}")
            except (OSError, ValueError) as exc:
                issues.append(f"工作副本无法复核：{source.id}: {exc}")
        try:
            self.sqlite_bundles(list(self.sources.values()))
        except (OSError, ValueError) as exc:
            issues.append(f"工作 SQLite 文件集合变化：{exc}")
        for step in self.manifest["steps"]:
            for name, expected in step.get("output_hashes", {}).items():
                try:
                    path = local_path(self.directory / name)
                    if not within(path, self.directory) or sha256_file(path) != expected:
                        issues.append(f"原始工具输出变化或越界：{name}")
                except (OSError, ValueError) as exc:
                    issues.append(f"原始工具输出无法复核：{name}: {exc}")
        return list(dict.fromkeys(issues))

    def invalidate_answers(self, reason):
        if self.manifest.get("answers"):
            self.manifest.setdefault("historical_answers", []).append({"invalidated_utc": utc_now(),
                "reason": reason, "answers": self.manifest["answers"]})
            self.manifest["answers"] = []

    def record_integrity(self, stage):
        check = {"stage": stage, "verified_utc": utc_now(), "issues": self.verify_current()}
        self.manifest.setdefault("integrity_checks", []).append(check)
        if check["issues"]:
            self.invalidate_answers("当前完整性复核未通过")
            self.manifest["state"] = "evidence_changed"
            self.manifest["warnings"] = list(dict.fromkeys([*self.manifest["warnings"], *check["issues"]]))
        self.save()
        return check

    def add_artifact(self, path: Path, parent_id: str, member: str, step_dir: Path):
        path = local_path(path)
        if not within(path, local_path(step_dir)) or not path.is_file() or parent_id not in self.sources:
            raise ValueError("派生产物越界或父证据不存在")
        return self._add_source(None, path, "file", sha256_file(path), path.stat().st_size, parent_id, member)
