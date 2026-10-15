import gzip
from pathlib import Path
import shutil
import stat
import tarfile
import zipfile

from ..evidence.paths import safe_member
from ..models import Artifact, ToolRecord, ToolResult
from .basic import identify


def member_path(name, directory=False, *, tar=False):
    """Accept TAR's conventional leading dot prefix without collapsing traversal."""
    if tar:
        if not name:
            return safe_member(name)
        name = name.replace("\\", "/")
        while name.startswith("./"):
            name = name[2:]
        if name in ("", "."):
            if directory:
                return Path(".")
            raise ValueError("TAR 根目录成员必须是目录")
    return safe_member(name)


def check_members(members, limits, archive_size, *, tar=False):
    if len(members) > limits.archive_members:
        raise ValueError("压缩成员数超过上限")
    seen = {}
    total = 0
    for name, size, compressed, directory, linked in members:
        path = member_path(name, directory, tar=tar)
        key = path.as_posix().casefold()
        if linked:
            raise ValueError(f"禁止链接、特殊或稀疏成员：{name!r}")
        if key in seen:
            raise ValueError(f"成员名称发生 Windows 大小写冲突：{name!r}")
        for parent in path.parents:
            parent_key = parent.as_posix().casefold()
            if parent_key in seen and not seen[parent_key]:
                raise ValueError("文件与目录成员冲突")
        if not directory and any(existing.startswith(key + "/") for existing in seen):
            raise ValueError("文件与子路径冲突")
        seen[key] = directory
        if size < 0 or size > limits.archive_member_bytes:
            raise ValueError(f"成员大小超过上限：{name!r}")
        if size and compressed is not None and size / max(1, compressed) > limits.archive_ratio:
            raise ValueError(f"成员压缩比超过上限：{name!r}")
        total += size
        if total > limits.archive_total_bytes:
            raise ValueError("压缩包声明的总解包量超过上限")
    if total / max(1, archive_size) > limits.archive_ratio:
        raise ValueError("压缩包总压缩比超过上限")


def copy_member(stream, target, source, ctx, state):
    target.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with target.open("xb") as output:
        while chunk := stream.read(65536):
            written += len(chunk)
            state[0] += len(chunk)
            limits = ctx.settings.limits
            if (written > limits.archive_member_bytes or state[0] > limits.archive_total_bytes
                    or state[0] / max(1, source.size) > limits.archive_ratio):
                raise ValueError("实际解包量或压缩比超过上限")
            if shutil.disk_usage(ctx.step_dir).free < limits.reserve_disk_bytes + len(chunk):
                raise OSError("解包磁盘空间不足")
            output.write(chunk)


def archive(ctx, params):
    result = ToolResult()
    for source in ctx.files():
        path = Path(source.working_path)
        kind = identify(path)
        if kind not in {"zip", "tar", "gzip", "7z", "rar", "docx", "xlsx", "pptx"}:
            continue
        if kind in {"7z", "rar"}:
            if params.action == "extract":
                result.status = "unsupported"
                result.warnings.append(f"{source.id} 第一版只列出 {kind} 清单，不解包")
                continue
            raw, _ = ctx.external("seven_zip", ["l", "-slt", "-ba", "-sccUTF-8", "--", str(path)])
            entries = raw.decode("utf-8-sig", errors="strict").replace("\r\n", "\n").split("\n\n")
            for entry in entries:
                fields = dict(line.split(" = ", 1) for line in entry.splitlines() if " = " in line)
                if "Path" not in fields:
                    continue
                try:
                    safe_member(fields["Path"])
                    safe = True
                except ValueError:
                    safe = False
                result.records.append(ToolRecord(source_id=source.id,
                    locator={"kind": "archive", "member": fields["Path"]}, data={**fields, "safe_path": safe}))
                if len(result.records) >= ctx.settings.limits.archive_members:
                    result.status, result.truncated = "partial", True
                    return result
            continue
        output_dir = ctx.step_dir / "extracted" / source.id
        state = [0]
        try:
            if kind in {"zip", "docx", "xlsx", "pptx"}:
                with zipfile.ZipFile(path) as package:
                    infos = package.infolist()
                    members = [(x.filename, x.file_size, x.compress_size, x.is_dir(),
                                stat.S_IFMT(x.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR))
                               for x in infos]
                    if any(x.flag_bits & 1 for x in infos) and params.action == "extract":
                        raise ValueError("第一版不解包加密 ZIP")
                    if params.action == "extract":
                        check_members(members, ctx.settings.limits, source.size)
                    for info, member in zip(infos, members):
                        add_listing(result, source.id, member)
                        if len(result.records) > ctx.settings.limits.archive_members:
                            raise ValueError("成员数超过上限")
                        if params.action == "extract" and not info.is_dir():
                            target = output_dir / safe_member(info.filename)
                            with package.open(info, "r") as stream:
                                copy_member(stream, target, source, ctx, state)
                            result.artifacts.append(Artifact(path=str(target), parent_id=source.id,
                                                             member=info.filename))
            elif kind == "tar":
                with tarfile.open(path, "r:") as package:
                    infos = []
                    for info in package:
                        infos.append(info)
                        if len(infos) > ctx.settings.limits.archive_members:
                            raise ValueError("成员数超过上限")
                    members = [(x.name, x.size, None, x.isdir(),
                                not (x.isfile() or x.isdir()) or bool(x.sparse)) for x in infos]
                    if params.action == "extract":
                        check_members(members, ctx.settings.limits, source.size, tar=True)
                    for info, member in zip(infos, members):
                        add_listing(result, source.id, member, tar=True)
                        if params.action == "extract" and info.isfile():
                            target = output_dir / member_path(info.name, tar=True)
                            with package.extractfile(info) as stream:
                                copy_member(stream, target, source, ctx, state)
                            result.artifacts.append(Artifact(path=str(target), parent_id=source.id, member=info.name))
            else:
                name = path.name[:-3] if path.name.lower().endswith(".gz") else path.name + ".decoded"
                member = (name, 0, source.size, False, False)
                add_listing(result, source.id, member)
                result.warnings.append("GZIP 清单不宣称已知未压缩大小；解包时按实际字节限制")
                if params.action == "extract":
                    target = output_dir / safe_member(name)
                    with gzip.open(path, "rb") as stream:
                        copy_member(stream, target, source, ctx, state)
                    result.artifacts.append(Artifact(path=str(target), parent_id=source.id, member=name))
        except (OSError, ValueError, EOFError, zipfile.BadZipFile, tarfile.TarError) as exc:
            result.status = "partial" if result.artifacts else "blocked"
            result.warnings.append(f"{source.id} 压缩包操作停止：{exc}；未完成文件不能作为完整提取结果")
    if not result.records and not result.warnings:
        result.status = "unsupported"
        result.warnings.append("未识别到支持的压缩格式")
    return result


def add_listing(result, source_id, member, *, tar=False):
    name, size, compressed, directory, linked = member
    try:
        member_path(name, directory, tar=tar)
        safe = not linked
    except ValueError:
        safe = False
    result.records.append(ToolRecord(source_id=source_id, locator={"kind": "archive", "member": name},
        data={"member": name, "declared_size": size, "compressed_size": compressed,
              "directory": directory, "safe_path": safe}))
