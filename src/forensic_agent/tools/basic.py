import codecs
import json
from pathlib import Path
import sqlite3
import zipfile

from charset_normalizer import from_bytes

from ..models import ToolRecord, ToolResult


def identify(path: Path) -> str:
    with path.open("rb") as stream:
        head = stream.read(512)
    signatures = [(b"SQLite format 3\x00", "sqlite"), (b"ElfFile\x00", "evtx"),
                  (b"\xd4\xc3\xb2\xa1", "pcap"), (b"\xa1\xb2\xc3\xd4", "pcap"),
                  (b"\x4d\x3c\xb2\xa1", "pcap"), (b"\xa1\xb2\x3c\x4d", "pcap"),
                  (b"\x0a\x0d\x0d\x0a", "pcapng"), (b"\xff\xd8\xff", "jpeg"),
                  (b"\x89PNG\r\n\x1a\n", "png"), (b"GIF87a", "gif"), (b"GIF89a", "gif"),
                  (b"II*\x00", "tiff"), (b"MM\x00*", "tiff"), (b"%PDF-", "pdf"),
                  (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "rar"),
                  (b"\x1f\x8b", "gzip"), (b"MZ", "pe"),
                  (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole")]
    for magic, kind in signatures:
        if head.startswith(magic):
            return kind
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            if "[Content_Types].xml" in names:
                for prefix, kind in (("word/", "docx"), ("xl/", "xlsx"), ("ppt/", "pptx")):
                    if any(name.startswith(prefix) for name in names):
                        return kind
        return "zip"
    if head[257:262] == b"ustar":
        return "tar"
    if head.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE, codecs.BOM_UTF8,
                        codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return "text"
    if not head:
        return "empty"
    if b"\x00" not in head and sum(byte < 32 and byte not in (9, 10, 13) for byte in head) / len(head) < .01:
        return "text"
    return "unknown"


def inventory(ctx, params):
    result = ToolResult()
    for source in ctx.files():
        path = Path(source.working_path)
        name = Path(source.original_path or source.member or path.name).name
        if params.name_contains.casefold() not in name.casefold():
            continue
        if params.extension and path.suffix.casefold() != "." + params.extension.lstrip(".").casefold():
            continue
        if source.size < params.min_size or (params.max_size is not None and source.size > params.max_size):
            continue
        try:
            kind = identify(path)
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            kind = "unknown"
            result.warnings.append(f"{source.id} 类型检查失败：{exc}")
        result.records.append(ToolRecord(source_id=source.id, locator={"kind": "file"},
                                        data={"name": name, "size": source.size, "type": kind,
                                              "extension_hint": path.suffix, "sha256": source.sha256}))
        if len(result.records) >= params.limit:
            result.truncated = True
            result.status = "partial"
            result.warnings.append("文件列表达到展示上限；不能据此证明其余文件不存在")
            break
    return result


def hashes(ctx, params):
    from ..evidence.store import sha256_file
    return ToolResult(records=[ToolRecord(source_id=item.id, locator={"kind": "file"},
                                          data={"sha256": sha256_file(Path(item.working_path)),
                                                "size": item.size}) for item in ctx.files()])


def decode_text(raw: bytes, requested: str):
    if requested != "auto":
        return raw.decode(requested, errors="strict"), requested, "用户指定；严格解码通过"
    for bom, encoding in ((codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
                          (codecs.BOM_UTF8, "utf-8-sig"), (codecs.BOM_UTF16_LE, "utf-16"),
                          (codecs.BOM_UTF16_BE, "utf-16")):
        if raw.startswith(bom):
            return raw.decode(encoding, errors="strict"), encoding, "BOM 标识"
    try:
        return raw.decode("utf-8", errors="strict"), "utf-8", "无 BOM；UTF-8 严格解码通过，编码仍属推断"
    except UnicodeDecodeError:
        pass
    # Chinese Windows competition evidence commonly uses GB18030/GBK. Tiny samples are
    # frequently misclassified as cp949 by statistical detectors; this remains an inference.
    try:
        return raw.decode("gb18030", errors="strict"), "gb18030", "中文 Windows 编码优先推断；严格解码通过，需人工核对"
    except UnicodeDecodeError:
        pass
    best = from_bytes(raw[:65536]).best()
    if best:
        try:
            return raw.decode(best.encoding, errors="strict"), best.encoding, "编码检测推断，需人工核对"
        except (UnicodeDecodeError, LookupError):
            pass
    return raw.decode("gb18030", errors="strict"), "gb18030", "GB18030 严格解码通过，编码仍属推断"


def search(ctx, params):
    result = ToolResult()
    needle = params.keyword if params.case_sensitive else params.keyword.casefold()
    for source in ctx.files():
        path = Path(source.working_path)
        try:
            if source.size > ctx.settings.limits.text_file_bytes:
                result.warnings.append(f"{source.id} 超过文本文件大小上限，未搜索")
                continue
            if params.encoding == "auto" and identify(path) not in {"text", "empty", "unknown"}:
                result.warnings.append(f"{source.id} 是非文本格式，未搜索正文")
                continue
            raw = path.read_bytes()
            if params.encoding == "auto" and b"\x00" in raw[:512] and not raw.startswith(
                    (codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
                result.warnings.append(f"{source.id} 疑似二进制或无 BOM UTF-16；请明确指定编码后搜索")
                continue
            text, encoding, basis = decode_text(raw, params.encoding)
            for line_no, line in enumerate(text.splitlines(), 1):
                haystack = line if params.case_sensitive else line.casefold()
                if needle in haystack:
                    offset = haystack.index(needle)
                    preview = line[max(0, offset - 200):offset + len(needle) + 400]
                    result.records.append(ToolRecord(source_id=source.id,
                        locator={"kind": "text", "line": line_no, "encoding": encoding},
                        data={"keyword": params.keyword, "text": preview, "encoding_basis": basis,
                              "preview_truncated": preview != line}))
                    if len(result.records) >= params.limit:
                        result.status, result.truncated = "partial", True
                        result.warnings.append("命中数达到上限；搜索未完成")
                        return result
        except (UnicodeError, LookupError, ValueError, OSError) as exc:
            result.warnings.append(f"{source.id} 无法搜索：{exc}")
    if result.warnings:
        result.status = "partial"
    return result


def metadata(ctx, params):
    result = ToolResult()
    for source in ctx.files():
        try:
            raw, stderr = ctx.external("exiftool", ["-config", "", "-j", "-G1", "-a", "-s", "-n",
                                                    source.working_path])
            data = json.loads(raw.decode("utf-8-sig"))[0]
            if stderr:
                result.warnings.append(stderr.decode("utf-8", errors="replace")[:1000])
            for field, value in data.items():
                if field == "SourceFile" or field.startswith("System:") or (params.fields and field not in params.fields
                        and field.split(":")[-1] not in params.fields):
                    continue
                result.records.append(ToolRecord(source_id=source.id, locator={"kind": "metadata", "field": field},
                                                data={"field": field, "value": value}))
            for field, value in source.filesystem.items():
                if not params.fields or field in params.fields or "OriginalFS:" + field in params.fields:
                    result.records.append(ToolRecord(source_id=source.id,
                        locator={"kind": "metadata", "field": "OriginalFS:" + field},
                        data={"field": "OriginalFS:" + field, "value": value}))
            if params.fields:
                found_fields = {record.data["field"].split(":")[-1] for record in result.records
                                if record.source_id == source.id}
                missing = [field for field in params.fields if field.split(":")[-1] not in found_fields]
                if missing:
                    result.warnings.append(f"{source.id} 未找到请求字段：{', '.join(missing)}")
            if "ExifTool:Error" in data or "Error" in data:
                result.status = "partial"
                result.warnings.append(f"{source.id} ExifTool 报告解析错误")
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            result.status = "partial"
            result.warnings.append(f"{source.id} 元数据读取失败：{exc}")
    if not result.records and result.warnings:
        result.status = "failed" if any("元数据读取失败" in x for x in result.warnings) else "partial"
    return result


SQL_FUNCTIONS = {"count", "min", "max", "sum", "avg", "total", "lower", "upper", "length", "substr",
                 "substring", "like", "glob", "coalesce", "ifnull", "nullif", "date", "time", "datetime",
                 "julianday", "strftime", "unixepoch", "hex", "quote", "typeof", "abs", "round", "trim",
                 "ltrim", "rtrim", "replace", "instr", "unicode", "char", "group_concat"}


def sql_authorizer(action, arg1, arg2, database, trigger):
    if action in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ}:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in SQL_FUNCTIONS:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def sqlite_query(ctx, params):
    from .sqlite_support import sqlite_query as execute
    return execute(ctx, params)


def evidence_window(ctx, params):
    if ctx.reference is None:
        raise ValueError("证据窗口缺少经程序解析的引用")
    value = ctx.reference.data
    if value["start"] != params.start:
        raise ValueError("证据窗口位置不一致")
    return ToolResult(records=[ToolRecord(source_id=ctx.reference.source_id,
        grounding="exploratory" if ctx.reference.grounding == "exploratory" else "derived",
        locator={"kind": "evidence_window", "parent_evidence_id": params.evidence_id,
                 "parent_field": params.field, "start": params.start, "length": len(value["value"])},
        data={"value": value["value"], "start": params.start, "total_length": value["total_length"],
              "next_start": params.start + len(value["value"]),
              "has_more": params.start + len(value["value"]) < value["total_length"]})])
