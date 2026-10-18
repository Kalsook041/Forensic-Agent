"""Fixed single-source EZTools exports; no shell, sync, VSS or arbitrary maps."""
import csv
import io
import json
from pathlib import Path
import re
import shutil

from ..evidence.paths import local_path, within
from ..evidence.store import sha256_file, write_json
from ..models import ToolRecord, ToolResult


def single_source(ctx):
    files = ctx.files()
    if getattr(ctx, 'input_root', None) is not None or len(files) != 1:
        raise ValueError("每次只接收一个已登记文件来源；请先选择具体文件 ID")
    return files[0]


def export(ctx, params, tool):
    source = single_source(ctx)
    path = Path(source.working_path)
    with path.open('rb') as stream:
        header = stream.read(32)
    valid = {'pecmd': header[:3] == b'MAM' or header[4:8] == b'SCCA',
             'mftecmd': header[:4] == b'FILE', 'recmd': header[:4] == b'regf',
             'sqlecmd': header.startswith(b'SQLite format 3\x00')}
    if not valid[tool]:
        return ToolResult(status='unsupported', error='文件头不适用：PECmd需Prefetch、MFTECmd本版仅MFT、RECmd需hive、SQLECmd需SQLite')
    if tool == 'sqlecmd' and header[18:20] != b'\x01\x01':
        return ToolResult(status='blocked', error='SQLite处于WAL模式；先提供关闭并checkpoint的完整数据库')
    if tool == 'recmd' and header[4:8] != header[8:12]:
        return ToolResult(status='blocked', error='注册表hive为dirty状态；请先人工重放事务日志并保留来源，不绕过日志检查')
    output = ctx.step_dir / 'export'
    output.mkdir()
    arguments = ['-f', str(path), '--csv', str(output)]
    if tool != 'sqlecmd':
        arguments += ['--csvf', 'records.csv']
    if tool == 'recmd':
        batch = local_path(Path(ctx.settings.tools.recmd).parent / 'BatchExamples' / 'BasicSystemInfo.reb')
        snapshot = output / 'BasicSystemInfo.reb'
        shutil.copyfile(batch, snapshot)
        write_json(output / 'support-files.json', {str(batch): sha256_file(snapshot)})
        arguments += ['--bn', str(snapshot)]
    if tool == 'sqlecmd':
        maps = local_path(Path(ctx.settings.tools.sqlecmd).parent / 'Maps')
        files = sorted(maps.rglob('*.smap'))
        if not files:
            raise ValueError('未安装SQLECmd Maps；不会下载或猜测SQL')
        snapshot = output / 'maps'
        snapshot.mkdir()
        support = {}
        total = 0
        if len(files) > ctx.settings.limits.max_files:
            raise ValueError('Maps数量超过限额')
        for item in files:
            item = local_path(item)
            total += item.stat().st_size
            if total > ctx.settings.limits.output_bytes:
                raise ValueError('Maps超过输出限额')
            target = snapshot / item.name
            if target.exists():
                raise ValueError('Maps同名冲突')
            shutil.copyfile(item, target)
            support[str(item)] = sha256_file(target)
        write_json(output / 'support-files.json', support)
        arguments += ['--maps', str(snapshot), '--noblob']
    stdout, stderr = ctx.external(tool, arguments, artifact_root=output)
    log = (stdout + stderr).decode('utf-8', errors='replace')
    result = ToolResult(warnings=['时间字段和CSV字段保留工具原始字符串；空值不能当未发生。'])
    if tool == 'sqlecmd':
        result.warnings.append('Maps可能转换时间（含localtime）；按保存的映射核对时区，不能当作检材原始时间字符串。')
    if re.search(r'\b(error|failed|exception|unable)\b', log, re.I):
        result.status = 'partial'
        result.warnings.append('工具日志含错误提示，结果可能不完整；核对原始输出。')
    outputs = sorted(output.rglob('*.csv'))
    if not outputs:
        return ToolResult(status='unsupported', error='未生成CSV；可能无匹配映射或解析失败，不能推断完整0',
                          warnings=['完整日志保留在external stdout/stderr。'])
    for csv_path in outputs:
        csv_path = local_path(csv_path)
        if not within(csv_path, output):
            raise ValueError('输出越界')
        # Raw CSV is registered as a hashed tool output by the existing runner.
        text = csv_path.read_bytes()
        if len(text) > ctx.settings.limits.output_bytes:
            raise ValueError('CSV超过输出限额')
        reader = csv.DictReader(io.StringIO(text.decode('utf-8-sig', errors='strict')))
        fields = reader.fieldnames
        if not fields or len(set(fields)) != len(fields) or any(not x for x in fields):
            raise ValueError('CSV字段为空或重复')
        for index, row in enumerate(reader, 1):
            if None in row or any(value is None for value in row.values()):
                raise ValueError('CSV行字段数量不匹配')
            if params.keyword and params.keyword.casefold() not in json.dumps(row, ensure_ascii=False).casefold():
                continue
            if len(result.records) >= params.limit:
                result.status, result.truncated = 'partial', True
                result.warnings.append('匹配记录超过上限；不能把本页当完整统计。')
                return result
            result.records.append(ToolRecord(source_id=source.id,
                locator={'kind': tool, 'csv_file': str(csv_path.relative_to(output)), 'row': index,
                         'json_path': str(csv_path)}, data=row))
    return result


def prefetch(ctx, params):
    return export(ctx, params, 'pecmd')


def mft(ctx, params):
    return export(ctx, params, 'mftecmd')


def registry(ctx, params):
    return export(ctx, params, 'recmd')


def sqlite_maps(ctx, params):
    return export(ctx, params, 'sqlecmd')
