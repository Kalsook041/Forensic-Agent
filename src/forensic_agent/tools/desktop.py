"""Closed Autopsy case queries and non-executing VeraCrypt handoff."""
from pathlib import Path
import sqlite3

from ..evidence.store import sha256_file
from ..models import ToolRecord, ToolResult
from .windows_artifacts import single_source


def autopsy(ctx, params):
    source = single_source(ctx)
    path = Path(source.working_path)
    with path.open('rb') as stream:
        header = stream.read(100)
    if not header.startswith(b'SQLite format 3\x00'):
        return ToolResult(status='unsupported', error='请选择已关闭并checkpoint的Autopsy案件autopsy.db，不是磁盘镜像')
    if header[18:20] != b'\x01\x01' or any(Path(str(path) + suffix).exists() for suffix in ('-wal', '-journal')):
        return ToolResult(status='blocked', error='案件处于WAL或日志模式；先关闭Autopsy并导出完整独立数据库')
    queries = {
        'files': ('tsk_files', ['obj_id', 'name', 'parent_path', 'size', 'mtime', 'ctime', 'atime', 'crtime'], 'obj_id'),
        'attributes': ('blackboard_attributes', ['artifact_id', 'attribute_type_id', 'value_type',
                       'value_text', 'value_int32', 'value_int64', 'value_double'], 'artifact_id'),
    }
    table, columns, order = queries[params.view]
    result = ToolResult(warnings=['只核验当前Autopsy数据库；未重新验证其原始镜像、人工导出来源链或采集完整性。',
                                 '时间/数字保留数据库原值；属性类型需结合Autopsy数据模型解释。'])
    with sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True) as connection:
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('PRAGMA query_only=ON')
        kind = connection.execute('SELECT type FROM sqlite_master WHERE name=?', (table,)).fetchone()
        if kind != ('table',):
            raise ValueError('不是受支持的Autopsy数据表；不执行视图或自由SQL')
        actual = {r[1] for r in connection.execute(f'PRAGMA table_info("{table}")')}
        if not set(columns) <= actual:
            raise ValueError('Autopsy数据库schema不受支持；请导出标准报告或检查版本')
        cursor = connection.execute('SELECT ' + ','.join(columns) + f' FROM {table} ORDER BY {order}')
        for scanned, row in enumerate(cursor, 1):
            if scanned > ctx.settings.limits.max_files:
                result.status, result.truncated = 'partial', True
                result.warnings.append('数据库扫描达到限额；筛选范围未完整遍历。')
                break
            data = dict(zip(columns, row))
            if params.keyword and not any(params.keyword.casefold() in str(x).casefold() for x in row):
                continue
            if len(result.records) >= params.limit:
                result.status, result.truncated = 'partial', True
                result.warnings.append('匹配行超过展示上限；不能推断全量统计。')
                break
            result.records.append(ToolRecord(source_id=source.id,
                locator={'kind': 'autopsy_db', 'table': table, 'row': scanned, order: data[order]}, data=data))
    return result


def veracrypt(ctx, params):
    source = single_source(ctx)
    executable = Path(ctx.settings.tools.veracrypt)
    return ToolResult(status='blocked', error='需要操作者确认VeraCrypt格式并在软件界面输入凭据；不会猜密或自动挂载',
        warnings=['已生成只读打开步骤；不是已解密结果。'], records=[ToolRecord(source_id=source.id,
            grounding='exploratory', locator={'kind': 'operator_handoff'}, data={
                'configured_executable': str(executable), 'executable_sha256': sha256_file(executable),
                'working_copy': source.working_path,
                'steps': ['仅在确认VeraCrypt/TrueCrypt格式后继续，不根据高熵猜格式。',
                          '在VeraCrypt选择该工作副本，点击Mount Options，勾选Mount volume as read-only。',
                          '在软件界面输入已知密码/密钥文件，不要把凭据粘贴进题目、模型或日志。',
                          '记录容器SHA256、软件版本、只读选项、盘符、时间和导出内部路径。',
                          '仅导出本题相关文件，卸载挂载卷；交回导出文件并保留人工来源交接记录。']})])
