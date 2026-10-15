"""Verified per-step SQLite copies and predefined, provenance-bearing query templates."""
import hashlib
from pathlib import Path
import shutil
import sqlite3
import time

from ..evidence.paths import local_path
from ..evidence.store import SQLITE_SUFFIXES
from ..models import ToolRecord, ToolResult


def quote_identifier(value):
    if not value or "\x00" in value:
        raise ValueError("无效 SQLite 标识符")
    return '"' + value.replace('"', '""') + '"'


def analysis_copy(ctx, source):
    registered = {Path(item.working_path): item for item in ctx.files()}
    path = Path(source.working_path)
    bundle = [source]
    for suffix in SQLITE_SUFFIXES:
        companion = path.with_name(path.name + suffix)
        item = registered.get(companion)
        present = companion.exists() or companion.is_symlink()
        if present and item is None:
            raise ValueError("分析前发现未登记的 SQLite 伴随文件")
        if item is not None and not present:
            raise ValueError("分析前发现 SQLite 伴随文件缺失")
        if present:
            bundle.append(item)
    output = ctx.step_dir / ("sqlite-" + source.id)
    output.mkdir()
    total = sum(item.size for item in bundle)
    if shutil.disk_usage(output).free < total + ctx.settings.limits.reserve_disk_bytes:
        raise OSError("SQLite 分析副本磁盘空间不足")
    for item in bundle:
        original = local_path(item.working_path)
        destination = output / original.name
        digest = hashlib.sha256()
        size = 0
        with original.open("rb") as src, destination.open("xb") as target:
            while chunk := src.read(1024 * 1024):
                size += len(chunk)
                if size > item.size or shutil.disk_usage(output).free < ctx.settings.limits.reserve_disk_bytes:
                    raise OSError("SQLite 副本增长或磁盘余量不足")
                digest.update(chunk)
                target.write(chunk)
        if size != item.size or digest.hexdigest() != item.sha256:
            raise ValueError(f"SQLite 文件在复制期间变化：{item.id}")
    return output / path.name, [{"source_id": item.id, "sha256": item.sha256,
                                  "name": Path(item.working_path).name} for item in bundle]


def template_query(connection, params):
    schema_sql = "SELECT name, type, sql FROM sqlite_schema WHERE type IN ('table','view') ORDER BY name"
    if params.query == "schema":
        return schema_sql, [], {"template": "schema", "grounding": "evidence"}
    tables = {name: kind for name, kind in connection.execute("SELECT name,type FROM sqlite_schema WHERE type IN ('table','view')")}
    if params.table not in tables:
        raise ValueError("表名不在检材实际结构中；请先调用 schema 模板")
    info = connection.execute("PRAGMA table_info(" + quote_identifier(params.table) + ")").fetchall()
    names = {row[1] for row in info}
    if any(column not in names for column in params.columns) or (params.filter_column and params.filter_column not in names):
        raise ValueError("字段不在检材实际表结构中")
    provenance = {"template": params.query, "table": params.table, "table_type": tables[params.table],
                  "columns": params.columns or [row[1] for row in info]}
    if params.query == "columns":
        return None, info, {**provenance, "grounding": "evidence"}
    projection = "COUNT(*) AS n" if params.query == "count" else (
        ",".join(quote_identifier(name) for name in params.columns) if params.columns else "*")
    sql = "SELECT " + projection + " FROM " + quote_identifier(params.table)
    parameters = []
    if params.filter_column:
        sql += " WHERE " + quote_identifier(params.filter_column) + " IS ?"
        parameters = [params.filter_value]
    # Fetching is also bounded below; LIMIT bounds evaluation/output for normal row queries.
    if params.query == "rows":
        sql += " LIMIT ?"
        parameters.append(params.limit + 1)
    return sql, parameters, {**provenance, "grounding": "derived" if params.query == "count" or tables[params.table] == "view" else "evidence"}


def sqlite_query(ctx, params):
    from .basic import identify, sql_authorizer
    result = ToolResult()
    for source in ctx.files():
        if identify(Path(source.working_path)) != "sqlite":
            continue
        try:
            path, bundle = analysis_copy(ctx, source)
            connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)
            try:
                connection.execute("PRAGMA query_only=ON")
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.execute("PRAGMA temp_store=MEMORY")
                connection.enable_load_extension(False)
                deadline = time.monotonic() + min(10, ctx.settings.limits.timeout_seconds)
                connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
                raw_sql = getattr(params, "sql", None)
                if raw_sql is not None:
                    sql, parameters = raw_sql, params.parameters
                    provenance = {"template": "operator_sql", "grounding": "exploratory"}
                    result.warnings.append("人工 SQL 探索结果可能由常量或计算产生，不作为模型答案的证据依据")
                else:
                    sql, parameters, provenance = template_query(connection, params)
                connection.set_authorizer(sql_authorizer)
                if sql is None:
                    columns = ["cid", "name", "type", "notnull", "default_value", "primary_key"]
                    rows = parameters[:params.limit + 1]
                    parameters = []
                else:
                    cursor = connection.execute(sql, parameters)
                    if cursor.description is None:
                        raise ValueError("只允许返回结果的只读查询")
                    columns = [column[0] for column in cursor.description]
                    rows = cursor.fetchmany(params.limit + 1)
                for index, row in enumerate(rows[:params.limit], 1):
                    values = [{"blob_hex": value.hex()} if isinstance(value, bytes) else value for value in row]
                    result.records.append(ToolRecord(source_id=source.id,
                        locator={"kind": "sqlite", "sql": sql, "parameters": parameters, "result_row": index,
                                 "analysis_copy": str(path), "bundle": bundle, "provenance": provenance},
                        grounding=provenance["grounding"], data={"columns": columns, "values": values}))
                if len(rows) > params.limit:
                    result.status, result.truncated = "partial", True
                    result.warnings.append(f"{source.id} 查询结果超过展示上限")
            finally:
                connection.close()
        except (sqlite3.Error, OSError, ValueError) as exc:
            result.status = "partial" if result.records else "failed"
            result.warnings.append(f"{source.id} SQLite 查询失败或被拒绝：{exc}")
    if not result.records and not result.warnings:
        result.warnings.append("未找到 SQLite 数据库或查询返回零行；请核对检材与查询")
    return result
