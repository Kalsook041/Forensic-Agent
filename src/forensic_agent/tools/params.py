from typing import Literal

from pydantic import Field, field_validator, model_validator
from ..settings import StrictModel


class EmptyParams(StrictModel):
    pass


class InventoryParams(StrictModel):
    name_contains: str = Field(default="", max_length=256)
    extension: str = Field(default="", max_length=32)
    min_size: int = Field(default=0, ge=0)
    max_size: int | None = Field(default=None, ge=0)
    limit: int = Field(default=500, ge=1, le=10000)


class SearchParams(StrictModel):
    keyword: str = Field(min_length=1, max_length=256)
    case_sensitive: bool = False
    encoding: Literal["auto", "utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be",
                      "utf-32", "utf-32-le", "utf-32-be", "gb18030"] = "auto"
    limit: int = Field(default=200, ge=1, le=1000)


class MetadataParams(StrictModel):
    fields: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("fields")
    @classmethod
    def valid_fields(cls, value):
        if any(len(x) > 100 or not x or any(ord(ch) < 32 for ch in x) for x in value):
            raise ValueError("无效元数据字段")
        return value


class ModelSQLiteParams(StrictModel):
    query: Literal["schema", "columns", "count", "rows"] = "schema"
    table: str = Field(default="", max_length=256)
    columns: list[str] = Field(default_factory=list, max_length=32)
    filter_column: str = Field(default="", max_length=256)
    filter_value: str | int | float | None = None
    limit: int = Field(default=200, ge=1, le=1000)

    @field_validator("table", "filter_column")
    @classmethod
    def identifiers(cls, value):
        if "\x00" in value:
            raise ValueError("标识符不允许 NUL")
        return value

    @field_validator("columns")
    @classmethod
    def valid_columns(cls, value):
        if any(not column or len(column) > 256 or "\x00" in column for column in value):
            raise ValueError("无效数据库字段名")
        return value

    @model_validator(mode="after")
    def needs_table(self):
        if self.query != "schema" and not self.table:
            raise ValueError("此查询模板需要实际表名 table")
        if self.query == "schema" and (self.table or self.columns or self.filter_column):
            raise ValueError("schema 模板不接收表/字段筛选")
        return self


class SQLiteParams(ModelSQLiteParams):
    sql: str | None = Field(default=None, min_length=1, max_length=4096)
    parameters: list[str | int | float | None] = Field(default_factory=list, max_length=128)

    @model_validator(mode="after")
    def no_mixed_query(self):
        if self.sql is not None and (self.query != "schema" or self.table or self.columns or self.filter_column):
            raise ValueError("人工 SQL 与查询模板不能混用")
        if self.sql is None and self.parameters:
            raise ValueError("模板参数使用 filter_value，不能提交自由 parameters")
        return self


class EvidenceWindowParams(StrictModel):
    evidence_id: str = Field(min_length=1, max_length=64, pattern=r"^step[0-9]{4,}:r[0-9]{5,}$")
    field: str = Field(min_length=1, max_length=128)
    start: int = Field(default=0, ge=0, le=64 * 1024**2)
    length: int = Field(default=160, ge=1, le=256)


class ArchiveParams(StrictModel):
    action: Literal["list", "extract"] = "list"


class PcapParams(StrictModel):
    protocol: Literal["overview", "dns", "http", "tls"] = "overview"
    limit: int = Field(default=200, ge=1, le=1000)
    offset: int = Field(default=0, ge=0, le=1000000, strict=True)
    ip_address: str = Field(default="", max_length=45)
    tcp_stream: int | None = Field(default=None, ge=0, strict=True)

    @field_validator("ip_address")
    @classmethod
    def valid_ip_address(cls, value):
        from ipaddress import ip_address

        if not value:
            return value
        # Scope IDs are interface names, not addresses usable in the fixed filter.
        if "%" in value:
            raise ValueError("只允许 IPv4 或 IPv6 地址，不允许接口 scope ID")
        return str(ip_address(value))


class EvtxParams(StrictModel):
    event_ids: list[int] = Field(default_factory=list, max_length=64)
    keyword: str = Field(default="", max_length=256)
    limit: int = Field(default=200, ge=1, le=1000)

    @field_validator("event_ids")
    @classmethod
    def valid_ids(cls, value):
        if any(x < 0 or x > 65535 for x in value):
            raise ValueError("事件 ID 范围应为 0..65535")
        return value


class ArtifactRowsParams(StrictModel):
    keyword: str = Field(default="", max_length=256)
    limit: int = Field(default=200, ge=1, le=1000, strict=True)


class AutopsyParams(ArtifactRowsParams):
    view: Literal["files", "attributes"] = "files"
