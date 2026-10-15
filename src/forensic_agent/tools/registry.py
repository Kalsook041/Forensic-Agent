from dataclasses import dataclass
from typing import Callable

from . import basic, archives, structured
from .params import (ArchiveParams, EmptyParams, EvidenceWindowParams, EvtxParams, InventoryParams,
                     MetadataParams, ModelSQLiteParams, PcapParams, SearchParams, SQLiteParams)


@dataclass(frozen=True)
class Adapter:
    description: str
    params: type
    execute: Callable
    external_tool: str | None = None
    model_params: type | None = None


REGISTRY = {
    "inventory": Adapter("目录检索、文件类型和来源清单", InventoryParams, basic.inventory),
    "hash": Adapter("SHA256 与大小", EmptyParams, basic.hashes),
    "search": Adapter("文本字面量关键词和编码检查", SearchParams, basic.search),
    "metadata": Adapter("图片与文档只读元数据", MetadataParams, basic.metadata, "exiftool"),
    "sqlite": Adapter("SQLite schema/columns/count/rows 查询模板；模型不能提交 SQL", SQLiteParams,
                      basic.sqlite_query, model_params=ModelSQLiteParams),
    "evidence_window": Adapter("按证据ID和字段读取有界原文窗口，start为字符偏移", EvidenceWindowParams, basic.evidence_window),
    "archive": Adapter("ZIP/TAR/GZIP 列表和受控解包，7z/RAR 仅列表", ArchiveParams, archives.archive),
    "pcap": Adapter("离线 PCAP/PCAPNG DNS、HTTP、TLS 和基础帧分析", PcapParams, structured.pcap, "tshark"),
    "evtx": Adapter("离线 Windows EVTX 事件解析", EvtxParams, structured.evtx),
    "evtxecmd": Adapter("使用本机 EZTools EvtxECmd 离线导出与查询 EVTX", EvtxParams, structured.evtxecmd, "evtxecmd"),
}


def validate_request(request):
    if request.tool_id not in REGISTRY:
        raise ValueError("工具不在静态白名单中")
    adapter = REGISTRY[request.tool_id]
    params_type = adapter.model_params if request.origin == "model" and adapter.model_params else adapter.params
    return adapter, params_type.model_validate(request.params)


def catalog(settings, *, for_model=False):
    from pathlib import Path
    return {key: {"description": value.description,
                  "parameters": (value.model_params if for_model and value.model_params else value.params).model_json_schema(),
                  "available": not value.external_tool or Path(getattr(settings.tools, value.external_tool)).is_file()}
            for key, value in REGISTRY.items()}
