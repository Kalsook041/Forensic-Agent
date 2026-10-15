from typing import Any, Literal

from pydantic import Field
from .settings import StrictModel

MAX_QUESTION_CHARS = 1000


class ToolRecord(StrictModel):
    source_id: str
    locator: dict[str, Any]
    data: dict[str, Any]
    grounding: Literal["evidence", "derived", "exploratory"] = "evidence"


class Artifact(StrictModel):
    path: str
    parent_id: str
    member: str


class ToolResult(StrictModel):
    status: Literal["ok", "partial", "failed", "blocked", "unsupported"] = "ok"
    records: list[ToolRecord] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error: str | None = None
    truncated: bool = False


class ToolRequest(StrictModel):
    tool_id: str
    source_id: str
    params: dict[str, Any] = Field(default_factory=dict)
    origin: Literal["operator", "model"] = "operator"


class Source(StrictModel):
    id: str
    original_path: str | None
    working_path: str
    kind: Literal["file", "directory"]
    sha256: str | None = None
    size: int = 0
    parent_id: str | None = None
    member: str | None = None
    filesystem: dict[str, Any] = Field(default_factory=dict)
