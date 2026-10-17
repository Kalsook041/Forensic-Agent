import json
from typing import Any, Literal

import httpx
from pydantic import Field, model_validator

from ..models import ToolRequest
from ..settings import StrictModel


class Claim(StrictModel):
    evidence_id: str = Field(min_length=1, max_length=64)
    field: str = Field(min_length=1, max_length=128)
    value: Any
    interpretation: str = Field(default="", max_length=1000)


class TaskReview(StrictModel):
    targets: list[str] = Field(min_length=1, max_length=5)
    scope: str = Field(min_length=1, max_length=300)
    constraints: list[str] = Field(max_length=5)
    evidence_needed: list[str] = Field(min_length=1, max_length=5)
    missing: list[str] = Field(default_factory=list, max_length=5)
    stop_when: str = Field(min_length=1, max_length=300)

    @model_validator(mode="after")
    def concise(self):
        if any(not line.strip() or len(line) > 200
               for line in [*self.targets, *self.constraints, *self.evidence_needed, *self.missing]):
            raise ValueError("审题条目须为 1..200 字符的简短摘要")
        if not self.scope.strip() or not self.stop_when.strip():
            raise ValueError("审题范围和停止条件不能为空白")
        if len(self.model_dump_json().encode("utf-8")) > 1800:
            raise ValueError("审题摘要超过 1800 UTF-8 字节，请精简且保留题目限制")
        return self


class Decision(StrictModel):
    task_review: TaskReview | None = None
    plan: list[str] = Field(default_factory=list, max_length=5)
    action: Literal["tool", "finish"]
    request: ToolRequest | None = None
    claims: list[Claim] = Field(default_factory=list, max_length=20)
    uncertainties: list[str] = Field(default_factory=list, max_length=10)

    @model_validator(mode="after")
    def consistent_action(self):
        if (self.action == "tool") != (self.request is not None):
            raise ValueError("tool 动作必须提供 request；finish 动作不能提供 request")
        if any(len(line) > 300 for line in [*self.plan, *self.uncertainties]):
            raise ValueError("计划或不确定性说明过长")
        return self


def decision_schema(tool_sources=None, *, require_task_review=False):
    """Encode action/request dependencies in the generation grammar, not only validation."""
    from ..tools.registry import REGISTRY
    requests = []
    for name, adapter in REGISTRY.items():
        if tool_sources is not None and not tool_sources.get(name):
            continue
        requests.append({"type": "object", "additionalProperties": False,
                         "required": ["tool_id", "source_id", "params"],
                         "properties": {"tool_id": {"const": name, "type": "string"},
                                        "source_id": ({"type": "string", "enum": tool_sources[name]}
                                                      if tool_sources is not None else
                                                      {"type": "string", "pattern": "^s[0-9]{5}$"}),
                                        "params": (adapter.model_params or adapter.params).model_json_schema()}})
    base = Decision.model_json_schema()
    properties = base["properties"]
    required = ["plan", "action", "request", "claims", "uncertainties"]
    if require_task_review:
        properties["task_review"] = {"$ref": "#/$defs/TaskReview"}
        required = ["task_review", *required]
    tool = {"type": "object", "additionalProperties": False,
            "required": required,
            "properties": {**properties, "action": {"const": "tool", "type": "string"},
                           "request": {"anyOf": requests}, "claims": {"type": "array", "maxItems": 0}}}
    if require_task_review:
        tool["properties"]["plan"] = {"type": "array", "items": {"type": "string"},
                                      "minItems": 1, "maxItems": 3}
    finish = {"type": "object", "additionalProperties": False,
              "required": required,
              "properties": {**properties, "action": {"const": "finish", "type": "string"},
                             "request": {"type": "null"}}}
    return {"anyOf": [tool, finish] if requests else [finish], "$defs": base["$defs"]}


class OllamaClient:
    def __init__(self, settings, transport=None):
        self.settings = settings
        self.client = httpx.Client(base_url=settings.base_url, trust_env=False, follow_redirects=False,
                                   timeout=httpx.Timeout(settings.timeout_seconds, connect=3), transport=transport)
        self.model_name = settings.name
        self.model_info = None
        self.last_response = None
        self.allowed_tool_sources = None
        self.require_task_review = False

    def close(self):
        self.client.close()

    def request(self, method, endpoint, payload=None):
        if (method, endpoint) not in {("GET", "/api/version"), ("GET", "/api/tags"),
                                     ("POST", "/api/show"), ("POST", "/api/chat")}:
            raise ValueError("Ollama API 不在白名单中")
        with self.client.stream(method, endpoint, json=payload) as response:
            response.raise_for_status()
            data = bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > 2 * 1024**2:
                    raise ValueError("Ollama 响应超过 2MiB 上限")
        value = json.loads(data)
        if not isinstance(value, dict):
            raise ValueError("Ollama 响应必须为对象")
        return value

    def discover(self):
        version = self.request("GET", "/api/version")
        tags = self.request("GET", "/api/tags").get("models", [])
        names = {item.get("name"): item for item in tags}
        if self.model_name not in names:
            compatible = sorted(item["name"] for item in tags
                if item.get("name", "").startswith(("qwen3:", "qwen3.5:")) and "cloud" not in item["name"].lower()
                and str(item.get("details", {}).get("parameter_size", "")).startswith("4"))
            if not compatible:
                raise ValueError("未找到已完整下载的本地 Qwen3/Qwen3.5 4B；不会自动联网拉取")
            self.model_name = compatible[0]
        shown = self.request("POST", "/api/show", {"model": self.model_name})
        if shown.get("remote_model") or shown.get("remote_host"):
            raise ValueError("拒绝 Ollama 远程/云模型")
        self.model_info = {"name": self.model_name, "digest": names[self.model_name].get("digest"),
                           "details": shown.get("details", {}), "version": version.get("version"),
                           "thinking": shown.get("thinking", {})}
        return self.model_info

    def decide(self, messages):
        if self.model_info is None:
            self.discover()
        payload = {"model": self.model_name, "messages": messages, "stream": False,
                   "format": decision_schema(self.allowed_tool_sources, require_task_review=self.require_task_review),
                   "options": {"temperature": 0, "num_ctx": self.settings.num_ctx,
                               "num_predict": self.settings.num_predict}, "keep_alive": "5m"}
        thinking = self.model_info.get("thinking") or {}
        if False in thinking.get("values", []) or (not thinking and "thinking" not in self.model_name):
            payload["think"] = False
        raw = self.request("POST", "/api/chat", payload)
        self.last_response = raw
        content = raw.get("message", {}).get("content", "")
        decision = Decision.model_validate_json(content)
        if self.require_task_review and decision.task_review is None:
            raise ValueError("首轮必须提供 task_review 审题摘要；未执行工具")
        if self.require_task_review and decision.action == "tool" and not 1 <= len(decision.plan) <= 3:
            raise ValueError("首轮工具请求必须先提供 1..3 步计划；未执行工具")
        return decision, raw
