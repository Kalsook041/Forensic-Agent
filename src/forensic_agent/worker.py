"""Trusted worker: no evidence access until parent assigns a Windows Job and sends input."""
import json
from pathlib import Path
import sys

from .models import Source, ToolRecord, ToolRequest, ToolResult
from .settings import Settings


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    try:
        payload = json.loads(sys.stdin.buffer.readline(16 * 1024**2))
        # These imports and all artifact parsing occur after the parent's Job assignment.
        from .tools.context import Context
        from .tools.registry import validate_request
        request = ToolRequest.model_validate(payload["request"])
        adapter, params = validate_request(request)
        settings = Settings.model_validate(payload["settings"])
        sources = [Source.model_validate(x) for x in payload["sources"]]
        ctx = Context(settings, sources, Path(payload["step_dir"]))
        if payload.get("reference") is not None:
            ctx.reference = ToolRecord.model_validate(payload["reference"])
        result = adapter.execute(ctx, params)
        serialized = json.dumps(result.model_dump(), ensure_ascii=False, allow_nan=False)
    except Exception as exc:
        result = ToolResult(status="failed", error=f"{type(exc).__name__}: {exc}")
        serialized = json.dumps(result.model_dump(), ensure_ascii=False, allow_nan=False)
    print(serialized, flush=True)


if __name__ == "__main__":
    main()
