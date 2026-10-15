import csv
import io
import json
from pathlib import Path
import re

from defusedxml import ElementTree
from Evtx.Evtx import Evtx

from ..evidence.store import sha256_file, write_json
from ..models import ToolRecord, ToolResult
from .basic import identify


PCAP_FIELDS = ["frame.number", "frame.time_epoch", "frame.len", "_ws.col.Protocol", "ip.src", "ip.dst",
               "ipv6.src", "ipv6.dst", "tcp.stream", "dns.qry.name", "dns.a", "dns.aaaa",
               "http.request.method", "http.host", "http.request.uri", "tls.handshake.extensions_server_name"]


def pcap(ctx, params):
    result = ToolResult()
    for source in ctx.files():
        if identify(Path(source.working_path)) not in {"pcap", "pcapng"}:
            continue
        arguments = ["-n", "-r", source.working_path, "-T", "fields", "-E", "header=y",
                     "-E", "separator=/t", "-E", "quote=d", "-E", "escape=y", "-E", "occurrence=a"]
        if params.protocol != "overview":
            arguments += ["-Y", {"dns": "dns", "http": "http.request", "tls": "tls.handshake"}[params.protocol]]
        for field in PCAP_FIELDS:
            arguments += ["-e", field]
        raw, stderr = ctx.external("tshark", arguments)
        if stderr:
            result.warnings.append(stderr.decode("utf-8", errors="replace")[:2000])
        rows = csv.DictReader(io.StringIO(raw.decode("utf-8-sig", errors="strict")), delimiter="\t")
        count = 0
        protocols = {}
        first_frame, last_frame = None, None
        for row in rows:
            if not (row.get("frame.number") or "").isdigit():
                raise ValueError("TShark 返回无效帧编号")
            count += 1
            protocol = row.get("_ws.col.protocol") or row.get("_ws.col.Protocol") or "unknown"
            protocols[protocol] = protocols.get(protocol, 0) + 1
            first_frame = first_frame or int(row["frame.number"])
            last_frame = int(row["frame.number"])
            if count <= params.limit:
                result.records.append(ToolRecord(source_id=source.id,
                locator={"kind": "pcap", "frame_number": int(row["frame.number"]),
                         "filter": params.protocol}, data={k: v for k, v in row.items() if k is not None and v}))
        if count > params.limit:
            result.status, result.truncated = "partial", True
            result.warnings.append("帧明细达到展示上限；统计基于本次完整工具输出")
        if params.protocol == "overview":
            result.records.insert(0, ToolRecord(source_id=source.id,
                locator={"kind": "pcap_summary", "frame_range": [first_frame, last_frame]},
                data={"packet_count": count, "protocol_counts": protocols}))
    if not result.records:
        result.warnings.append("没有匹配帧；TLS 加密载荷不会被推测为明文")
    return result


NAMESPACE = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def evtx(ctx, params):
    result = ToolResult()
    for source in ctx.files():
        if identify(Path(source.working_path)) != "evtx":
            continue
        try:
            with Evtx(source.working_path) as log:
                if not log.get_file_header().verify():
                    raise ValueError("EVTX 文件头校验失败")
                for record in log.records():
                    try:
                        xml = record.xml()
                        if len(xml.encode("utf-8")) > 128 * 1024:
                            raise ValueError("单事件 XML 超过 128KiB 限额")
                        root = ElementTree.fromstring(xml, forbid_dtd=True, forbid_entities=True, forbid_external=True)
                        system = root.find(NAMESPACE + "System")
                        if system is None:
                            raise ValueError("事件缺少 System 节点")
                        event_id = int(system.findtext(NAMESPACE + "EventID", default="-1"))
                        if params.event_ids and event_id not in params.event_ids:
                            continue
                        if params.keyword and params.keyword.casefold() not in xml.casefold():
                            continue
                        provider = system.find(NAMESPACE + "Provider")
                        time_created = system.find(NAMESPACE + "TimeCreated")
                        data = {}
                        for node in root.findall(".//" + NAMESPACE + "Data"):
                            key = node.get("Name", "unnamed")
                            data.setdefault(key, []).append(node.text or "")
                        result.records.append(ToolRecord(source_id=source.id,
                            locator={"kind": "evtx", "record_id": record.record_num()},
                            data={"event_id": event_id, "record_id": record.record_num(),
                                  "provider": provider.get("Name", "") if provider is not None else "",
                                  "time_created": time_created.get("SystemTime", "") if time_created is not None else "",
                                  "computer": system.findtext(NAMESPACE + "Computer", default=""),
                                  "event_data": data, "xml": xml}))
                        if len(result.records) >= params.limit:
                            result.status, result.truncated = "partial", True
                            result.warnings.append("事件数达到上限；未完成全日志遍历")
                            return result
                    except Exception as exc:
                        result.status = "partial"
                        result.warnings.append(f"{source.id} 单事件解析失败：{type(exc).__name__}: {exc}")
                        if len(result.warnings) >= 50:
                            result.warnings.append("错误数达到 50，停止该日志")
                            break
        except Exception as exc:
            result.status = "partial" if result.records else "failed"
            result.warnings.append(f"{source.id} EVTX 解析失败：{type(exc).__name__}: {exc}")
    if not result.records and not result.warnings:
        result.warnings.append("未找到匹配的 EVTX 事件")
    return result


def evtxecmd(ctx, params):
    """Fixed offline JSON export; never exposes --sync or user output paths."""
    result = ToolResult()
    for source in ctx.files():
        if identify(Path(source.working_path)) != "evtx":
            continue
        output = ctx.step_dir / ("evtxecmd-" + source.id)
        output.mkdir()
        destination = output / "events.json"
        arguments = ["-f", source.working_path, "--json", str(output), "--jsonf", "events.json", "--fj"]
        maps = Path(ctx.settings.tools.evtxecmd).parent / "Maps"
        if maps.is_dir():
            arguments += ["--maps", str(maps)]
            write_json(output / "maps-manifest.json", {str(path.relative_to(maps)): sha256_file(path)
                       for path in sorted(maps.rglob("*")) if path.is_file()})
        if params.event_ids:
            arguments += ["--inc", ",".join(str(value) for value in params.event_ids)]
        stdout, stderr = ctx.external("evtxecmd", arguments, artifact_root=output)
        log = (stdout + stderr).decode("utf-8", errors="replace")
        notices = [line.strip() for line in log.splitlines() if "warning" in line.lower()
                   or "not found" in line.lower() or re.search(r"Errors:\s*[1-9]", line)]
        if notices:
            result.warnings.append("EvtxECmd 提示（完整内容见 external stdout）：" + "\n".join(notices[:10])[:2000])
        if re.search(r"Errors:\s*[1-9]", log):
            result.status = "partial"
        if not destination.is_file():
            raise ValueError("EvtxECmd 未生成预期 JSON；请核查原始工具输出")
        with destination.open("rb") as stream:
            for line_number, raw in enumerate(stream, 1):
                if len(raw) > 128 * 1024:
                    raise ValueError("单事件 JSON 超过 128KiB 限额")
                if not raw.strip():
                    continue
                row = json.loads(raw.decode("utf-8-sig"))
                event = row["Event"]
                system = event["System"]
                identity = system["EventID"]
                event_id = int(identity["#text"] if isinstance(identity, dict) else identity)
                if params.event_ids and event_id not in params.event_ids:
                    continue
                if params.keyword and params.keyword.casefold() not in raw.decode("utf-8-sig").casefold():
                    continue
                if len(result.records) >= params.limit:
                    result.status, result.truncated = "partial", True
                    result.warnings.append("事件数达到展示上限；未展示全部 JSON 事件")
                    return result
                record_id = int(system["EventRecordID"])
                result.records.append(ToolRecord(source_id=source.id,
                    locator={"kind": "evtxecmd", "record_id": record_id, "json_line": line_number,
                             "json_path": str(destination)},
                    data={"event_id": event_id, "record_id": record_id,
                          "provider": system.get("Provider", {}).get("@Name", ""),
                          "time_created": system.get("TimeCreated", {}).get("@SystemTime", ""),
                          "computer": system.get("Computer", ""), "channel": system.get("Channel", ""),
                          "event_data": event.get("EventData", {}), "raw_json": row}))
        result.warnings.append("EvtxECmd 时间字段保留原始字符串；没有显式时区时不补齐时区")
    if not result.records and not result.warnings:
        result.warnings.append("未找到匹配的 EVTX 事件")
    return result
