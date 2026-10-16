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


PCAP_FIELDS = ["frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "_ws.col.Protocol", "eth.type", "vlan.etype",
               "ip.version", "ip.src", "ip.dst", "ip.proto", "ipv6.version", "ipv6.src", "ipv6.dst", "ipv6.nxt",
               "ipv6.hopopts.nxt", "ipv6.routing.nxt", "ipv6.fraghdr.nxt", "ipv6.dstopts.nxt", "ah.next_header",
               "tcp.stream", "tcp.hdr_len", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
               "dns.qry.name", "dns.a", "dns.aaaa", "http.request.method", "http.host", "http.request.uri",
               "tls.handshake.extensions_server_name"]


def pcap(ctx, params):
    from decimal import Decimal, InvalidOperation
    from ipaddress import ip_address

    result = ToolResult()
    filters = []
    if params.protocol != "overview":
        filters.append({"dns": "dns", "http": "http.request", "tls": "tls.handshake"}[params.protocol])
    if params.ip_address:
        field = "ip.addr" if ip_address(params.ip_address).version == 4 else "ipv6.addr"
        filters.append(f"{field} == {params.ip_address}")
    if params.tcp_stream is not None:
        filters.append(f"tcp.stream == {params.tcp_stream}")
    display_filter = " && ".join(f"({item})" for item in filters)
    scope = {"kind": "filtered" if filters else "capture", "protocol": params.protocol,
             "ip_address": params.ip_address, "tcp_stream": params.tcp_stream}
    for source in ctx.files():
        if identify(Path(source.working_path)) not in {"pcap", "pcapng"}:
            continue
        arguments = ["-n", "-r", source.working_path, "-T", "fields", "-E", "header=y",
                     "-E", "separator=/t", "-E", "quote=d", "-E", "escape=y", "-E", "occurrence=a"]
        if display_filter:
            arguments += ["-Y", display_filter]
        for field in PCAP_FIELDS:
            arguments += ["-e", field]
        raw, stderr = ctx.external("tshark", arguments)
        if stderr:
            result.warnings.append(stderr.decode("utf-8", errors="replace")[:2000])
        rows = csv.DictReader(io.StringIO(raw.decode("utf-8-sig", errors="strict")), delimiter="\t")
        count = 0
        protocols = {}
        addresses, streams, tcp_ports, udp_ports = set(), set(), set(), set()
        ip_complete, tcp_complete, udp_complete = True, True, True
        capture_truncated_count = 0
        start_epoch, end_epoch = None, None
        first_frame, last_frame = None, None
        page = []
        for row in rows:
            if not (row.get("frame.number") or "").isdigit():
                raise ValueError("TShark 返回无效帧编号")
            count += 1
            protocol = row.get("_ws.col.protocol") or row.get("_ws.col.Protocol") or "unknown"
            protocols[protocol] = protocols.get(protocol, 0) + 1
            first_frame = first_frame or int(row["frame.number"])
            last_frame = int(row["frame.number"])
            lengths = [row.get(field) or "" for field in ("frame.cap_len", "frame.len")]
            if any(not value.isdigit() for value in lengths):
                raise ValueError("TShark 返回无效帧长度")
            capture_truncated = int(lengths[0]) < int(lengths[1])
            capture_truncated_count += int(capture_truncated)
            values = {field: [value for value in (row.get(field) or "").split(",") if value]
                      for field in PCAP_FIELDS}
            next_headers = [value for field in ("ip.proto", "ipv6.nxt", "ipv6.hopopts.nxt",
                                                "ipv6.routing.nxt", "ipv6.fraghdr.nxt", "ipv6.dstopts.nxt",
                                                "ah.next_header")
                            for value in values[field]]
            ipv6_next_headers = [value for field in ("ipv6.nxt", "ipv6.hopopts.nxt", "ipv6.routing.nxt",
                                                     "ipv6.fraghdr.nxt", "ipv6.dstopts.nxt")
                                 for value in values[field]]
            missing_ipv6_extension = any(ipv6_next_headers.count(protocol) > len(values[field])
                                         for protocol, field in (("0", "ipv6.hopopts.nxt"),
                                                                 ("43", "ipv6.routing.nxt"),
                                                                 ("44", "ipv6.fraghdr.nxt"),
                                                                 ("60", "ipv6.dstopts.nxt")))
            # Account for a missing inner IP header as well as a missing link/network header.
            # Wireshark also exposes ip.version=6 for IPv6 packets.
            network_types = values["eth.type"] + values["vlan.etype"]
            expected_v4 = max(values["ip.version"].count("4"),
                              network_types.count("0x0800") + next_headers.count("4"))
            expected_v6 = max(len(values["ipv6.version"]),
                              network_types.count("0x86dd") + next_headers.count("41"))
            missing_ah = next_headers.count("51") > len(values["ah.next_header"])
            missing_network = (missing_ipv6_extension or missing_ah or len(values["ip.src"]) != expected_v4
                               or len(values["ip.dst"]) != expected_v4
                               or len(values["ip.proto"]) != expected_v4
                               or len(values["ipv6.src"]) != expected_v6
                               or len(values["ipv6.dst"]) != expected_v6
                               or len(values["ipv6.nxt"]) != expected_v6
                               or (capture_truncated and not values["eth.type"]
                                   and not (expected_v4 or expected_v6)))
            if missing_network:
                ip_complete = tcp_complete = udp_complete = False
            if next_headers.count("6") > min(len(values["tcp.stream"]), len(values["tcp.hdr_len"]),
                                              len(values["tcp.srcport"]), len(values["tcp.dstport"])):
                tcp_complete = False
            if next_headers.count("17") > min(len(values["udp.srcport"]), len(values["udp.dstport"])):
                udp_complete = False
            try:
                epoch = Decimal(row["frame.time_epoch"])
                if not epoch.is_finite():
                    raise ValueError("TShark 返回非有限帧时间")
            except (InvalidOperation, KeyError, TypeError) as exc:
                raise ValueError("TShark 返回无效帧时间") from exc
            start_epoch = epoch if start_epoch is None else min(start_epoch, epoch)
            end_epoch = epoch if end_epoch is None else max(end_epoch, epoch)
            for field in ("ip.src", "ip.dst", "ipv6.src", "ipv6.dst"):
                for value in (row.get(field) or "").split(","):
                    if value:
                        addresses.add(str(ip_address(value)))
            for fields, values in ((("tcp.stream",), streams),
                                   (("tcp.srcport", "tcp.dstport"), tcp_ports),
                                   (("udp.srcport", "udp.dstport"), udp_ports)):
                for field in fields:
                    for value in (row.get(field) or "").split(","):
                        if value:
                            if not value.isdigit():
                                raise ValueError(f"TShark 返回无效数字字段：{field}")
                            values.add(int(value))
            if params.offset < count <= params.offset + params.limit:
                page.append(ToolRecord(source_id=source.id,
                locator={"kind": "pcap", "frame_number": int(row["frame.number"]),
                         "filter": params.protocol, "scope": scope, "matched_row": count},
                data={k: v for k, v in row.items() if k is not None and v}))
        returned = len(page)
        has_more = params.offset + returned < count
        navigation = {"scope": scope, "matched_packet_count": count, "offset": params.offset,
                      "limit": params.limit, "returned_packet_count": returned, "has_more": has_more,
                      "next_offset": params.offset + returned if has_more else None}
        if capture_truncated_count:
            result.status, result.truncated = "partial", True
            result.warnings.append(f"捕获采集截断了{capture_truncated_count}个匹配帧（frame.cap_len < frame.len）；"
                                   "缺失字节无法恢复，统计仅基于已捕获且可解码的头部")
        if not (ip_complete and tcp_complete and udp_complete):
            result.status, result.truncated = "partial", True
            result.warnings.append("部分网络/传输头部未完整解码（含截断或分片）；完整性标记为false的统计不可作为总数，"
                                   "null表示无法确认，observed_*仅为已解码观察值")
        if returned < count:
            result.status, result.truncated = "partial", True
            result.warnings.append("当前页省略了匹配帧明细；统计基于本次完整工具输出，不能把当前页视为全文件明细")
        if params.protocol == "overview":
            address_list = sorted(addresses, key=lambda value: (ip_address(value).version,
                                                                int(ip_address(value))))
            addresses_complete = ip_complete and len(address_list) <= 1000
            if len(address_list) > 1000:
                result.status, result.truncated = "partial", True
                result.warnings.append("IP 地址列表超过1000项，仅展示前1000项；完整计数是否可用见ip_statistics_complete")
            result.records.append(ToolRecord(source_id=source.id, grounding="derived",
                locator={"kind": "pcap_summary", "frame_range": [first_frame, last_frame], "scope": scope,
                         "aggregation_basis": "基于本次完整 TShark 字段输出的全部匹配帧聚合；不根据当前页推断全局"},
                data={"packet_count": count, "protocol_counts": protocols,
                      "ip_addresses": address_list[:1000], "ip_address_count": len(address_list) if ip_complete else None,
                      "observed_ip_address_count": len(address_list), "ip_statistics_complete": ip_complete,
                      "ip_addresses_complete": addresses_complete,
                      "tcp_session_count": len(streams) if tcp_complete else None,
                      "observed_tcp_session_count": len(streams), "tcp_statistics_complete": tcp_complete,
                      "tcp_ports": sorted(tcp_ports), "udp_ports": sorted(udp_ports),
                      "udp_statistics_complete": udp_complete,
                      "capture_truncated_packet_count": capture_truncated_count,
                      "capture_start_epoch": str(start_epoch) if start_epoch is not None else None,
                      "capture_end_epoch": str(end_epoch) if end_epoch is not None else None,
                      "duration_seconds": str(end_epoch - start_epoch) if start_epoch is not None else None,
                      "statistics_complete": ip_complete and tcp_complete and udp_complete,
                      "statistics_scope": "all_matched_packets",
                      **navigation}))
        else:
            result.warnings.append("PCAP 分页: " + json.dumps({"source_id": source.id, **navigation},
                                                               ensure_ascii=False, separators=(",", ":")))
        result.records.extend(page)
        if count == 0:
            result.warnings.append("没有匹配帧；TLS 加密载荷不会被推测为明文")
    if not result.records and not result.warnings:
        result.warnings.append("没有可解析的捕获文件")
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
