import ipaddress
import json
import struct

import pytest
from pydantic import ValidationError

from forensic_agent.evidence import Case, sha256_file
from forensic_agent.models import ToolRequest
from forensic_agent.tools.params import PcapParams
from forensic_agent.tools.runner import run_tool


def _packet(source, destination, source_port, destination_port, *, tcp=False, payload=b"", syn=False):
    if tcp:
        transport = struct.pack("!HHIIBBHHH", source_port, destination_port, 0 if syn else 1,
                                0, 0x50, 0x02 if syn else 0x18, 65535, 0, 0) + payload
        protocol = 6
    else:
        transport = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
        protocol = 17
    source, destination = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    if source.version == 4:
        network = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 1, 0, 64, protocol, 0,
                              source.packed, destination.packed)
        ethertype = b"\x08\x00"
    else:
        network = struct.pack("!IHBB16s16s", 6 << 28, len(transport), protocol, 64,
                              source.packed, destination.packed)
        ethertype = b"\x86\xdd"
    return b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b" + ethertype + network + transport


def _write_capture(path, packets):
    # Nanosecond PCAP makes timestamp precision and out-of-order time handling observable.
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xa1b23c4d, 2, 4, 0, 0, 65535, 1))
        for seconds, nanoseconds, packet in packets:
            stream.write(struct.pack("<IIII", seconds, nanoseconds, len(packet), len(packet)))
            stream.write(packet)


def _write_truncated_capture(path, packet, captured_length):
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xa1b23c4d, 2, 4, 0, 0, 65535, 1))
        stream.write(struct.pack("<IIII", 1700000000, 0, captured_length, len(packet)))
        stream.write(packet[:captured_length])


@pytest.fixture
def capture_case(tmp_path, settings):
    path = tmp_path / "跨页多流.pcap"
    a, b, c = "192.0.2.1", "198.51.100.2", "203.0.113.3"
    d, e = "2001:db8::1", "2001:db8::2"
    dns = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x04page\x04test\x00\x00\x01\x00\x01"
    http = b"GET /page HTTP/1.1\r\nHost: page.test\r\n\r\n"
    packets = [
        (1700000002, 9, _packet(a, b, 40001, 80, tcp=True, syn=True)),
        (1700000000, 1, _packet(a, b, 40001, 80, tcp=True, payload=http)),
        (1700000001, 2, _packet(b, c, 40002, 443, tcp=True, syn=True)),
        (1700000001, 3, _packet(a, c, 53000, 53, payload=dns)),
        (1700000001, 4, _packet(d, e, 40003, 8080, tcp=True, syn=True)),
        (1700000001, 5, _packet(d, e, 40003, 8080, tcp=True, payload=http)),
        (1700000001, 6, _packet(b, c, 53001, 9999, payload=b"page")),
        (1700000003, 123456789, _packet(c, a, 40004, 22, tcp=True, syn=True)),
    ]
    _write_capture(path, packets)
    return Case.create(path, settings), path, sha256_file(path)


def _run(case, **params):
    step = run_tool(case, ToolRequest(tool_id="pcap", source_id="s00001", params=params))
    assert step["result"]["status"] in {"ok", "partial"}, step["result"]
    assert not step["integrity"]["issues"]
    return step


def _summary(step):
    record = step["evidence"][0]
    assert record["locator"]["kind"] == "pcap_summary"
    assert record["grounding"] == "derived"
    assert "完整 TShark" in record["locator"]["aggregation_basis"]
    return record["data"]


def _frames(step):
    return [row["locator"]["frame_number"] for row in step["evidence"]
            if row["locator"]["kind"] == "pcap"]


def test_full_capture_statistics_from_real_tshark(capture_case):
    case, path, before = capture_case
    step = _run(case)
    summary = _summary(step)
    assert step["result"]["status"] == "ok"
    assert not step["result"]["truncated"]
    assert summary["packet_count"] == summary["matched_packet_count"] == 8
    assert sum(summary["protocol_counts"].values()) == 8
    assert summary["ip_addresses"] == ["192.0.2.1", "198.51.100.2", "203.0.113.3",
                                        "2001:db8::1", "2001:db8::2"]
    assert summary["ip_address_count"] == 5
    assert summary["ip_addresses_complete"]
    assert summary["tcp_session_count"] == 4
    assert summary["observed_tcp_session_count"] == 4 and summary["tcp_statistics_complete"]
    assert summary["observed_ip_address_count"] == 5 and summary["ip_statistics_complete"]
    assert summary["capture_truncated_packet_count"] == 0
    assert summary["tcp_ports"] == [22, 80, 443, 8080, 40001, 40002, 40003, 40004]
    assert summary["udp_ports"] == [53, 9999, 53000, 53001]
    assert summary["capture_start_epoch"] == "1700000000.000000001"
    assert summary["capture_end_epoch"] == "1700000003.123456789"
    assert summary["duration_seconds"] == "3.123456788"
    assert summary["statistics_complete"]
    assert summary["statistics_scope"] == "all_matched_packets"
    assert summary["scope"]["kind"] == "capture"
    assert summary["returned_packet_count"] == 8
    assert not summary["has_more"] and summary["next_offset"] is None
    assert _frames(step) == list(range(1, 9))
    assert sha256_file(path) == before
    assert not case.verify_originals()


def test_model_overview_preserves_summary_without_repeated_frame_context(capture_case):
    from forensic_agent.agent.loop import compact_messages

    case, _, _ = capture_case
    case.manifest["question"] = "PCAP中有哪些IP，共有多少TCP会话？"
    step = _run(case, limit=3)
    messages = compact_messages(case)
    user = json.loads(messages[1]["content"])
    observation = user["observations"][0]
    summary = observation["records"][0]["data"]
    assert user["question"] == case.manifest["question"]
    assert summary["ip_addresses"] == step["evidence"][0]["data"]["ip_addresses"]
    assert summary["tcp_session_count"] == 4 and summary["tcp_statistics_complete"]
    assert summary["statistics_complete"] and summary["next_offset"] == 3
    assert observation["status"] == "partial" and observation["preview_incomplete"]
    assert len(observation["records"]) == 2 and observation["record_count"] == 4
    assert len(case.manifest["steps"][0]["evidence"]) == 4
    assert len(messages[1]["content"].encode("utf-8")) < 3000


def test_pages_keep_full_statistics_and_remain_partial(capture_case):
    case, path, before = capture_case
    baseline = None
    for offset, frames, next_offset in ((0, [1, 2, 3], 3), (3, [4, 5, 6], 6), (6, [7, 8], None),
                                        (20, [], None)):
        step = _run(case, limit=3, offset=offset)
        summary = _summary(step)
        assert step["result"]["status"] == "partial"
        assert step["result"]["truncated"]
        assert _frames(step) == frames
        assert summary["matched_packet_count"] == 8
        assert summary["returned_packet_count"] == len(frames)
        assert summary["next_offset"] == next_offset
        assert summary["has_more"] == (next_offset is not None)
        assert [row["locator"]["matched_row"] for row in step["evidence"][1:]] == frames
        statistics = {key: summary[key] for key in ("ip_addresses", "tcp_session_count", "tcp_ports",
                                                   "udp_ports", "duration_seconds", "protocol_counts")}
        baseline = statistics if baseline is None else baseline
        assert statistics == baseline
    assert sha256_file(path) == before
    assert not case.verify_originals()


def test_fixed_ip_and_stream_filters_use_matching_scope(capture_case):
    case, _, _ = capture_case
    cases = [({"ip_address": "203.0.113.3"}, [3, 4, 7, 8], 2),
             ({"ip_address": "2001:0db8:0:0:0:0:0:1"}, [5, 6], 1),
             ({"tcp_stream": 1}, [3], 1),
             ({"ip_address": "203.0.113.3", "tcp_stream": 1}, [3], 1)]
    for params, frames, sessions in cases:
        step = _run(case, **params)
        summary = _summary(step)
        assert _frames(step) == frames
        assert summary["packet_count"] == len(frames)
        assert summary["tcp_session_count"] == sessions
        assert summary["scope"]["kind"] == "filtered"
        assert summary["statistics_complete"]
        assert step["result"]["status"] == "ok"
        commands = (case.directory / "steps" / step["id"] / "commands.jsonl").read_text(encoding="utf-8")
        finished = json.loads(commands.splitlines()[-1])
        assert "-n" in finished["argv"]
        assert "-Y" in finished["argv"]
        if "tcp_stream" in params:
            assert "(tcp.stream == 1)" in finished["argv"][finished["argv"].index("-Y") + 1]


def test_protocol_pages_preserve_frame_shape(capture_case):
    case, _, _ = capture_case
    dns = _run(case, protocol="dns")
    assert dns["evidence"][0]["data"]["dns.qry.name"] == "page.test"
    assert _frames(dns) == [4]
    http = _run(case, protocol="http", offset=1, limit=1)
    assert http["result"]["status"] == "partial"
    assert http["evidence"][0]["data"]["http.request.uri"] == "/page"
    assert _frames(http) == [6]
    assert http["evidence"][0]["locator"]["matched_row"] == 2
    navigation = next(warning for warning in http["result"]["warnings"] if warning.startswith("PCAP 分页: "))
    page = json.loads(navigation.removeprefix("PCAP 分页: "))
    assert page["matched_packet_count"] == 2 and page["returned_packet_count"] == 1
    assert not page["has_more"] and page["next_offset"] is None
    assert page["scope"]["protocol"] == "http"


def test_empty_match_has_explicit_zero_statistics(capture_case):
    case, _, _ = capture_case
    step = _run(case, ip_address="203.0.113.99")
    summary = _summary(step)
    assert step["result"]["status"] == "ok"
    assert summary["packet_count"] == summary["matched_packet_count"] == summary["returned_packet_count"] == 0
    assert summary["ip_addresses"] == [] and summary["ip_address_count"] == summary["tcp_session_count"] == 0
    assert summary["capture_start_epoch"] is summary["capture_end_epoch"] is summary["duration_seconds"] is None
    assert not summary["has_more"] and summary["next_offset"] is None
    assert _frames(step) == []
    assert any("没有匹配帧" in warning for warning in step["result"]["warnings"])
    http = _run(case, protocol="http", tcp_stream=1)
    assert http["evidence"] == []
    assert any("没有匹配帧" in warning for warning in http["result"]["warnings"])


@pytest.mark.parametrize("params", [
    {"ip_address": "192.0.2.1 || tcp"}, {"ip_address": "example.test"}, {"ip_address": "127.1"},
    {"ip_address": "fe80::1%eth0"}, {"ip_address": "192.0.2.1\n"}, {"tcp_stream": -1},
    {"tcp_stream": True}, {"tcp_stream": "0 || tcp"}, {"offset": -1}, {"offset": 1000001},
    {"offset": True}, {"offset": 1.5}, {"limit": 0}, {"limit": 1001}, {"filter": "tcp"},
])
def test_invalid_pcap_parameters_rejected(params):
    with pytest.raises(ValidationError):
        PcapParams.model_validate(params)


def test_invalid_filter_never_launches_worker(capture_case):
    case, path, before = capture_case
    step = run_tool(case, ToolRequest(tool_id="pcap", source_id="s00001",
                                      params={"ip_address": "192.0.2.1 || tcp"}))
    assert step["result"]["status"] == "blocked"
    assert "worker_argv" not in step
    assert sha256_file(path) == before


def test_ip_list_cap_keeps_full_count_and_marks_partial(tmp_path, settings):
    path = tmp_path / "多地址.pcap"
    packets = [(1700000000 + index, 0,
                _packet(str(ipaddress.ip_address(0x0a000000 + index * 2)),
                        str(ipaddress.ip_address(0x0a000001 + index * 2)), 53000, 9999, payload=b"page"))
               for index in range(501)]
    _write_capture(path, packets)
    case = Case.create(path, settings)
    summary_step = _run(case, limit=1000)
    summary = _summary(summary_step)
    assert summary_step["result"]["status"] == "partial"
    assert summary_step["result"]["truncated"]
    assert summary["ip_address_count"] == 1002 and len(summary["ip_addresses"]) == 1000
    assert not summary["ip_addresses_complete"]
    assert summary["statistics_complete"]
    assert summary["returned_packet_count"] == summary["matched_packet_count"] == 501
    assert not summary["has_more"]
    assert not case.verify_originals()


def test_tunneled_addresses_are_counted_individually(tmp_path, settings):
    path = tmp_path / "IP封装.pcap"
    inner = _packet("192.0.2.1", "198.51.100.2", 40001, 80, tcp=True, syn=True)[14:]
    outer = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(inner), 1, 0, 64, 4, 0,
                        ipaddress.ip_address("203.0.113.3").packed,
                        ipaddress.ip_address("203.0.113.4").packed)
    packet = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x08\x00" + outer + inner
    _write_capture(path, [(1700000000, 0, packet)])
    case = Case.create(path, settings)
    step = _run(case)
    summary = _summary(step)
    assert summary["ip_addresses"] == ["192.0.2.1", "198.51.100.2", "203.0.113.3", "203.0.113.4"]
    assert summary["ip_address_count"] == 4
    assert summary["tcp_session_count"] == 1
    assert "," in step["evidence"][1]["data"]["ip.src"]
    assert summary["tcp_ports"] == [80, 40001]


@pytest.mark.parametrize("captured_length,ip_count", [(10, None), (14, None), (24, None), (34, 2)])
def test_capture_missing_network_or_tcp_header_never_claims_complete_count(tmp_path, settings,
                                                                         captured_length, ip_count):
    path = tmp_path / "头部截断.pcap"
    packet = _packet("192.0.2.1", "198.51.100.2", 40001, 80, tcp=True, syn=True)
    _write_truncated_capture(path, packet, captured_length)
    before = sha256_file(path)
    case = Case.create(path, settings)
    step = _run(case)
    summary = _summary(step)
    assert step["result"]["status"] == "partial" and step["result"]["truncated"]
    assert summary["capture_truncated_packet_count"] == 1
    assert summary["tcp_session_count"] is None
    assert summary["observed_tcp_session_count"] == 0
    assert not summary["tcp_statistics_complete"] and not summary["statistics_complete"]
    assert summary["ip_address_count"] == ip_count
    assert summary["ip_statistics_complete"] == (ip_count is not None)
    assert summary["ip_addresses_complete"] == (ip_count is not None)
    if ip_count is None:
        assert isinstance(summary["observed_ip_address_count"], int)
    assert any("捕获采集截断" in warning for warning in step["result"]["warnings"])
    assert sha256_file(path) == before and not case.verify_originals()


def test_capture_with_complete_tcp_header_and_truncated_payload_keeps_session_count(tmp_path, settings):
    path = tmp_path / "载荷截断.pcap"
    packet = _packet("192.0.2.1", "198.51.100.2", 40001, 80, tcp=True, payload=b"payload" * 5)
    _write_truncated_capture(path, packet, 54)
    case = Case.create(path, settings)
    step = _run(case)
    summary = _summary(step)
    assert step["result"]["status"] == "partial" and step["result"]["truncated"]
    assert summary["capture_truncated_packet_count"] == 1
    assert summary["tcp_session_count"] == summary["observed_tcp_session_count"] == 1
    assert summary["tcp_statistics_complete"] and summary["statistics_complete"]
    assert summary["ip_address_count"] == 2 and summary["ip_statistics_complete"]
    assert summary["tcp_ports"] == [80, 40001]
    assert step["evidence"][1]["data"]["frame.cap_len"] == "54"


def test_noninitial_tcp_fragment_does_not_misreport_zero_sessions(tmp_path, settings):
    path = tmp_path / "TCP分片.pcap"
    packet = bytearray(_packet("192.0.2.1", "198.51.100.2", 40001, 80, tcp=True, syn=True))
    struct.pack_into("!H", packet, 20, 1)  # Noninitial IPv4 fragment; protocol=6, no decodable TCP header.
    _write_capture(path, [(1700000000, 0, packet)])
    case = Case.create(path, settings)
    step = _run(case)
    summary = _summary(step)
    assert summary["capture_truncated_packet_count"] == 0
    assert summary["tcp_session_count"] is None and summary["observed_tcp_session_count"] == 0
    assert not summary["tcp_statistics_complete"] and not summary["statistics_complete"]
    assert summary["ip_address_count"] == 2 and summary["ip_statistics_complete"]
    assert step["result"]["status"] == "partial"
    assert any("分片" in warning for warning in step["result"]["warnings"])


def test_ipv6_header_without_tcp_header_is_incomplete(tmp_path, settings):
    path = tmp_path / "IPv6TCP头缺失.pcap"
    packet = _packet("2001:db8::1", "2001:db8::2", 40001, 80, tcp=True, syn=True)
    _write_truncated_capture(path, packet, 54)
    case = Case.create(path, settings)
    step = _run(case)
    summary = _summary(step)
    assert summary["ip_address_count"] == 2 and summary["ip_statistics_complete"]
    assert summary["tcp_session_count"] is None and summary["observed_tcp_session_count"] == 0
    assert not summary["tcp_statistics_complete"] and not summary["statistics_complete"]
    assert step["result"]["status"] == "partial"


def test_missing_ipv6_extension_header_cannot_claim_zero_tcp_sessions(tmp_path, settings):
    path = tmp_path / "IPv6扩展头缺失.pcap"
    packet = bytearray(_packet("2001:db8::1", "2001:db8::2", 40001, 80, tcp=True, syn=True))
    packet[20] = 0  # IPv6 base header says Hop-by-Hop Options comes next.
    struct.pack_into("!H", packet, 18, 28)
    packet[54:54] = b"\x06\x00\x00\x00\x00\x00\x00\x00"  # Extension would indicate TCP.
    _write_truncated_capture(path, packet, 54)
    case = Case.create(path, settings)
    step = _run(case)
    summary = _summary(step)
    assert summary["tcp_session_count"] is None and summary["observed_tcp_session_count"] == 0
    assert not summary["tcp_statistics_complete"] and not summary["statistics_complete"]
    assert step["result"]["status"] == "partial"


@pytest.mark.parametrize("version", [4, 6])
@pytest.mark.parametrize("capture", ["missing_ip", "full", "payload_only"])
def test_vlan_network_completeness_uses_inner_type(tmp_path, settings, version, capture):
    addresses = (("192.0.2.1", "198.51.100.2") if version == 4
                 else ("2001:db8::1", "2001:db8::2"))
    plain = _packet(*addresses, 40001, 80, tcp=True, payload=b"payload" * 5)
    packet = plain[:12] + b"\x81\x00\x00\x01" + plain[12:]
    path = tmp_path / "VLAN.pcap"
    if capture == "full":
        _write_capture(path, [(1700000000, 0, packet)])
    else:
        length = 18 if capture == "missing_ip" else 18 + (20 if version == 4 else 40) + 20
        _write_truncated_capture(path, packet, length)
    case = Case.create(path, settings)
    step = _run(case)
    summary = _summary(step)
    complete = capture != "missing_ip"
    assert summary["ip_address_count"] == (2 if complete else None)
    assert summary["observed_ip_address_count"] == (2 if complete else 0)
    assert summary["ip_statistics_complete"] == complete
    assert summary["tcp_session_count"] == (1 if complete else None)
    assert summary["observed_tcp_session_count"] == (1 if complete else 0)
    assert summary["tcp_statistics_complete"] == summary["statistics_complete"] == complete
    assert summary["capture_truncated_packet_count"] == (0 if capture == "full" else 1)
    assert step["result"]["status"] == ("ok" if capture == "full" else "partial")
    assert not case.verify_originals()


@pytest.mark.parametrize("version", [4, 6])
@pytest.mark.parametrize("capture", ["missing_ah", "missing_tcp", "full", "payload_only"])
def test_ah_next_header_controls_transport_completeness(tmp_path, settings, version, capture):
    addresses = (("192.0.2.1", "198.51.100.2") if version == 4
                 else ("2001:db8::1", "2001:db8::2"))
    packet = bytearray(_packet(*addresses, 40001, 80, tcp=True, payload=b"payload" * 5))
    network_end = 34 if version == 4 else 54
    ah = struct.pack("!BBHII", 6, 4, 0, 1, 1) + bytes(12)
    packet[network_end:network_end] = ah
    packet[23 if version == 4 else 20] = 51
    struct.pack_into("!H", packet, 16 if version == 4 else 18,
                     len(packet) - (14 if version == 4 else 54))
    path = tmp_path / "AH.pcap"
    if capture == "full":
        _write_capture(path, [(1700000000, 0, packet)])
    else:
        length = {"missing_ah": network_end, "missing_tcp": network_end + len(ah),
                  "payload_only": network_end + len(ah) + 20}[capture]
        _write_truncated_capture(path, packet, length)
    case = Case.create(path, settings)
    step = _run(case)
    summary = _summary(step)
    tcp_complete = capture in {"full", "payload_only"}
    ip_complete = capture != "missing_ah"
    assert summary["ip_address_count"] == (2 if ip_complete else None)
    assert summary["observed_ip_address_count"] == 2
    assert summary["ip_statistics_complete"] == ip_complete
    assert summary["tcp_session_count"] == (1 if tcp_complete else None)
    assert summary["observed_tcp_session_count"] == (1 if tcp_complete else 0)
    assert summary["tcp_statistics_complete"] == summary["statistics_complete"] == tcp_complete
    assert summary["capture_truncated_packet_count"] == (0 if capture == "full" else 1)
    assert step["result"]["status"] == ("ok" if capture == "full" else "partial")
    assert not case.verify_originals()
