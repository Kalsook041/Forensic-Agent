import ipaddress
from pathlib import Path
import sqlite3
import struct

from forensic_agent.evidence import Case, sha256_file
from forensic_agent.models import ToolRequest
from forensic_agent.tools.runner import run_tool


def create_pcap(path):
    def ethernet_ip(payload, protocol):
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, protocol, 0,
                         ipaddress.ip_address("192.0.2.2").packed, ipaddress.ip_address("198.51.100.1").packed)
        return b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x08\x00" + ip + payload
    dns = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x07contest\x04test\x00\x00\x01\x00\x01"
    udp = struct.pack("!HHHH", 12345, 53, 8 + len(dns), 0) + dns
    http = b"GET /flag?value=FLAG-PCAP HTTP/1.1\r\nHost: contest.test\r\n\r\n"
    tcp = struct.pack("!HHIIBBHHH", 12346, 80, 1, 0, 0x50, 0x18, 65535, 0, 0) + http
    packets = [ethernet_ip(udp, 17), ethernet_ip(tcp, 6)]
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            stream.write(struct.pack("<IIII", 1700000000 + index, 0, len(packet), len(packet)))
            stream.write(packet)


def test_real_tshark_dns_and_http(tmp_path, settings):
    path = tmp_path / "流量.pcap"
    create_pcap(path)
    before = sha256_file(path)
    case = Case.create(path, settings)
    dns = run_tool(case, ToolRequest(tool_id="pcap", source_id="s00001", params={"protocol": "dns"}))
    assert dns["result"]["status"] == "ok", dns["result"]
    assert dns["evidence"][0]["data"]["dns.qry.name"] == "contest.test"
    assert dns["evidence"][0]["locator"]["frame_number"] == 1
    http = run_tool(case, ToolRequest(tool_id="pcap", source_id="s00001", params={"protocol": "http"}))
    assert http["result"]["status"] == "ok", http["result"]
    assert http["evidence"][0]["data"]["http.request.uri"] == "/flag?value=FLAG-PCAP"
    assert http["evidence"][0]["locator"]["frame_number"] == 2
    assert sha256_file(path) == before


def test_wal_content_not_silently_omitted(tmp_path, settings):
    path = tmp_path / "wal.sqlite"
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE flags(value TEXT)")
        connection.execute("INSERT INTO flags VALUES('FLAG-IN-WAL')")
        connection.commit()
        assert path.with_name(path.name + "-wal").stat().st_size > 0
        case = Case.create(path, settings)
        step = run_tool(case, ToolRequest(tool_id="sqlite", source_id="s00001",
                                          params={"sql": "SELECT value FROM flags"}))
        assert step["result"]["status"] == "ok", step["result"]
        assert step["evidence"][0]["data"]["values"] == ["FLAG-IN-WAL"]
        assert len(case.sources) >= 2
        assert not case.verify_originals()
    finally:
        connection.close()


def test_evtx_sample(settings):
    path = Path(__file__).parent / "fixtures" / "system.evtx"
    assert path.is_file(), "真实 EVTX 样本必须随测试交付"
    case = Case.create(path, settings)
    step = run_tool(case, ToolRequest(tool_id="evtx", source_id="s00001", params={"limit": 3}))
    assert step["result"]["status"] == "partial", step["result"]
    assert len(step["evidence"]) == 3
    assert step["evidence"][0]["data"]["event_id"] >= 0
    assert "<Event" in step["evidence"][0]["data"]["xml"]
    from forensic_agent.agent.loop import compact_messages
    import json
    summary = json.loads(compact_messages(case)[1]["content"])["observations"][0]["records"][0]
    assert summary["data"]["record_id"] == step["evidence"][0]["data"]["record_id"]
    assert summary["data"]["event_id"] == step["evidence"][0]["data"]["event_id"]
    assert "preview" not in summary["data"]


def test_real_evtxecmd_matches_python_events(settings):
    path = Path(__file__).parent / "fixtures" / "system.evtx"
    case = Case.create(path, settings)
    request = {"source_id": "s00001", "params": {"event_ids": [6005], "limit": 20}}
    python_result = run_tool(case, ToolRequest(tool_id="evtx", **request))
    native_result = run_tool(case, ToolRequest(tool_id="evtxecmd", **request))
    assert native_result["result"]["status"] == "ok", native_result["result"]
    expected = [row["data"]["record_id"] for row in python_result["evidence"]]
    assert expected and expected == [row["data"]["record_id"] for row in native_result["evidence"]]
    assert all(row["data"]["event_id"] == 6005 for row in native_result["evidence"])
    assert Path(native_result["evidence"][0]["locator"]["json_path"]).is_file()
    assert not case.verify_originals()
