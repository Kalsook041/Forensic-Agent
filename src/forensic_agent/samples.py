"""Synthetic sample generator. Never execute or capture traffic from evidence."""
import gzip
import ipaddress
from pathlib import Path
import sqlite3
import struct
import zipfile
import zlib

from .evidence.store import sha256_file, write_json


def create_pcap(path):
    def packet(payload, protocol):
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(payload) + 20, 1, 0, 64, protocol, 0,
                         ipaddress.ip_address("192.0.2.2").packed, ipaddress.ip_address("198.51.100.1").packed)
        return bytes(range(12)) + b"\x08\x00" + ip + payload
    dns = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x07contest\x04test\x00\x00\x01\x00\x01"
    udp = struct.pack("!HHHH", 12345, 53, len(dns) + 8, 0) + dns
    http = b"GET /flag?value=FLAG-PCAP HTTP/1.1\r\nHost: contest.test\r\n\r\n"
    tcp = struct.pack("!HHIIBBHHH", 12346, 80, 1, 0, 0x50, 0x18, 65535, 0, 0) + http
    with path.open("xb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, raw in enumerate((packet(udp, 17), packet(tcp, 6))):
            stream.write(struct.pack("<IIII", 1700000000 + index, 0, len(raw), len(raw)))
            stream.write(raw)


def create_samples(directory: Path):
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "线索.txt").write_text("普通记录\nFLAG-TEXT-2026\n结束\n", encoding="utf-8")
    (directory / "UTF16.txt").write_text("示例\nFLAG-UTF16\n", encoding="utf-16")
    (directory / "GB18030.txt").write_bytes("中文编码\n关键词测试\n".encode("gb18030"))
    db = sqlite3.connect(directory / "聊天记录.sqlite")
    db.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, body TEXT)")
    db.executemany("INSERT INTO messages(body) VALUES(?)", [("alpha",), ("FLAG-SQLITE",), ("gamma",)])
    db.commit()
    db.close()
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
           + chunk(b"tEXt", b"Author\x00Forensic Fixture")
           + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk(b"IEND", b""))
    (directory / "作者图片.png").write_bytes(png)
    with zipfile.ZipFile(directory / "安全压缩包.zip", "w") as package:
        package.writestr("中文目录/flag.txt", "FLAG-ZIP")
    (directory / "单文件.txt.gz").write_bytes(gzip.compress(b"FLAG-GZIP"))
    create_pcap(directory / "DNS_HTTP.pcap")
    expected = {"kind": "synthetic_training_samples", "text_line": 2, "text_value": "FLAG-TEXT-2026",
                "metadata_author": "Forensic Fixture", "sqlite_count": 3, "dns_frame": 1,
                "dns_name": "contest.test", "http_frame": 2, "http_uri": "/flag?value=FLAG-PCAP",
                "sha256": {path.name: sha256_file(path) for path in directory.iterdir() if path.is_file()}}
    write_json(directory.parent / "expected.json", expected)
    return expected
