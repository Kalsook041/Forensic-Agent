import sqlite3
import struct
import zlib

import pytest

from forensic_agent.settings import Settings, ToolPaths, Limits


@pytest.fixture
def settings(tmp_path):
    return Settings(work_dir=tmp_path / "案件工作区", limits=Limits(reserve_disk_bytes=0),
                    tools=ToolPaths(tshark="E:/Wireshark/tshark.exe",
                                    exiftool="E:/exiftool-13.59_64/exiftool.exe",
                                    evtxecmd="E:/Forensics/EZTools/net9/EvtxeCmd/EvtxECmd.exe",
                                    seven_zip="C:/Program Files/7-Zip/7z.exe"))


@pytest.fixture
def evidence(tmp_path):
    root = tmp_path / "原始检材 中文"
    root.mkdir()
    (root / "日志.txt").write_text("普通记录\nSECRET-旗标-42\n结束\n", encoding="utf-8")
    (root / "UTF16.txt").write_text("测试\nSECRET-UTF16\n", encoding="utf-16")
    (root / "GB18030.txt").write_bytes("中文检材\n关键词测试\n".encode("gb18030"))
    db = sqlite3.connect(root / "记录.sqlite")
    db.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, body TEXT)")
    db.executemany("INSERT INTO messages(body) VALUES(?)", [("alpha",), ("旗标",), ("gamma",)])
    db.commit()
    db.close()
    def chunk(tag, payload):
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", zlib.crc32(tag + payload))
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
           + chunk(b"tEXt", b"Author\x00Forensic Fixture")
           + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00")) + chunk(b"IEND", b""))
    (root / "图片.png").write_bytes(png)
    return root
