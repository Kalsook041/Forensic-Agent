import sqlite3
import struct
import zlib
import ctypes
from ctypes import wintypes
import os
from types import SimpleNamespace

import pytest

from forensic_agent.settings import Settings, ToolPaths, Limits


@pytest.fixture
def process_tree_probe(tmp_path):
    """Prove a descendant reached user code, then check its OS exit state."""
    ready = tmp_path / "child-ready.pid"
    marker = tmp_path / "child-finished"
    child = ("import os,time; from pathlib import Path; "
             f"ready=Path({str(ready)!r}); pending=ready.with_suffix('.tmp'); "
             "pending.write_text(str(os.getpid())); pending.replace(ready); "
             f"time.sleep(30); Path({str(marker)!r}).touch()")

    def script(root_waits, gated=False):
        return ("import sys,subprocess,time; from pathlib import Path; "
                + ("sys.stdin.readline(); " if gated else "")
                + f"subprocess.Popen([sys.executable,'-I','-c',{child!r}]); "
                + f"ready=Path({str(ready)!r})\n"
                + "deadline=time.monotonic()+5\n"
                + "while not ready.exists() and time.monotonic()<deadline: time.sleep(0.01)\n"
                + "assert ready.exists(), 'child never became ready'\n"
                + "print('started',flush=True)\n"
                + ("time.sleep(30)" if root_waits else "sys.exit(0)"))

    def assert_stopped():
        assert os.name == "nt"
        assert ready.is_file(), "The test must exercise an actually started descendant"
        child_pid = int(ready.read_text())
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x00100000, False, child_pid)  # SYNCHRONIZE
        if not handle:
            # ERROR_INVALID_PARAMETER means the process no longer exists.
            assert ctypes.get_last_error() == 87, "Could not verify the descendant's exit"
        else:
            try:
                assert kernel.WaitForSingleObject(handle, 1000) == 0, "Descendant survived Job cleanup"
            finally:
                kernel.CloseHandle(handle)
        assert not marker.exists()

    return SimpleNamespace(script=script, assert_stopped=assert_stopped, child_script=child, ready=ready)


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
