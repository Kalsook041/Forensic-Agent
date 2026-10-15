import ctypes
import os
from pathlib import Path
import stat


def is_reparse(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def local_path(value: str | Path, *, must_exist: bool = True) -> Path:
    raw = os.fspath(value)
    if raw.startswith(("\\\\", "//")):
        raise ValueError("禁止 UNC、设备路径和网络检材")
    path = Path(os.path.abspath(raw))
    if os.name == "nt":
        if any(":" in part for part in path.parts[1:]):
            raise ValueError("第一版不接收 NTFS ADS 路径")
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor))
        if drive_type not in (2, 3, 5, 6):
            raise ValueError("只接收本机磁盘路径")
    for item in [*reversed(path.parents), path]:
        if item.exists() or item.is_symlink():
            if is_reparse(item):
                raise ValueError(f"禁止符号链接或重解析点：{item}")
    if must_exist and not path.exists():
        raise FileNotFoundError(path)
    return path


def within(path: Path, root: Path) -> bool:
    return path == root or path.is_relative_to(root)


def safe_member(name: str) -> Path:
    name = name.replace("\\", "/")
    if not name or name.startswith("/") or "\x00" in name:
        raise ValueError("压缩包含空、绝对或 NUL 路径")
    parts = name.rstrip("/").split("/")
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", *(f"COM{i}" for i in "123456789¹²³"),
                *(f"LPT{i}" for i in "123456789¹²³")}
    for part in parts:
        if (part in ("", ".", "..") or part.endswith((".", " "))
                or any(ord(ch) < 32 or ch in ':<>"|?*' for ch in part)
                or part.split(".")[0].rstrip(" .").upper() in reserved):
            raise ValueError(f"不安全的 Windows 压缩成员路径：{name!r}")
    return Path(*parts)
