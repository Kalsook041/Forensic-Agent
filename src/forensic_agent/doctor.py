import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import tempfile

from .agent.ollama import OllamaClient
from .evidence.store import sha256_file
from .tools.process import capture, clean_environment


VERSION_ARGUMENTS = {"tshark": ["--version"], "capinfos": ["--version"],
                     "exiftool": ["-config", "", "-ver"], "seven_zip": ["i"], "ollama": ["--version"],
                     **{key: ["--version"] for key in ("evtxecmd", "pecmd", "mftecmd", "recmd", "sqlecmd")}}
COMMAND_NAMES = {"tshark": "tshark.exe", "capinfos": "capinfos.exe", "exiftool": "exiftool.exe",
                 "seven_zip": "7z.exe", "ollama": "ollama.exe", "evtxecmd": "EvtxECmd.exe",
                 "pecmd": "PECmd.exe", "mftecmd": "MFTECmd.exe", "recmd": "RECmd.exe", "sqlecmd": "SQLECmd.exe"}


def find_tools(settings):
    guesses = {"tshark": ["E:/Wireshark/tshark.exe", "C:/Program Files/Wireshark/tshark.exe"],
               "capinfos": ["E:/Wireshark/capinfos.exe", "C:/Program Files/Wireshark/capinfos.exe"],
               "exiftool": ["E:/exiftool-13.59_64/exiftool.exe"],
               "seven_zip": ["C:/Program Files/7-Zip/7z.exe"],
               "ollama": [str(Path(os.environ.get("LOCALAPPDATA", "C:/")) / "Programs/Ollama/ollama.exe")]}
    ez_root = Path("E:/Forensics/EZTools/net9")
    guesses.update({"evtxecmd": [str(ez_root / "EvtxeCmd/EvtxECmd.exe")],
                    "pecmd": [str(ez_root / "PECmd.exe")], "mftecmd": [str(ez_root / "MFTECmd.exe")],
                    "recmd": [str(ez_root / "RECmd/RECmd.exe")], "sqlecmd": [str(ez_root / "SQLECmd/SQLECmd.exe")]})
    if os.name == "nt":
        import winreg
        for hive, key_name in ((winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                               (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")):
            try:
                with winreg.OpenKey(hive, key_name) as root:
                    for index in range(winreg.QueryInfoKey(root)[0]):
                        try:
                            with winreg.OpenKey(root, winreg.EnumKey(root, index)) as child:
                                display = str(winreg.QueryValueEx(child, "DisplayName")[0]).lower()
                                location = str(winreg.QueryValueEx(child, "InstallLocation")[0])
                                for key, token in (("tshark", "wireshark"), ("capinfos", "wireshark"),
                                                   ("seven_zip", "7-zip"), ("ollama", "ollama")):
                                    if token in display and location:
                                        guesses[key].append(str(Path(location) / COMMAND_NAMES[key]))
                        except OSError:
                            continue
            except OSError:
                pass
    found = {}
    for key, command in COMMAND_NAMES.items():
        configured = getattr(settings.tools, key)
        candidates = [configured, shutil.which(command), *guesses[key]]
        found[key] = next((str(Path(x).absolute()) for x in candidates if x and Path(x).is_file()), None)
    return found


def inspect_environment(settings):
    found = find_tools(settings)
    info = {"python": {"executable": __import__("sys").executable, "version": __import__("sys").version},
            "tools": {}, "dependencies": {}, "work_dir": str(settings.work_dir),
            "offline_acceptance": "未验证物理断网冷启动；doctor 不会自动断网", "warnings": []}
    with tempfile.TemporaryDirectory(prefix="forensic-doctor-") as folder:
        cwd = Path(folder)
        for key, path in found.items():
            item = {"configured_path": getattr(settings.tools, key), "detected_path": path, "available": bool(path)}
            if path:
                try:
                    captured = capture([path, *VERSION_ARGUMENTS[key]], cwd=cwd, env=clean_environment(cwd),
                                       timeout=5, max_output=65536)
                    text = (captured.stdout + captured.stderr).decode("utf-8", errors="replace")
                    item.update(version_output="\n".join(text.splitlines()[:8]), exit_code=captured.returncode,
                                stopped=captured.stopped, executable_sha256=sha256_file(Path(path)))
                    item["available"] = not captured.stopped and captured.returncode == 0
                except (OSError, RuntimeError, ValueError) as exc:
                    item.update(available=False, error=f"{type(exc).__name__}: {exc}")
            info["tools"][key] = item
    for name in ("pydantic", "httpx", "charset-normalizer", "python-evtx", "defusedxml"):
        try:
            info["dependencies"][name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            info["dependencies"][name] = None
    client = OllamaClient(settings.model)
    try:
        info["model"] = {"available": True, **client.discover()}
    except Exception as exc:
        info["model"] = {"available": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        client.close()
    if os.environ.get("OLLAMA_HOST", "").startswith("0.0.0.0"):
        info["warnings"].append("当前继承的 OLLAMA_HOST 为全网卡地址；请用 scripts/start-ollama.ps1 启动项目专用本地服务")
    if settings.work_dir.exists():
        info["work_free_bytes"] = shutil.disk_usage(settings.work_dir).free
    else:
        info["warnings"].append("工作目录尚未创建；首次建案时创建")
    info["warnings"].append("仅检测已支持适配器的工具，不承诺枚举整台电脑的所有软件")
    return info


def network_interfaces():
    if os.name != "nt":
        return {"verified": False, "reason": "仅支持 Windows"}
    # Fixed script, no untrusted interpolation, and no active Internet probes.
    script = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); @(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up' | Select-Object Name,InterfaceDescription,Status) | ConvertTo-Json -Compress"
    executable = str(Path(os.environ.get("SystemRoot", "C:/Windows")) /
                     "System32/WindowsPowerShell/v1.0/powershell.exe")
    try:
        with tempfile.TemporaryDirectory(prefix="forensic-network-doctor-") as folder:
            cwd = Path(folder)
            completed = capture([executable, "-NoProfile", "-NonInteractive", "-Command", script],
                                cwd=cwd, env=clean_environment(cwd), timeout=15, max_output=65536)
        if completed.stopped:
            raise RuntimeError(completed.stopped)
        if completed.returncode:
            raise RuntimeError(completed.stderr.decode("utf-8", errors="replace")[:500])
        raw = completed.stdout.decode("utf-8-sig", errors="replace").strip()
        value = json.loads(raw) if raw else []
        return {"verified": True, "up_adapters": value if isinstance(value, list) else [value]}
    except Exception as exc:
        return {"verified": False, "reason": str(exc)}
