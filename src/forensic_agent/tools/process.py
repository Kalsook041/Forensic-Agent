from dataclasses import dataclass
import ctypes
import base64
import json
from ctypes import wintypes
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time


class WindowsJob:
    """A fail-closed job. The worker waits for stdin until assignment succeeds."""

    def __init__(self, limits):
        if os.name != "nt":
            raise RuntimeError("受限执行器只支持 Windows；不会静默退回不受限执行")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                        ctypes.c_void_p, wintypes.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())

        class Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                        ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD), ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

        class Io(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                        ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                         "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class Extended(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", Io),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        class Cpu(ctypes.Structure):
            _fields_ = [("ControlFlags", wintypes.DWORD), ("CpuRate", wintypes.DWORD)]

        extended = Extended()
        extended.BasicLimitInformation.LimitFlags = 0x2000 | 0x100 | 0x200 | 0x8
        extended.BasicLimitInformation.ActiveProcessLimit = 8
        extended.ProcessMemoryLimit = limits.memory_bytes
        extended.JobMemoryLimit = limits.memory_bytes
        cpu = Cpu(1 | 4, limits.cpu_percent * 100)
        try:
            for information_class, value in ((9, extended), (15, cpu)):
                if not self.kernel.SetInformationJobObject(self.handle, information_class,
                                                           ctypes.byref(value), ctypes.sizeof(value)):
                    raise ctypes.WinError(ctypes.get_last_error())
        except BaseException:
            self.close()
            raise

    def assign(self, pid):
        process = self.kernel.OpenProcess(0x0100 | 0x0001, False, pid)
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self.kernel.AssignProcessToJobObject(self.handle, process):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.kernel.CloseHandle(process)

    def terminate(self):
        if self.handle:
            self.kernel.TerminateJobObject(self.handle, 1)

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


@dataclass
class Captured:
    stdout: bytes
    stderr: bytes
    returncode: int
    stopped: str | None


def capture(argv: list[str], *, cwd: Path, env: dict, timeout: float, max_output: int,
            input_bytes: bytes | None = None, job: WindowsJob | None = None,
            stdout_path: Path | None = None, stderr_path: Path | None = None,
            artifact_root: Path | None = None, artifact_bytes: int = 0,
            reserve_disk_bytes: int = 0) -> Captured:
    """Capture trusted argv; direct tools start only after Job assignment."""
    if job is not None:
        return _capture(argv, cwd=cwd, env=env, timeout=timeout, max_output=max_output,
                        input_bytes=input_bytes, job=job, stdout_path=stdout_path,
                        stderr_path=stderr_path, artifact_root=artifact_root,
                        artifact_bytes=artifact_bytes, reserve_disk_bytes=reserve_disk_bytes)
    from ..settings import Limits

    # The proxy contains only trusted startup code and blocks on stdin. Sending
    # its payload is the release gate, after _capture successfully assigns it.
    payload = json.dumps({"argv": argv, "input": base64.b64encode(input_bytes or b"").decode("ascii")},
                         ensure_ascii=True).encode("ascii")
    if len(payload) > 16 * 1024**2:
        raise ValueError("受限启动参数超过 16 MiB")
    owned_job = WindowsJob(Limits())
    try:
        return _capture([sys.executable, "-I", str(Path(__file__).with_name("_startup_proxy.py"))],
                        cwd=cwd, env=env, timeout=timeout, max_output=max_output,
                        input_bytes=payload, job=owned_job, stdout_path=stdout_path,
                        stderr_path=stderr_path, artifact_root=artifact_root,
                        artifact_bytes=artifact_bytes, reserve_disk_bytes=reserve_disk_bytes)
    finally:
        owned_job.close()


def _capture(argv: list[str], *, cwd: Path, env: dict, timeout: float, max_output: int,
             input_bytes: bytes | None, job: WindowsJob,
             stdout_path: Path | None, stderr_path: Path | None,
             artifact_root: Path | None, artifact_bytes: int,
             reserve_disk_bytes: int) -> Captured:
    def artifact_failure():
        if artifact_root is None:
            return None
        try:
            total_bytes = 0
            for directory, directories, filenames in os.walk(artifact_root, followlinks=False):
                for name in [*directories, *filenames]:
                    path = Path(directory) / name
                    if path.is_symlink() or path.is_junction():
                        return "artifact_link"
                for name in filenames:
                    total_bytes += (Path(directory) / name).stat().st_size
                    if total_bytes > artifact_bytes:
                        return "artifact_output_limit"
            if shutil.disk_usage(artifact_root).free < reserve_disk_bytes:
                return "disk_reserve"
        except OSError:
            return "artifact_storage_failure"
        return None

    if reason := artifact_failure():
        return Captured(b"", b"", -1, reason)
    process = subprocess.Popen(argv, cwd=cwd, env=env, shell=False, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    buffers = [bytearray(), bytearray()]
    lock = threading.Lock()
    overflow = threading.Event()
    failures = []
    total = 0

    def drain(pipe, index, destination):
        nonlocal total
        stream = None
        try:
            stream = destination.open("xb") if destination else None
            while chunk := pipe.read(65536):
                with lock:
                    remaining = max(0, max_output - total)
                    kept = chunk[:remaining]
                    total += len(chunk)
                    buffers[index].extend(kept)
                    if stream:
                        stream.write(kept)
                        stream.flush()
                    if total > max_output:
                        overflow.set()
        except (OSError, ValueError) as exc:
            failures.append(str(exc))
            overflow.set()
        finally:
            if stream:
                stream.close()
            pipe.close()

    threads = [threading.Thread(target=drain, args=(pipe, i, path), daemon=True)
               for i, (pipe, path) in enumerate(((process.stdout, stdout_path), (process.stderr, stderr_path)))]
    stopped = None
    writer = None
    deadline = time.monotonic() + timeout
    try:
        if job:
            job.assign(process.pid)
        for thread in threads:
            thread.start()
        def feed():
            try:
                if input_bytes is not None:
                    process.stdin.write(input_bytes)
            except (BrokenPipeError, OSError):
                pass
            finally:
                process.stdin.close()
        writer = threading.Thread(target=feed, daemon=True)
        writer.start()
        while process.poll() is None:
            artifact_reason = artifact_failure()
            if overflow.is_set() or time.monotonic() >= deadline or artifact_reason:
                stopped = artifact_reason or ("output_limit" if overflow.is_set() else "timeout")
                if job:
                    job.terminate()
                else:
                    process.kill()
                break
            time.sleep(0.02)
        process.wait(timeout=5)
        if job:
            # Kill any descendants that outlive a normally exited root and hold pipes open.
            job.terminate()
        for thread in threads:
            thread.join(timeout=5)
        writer.join(timeout=5)
        if any(thread.is_alive() for thread in threads):
            stopped = stopped or "pipe_not_closed"
        if overflow.is_set():
            stopped = stopped or "output_limit"
        stopped = stopped or artifact_failure()
        if failures:
            stopped = "output_storage_failure: " + "; ".join(failures)
        return Captured(bytes(buffers[0]), bytes(buffers[1]), process.returncode, stopped)
    finally:
        # Also runs on assignment, writer, wait, or storage failures. Terminate
        # the whole Job before touching buffered pipe locks owned by threads.
        job.terminate()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if writer is not None:
            writer.join(timeout=5)
        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=5)
        if (writer is None or not writer.is_alive()) and process.stdin and not process.stdin.closed:
            process.stdin.close()
        for thread, pipe in zip(threads, (process.stdout, process.stderr)):
            # Never block the caller acquiring a reader's buffered pipe lock.
            if not thread.is_alive() and pipe and not pipe.closed:
                pipe.close()


def clean_environment(step_dir: Path) -> dict:
    env = os.environ.copy()
    for key in list(env):
        if key.upper() in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "PYTHONPATH", "PYTHONHOME",
                           "PERL5LIB", "PERL5OPT", "EXIFTOOL_HOME"}:
            env.pop(key, None)
    for key in ("LC_ALL", "LC_CTYPE", "LANG"):
        env[key] = "C"
    env["PYTHONUTF8"] = "1"
    env["DOTNET_DISABLE_GUI_ERRORS"] = "1"
    env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
    env["HOME"] = str(step_dir)
    env["USERPROFILE"] = str(step_dir)
    env["APPDATA"] = str(step_dir / "appdata")
    env["LOCALAPPDATA"] = str(step_dir / "localappdata")
    env["TEMP"] = env["TMP"] = str(step_dir / "tmp")
    for name in ("appdata", "localappdata", "tmp"):
        (step_dir / name).mkdir(exist_ok=True)
    env["WIRESHARK_CONFIG_DIR"] = str(step_dir / "appdata")
    return env
