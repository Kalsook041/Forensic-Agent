"""Exercise the real Windows PowerShell 5.1 launcher, including JSON quoting."""
import json
import os
from pathlib import Path
import subprocess
import sys


root = Path(__file__).resolve().parents[1]
state = root / "local-state"
state.mkdir(exist_ok=True)
probe = state / "launcher-probe.ps1"
probe.write_text("[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)\n"
                 + "& '" + str(root / "forensic.ps1").replace("'", "''")
                 + "' tool search --evidence '" + str(root / "examples/检材/线索.txt").replace("'", "''")
                 + "' --params '{\"keyword\":\"FLAG\"}'\nexit $LASTEXITCODE\n", encoding="utf-8-sig")
powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
try:
    completed = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                "-File", str(probe)], shell=False, capture_output=True, timeout=60,
                               creationflags=subprocess.CREATE_NO_WINDOW)
finally:
    probe.unlink(missing_ok=True)
if completed.returncode:
    sys.stderr.buffer.write(completed.stdout + completed.stderr)
    raise SystemExit(completed.returncode)
output = json.loads(completed.stdout.decode("utf-8-sig"))
case = json.loads((Path(output["case"]) / "case.json").read_text(encoding="utf-8"))
assert output["status"] == "ok" and case["steps"][0]["evidence"][0]["data"]["text"] == "FLAG-TEXT-2026"
(state / "launcher-check.json").write_text(json.dumps({"passed": True, "shell": "Windows PowerShell 5.1",
    "result": output}, ensure_ascii=False, indent=2), encoding="utf-8")
print("Windows PowerShell 5.1 launcher: Chinese path + JSON parameters passed")
