"""Opt-in functional checks for this host's installed tools; keeps each run's evidence."""
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "local-state" / "launcher-checks" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
OUT.mkdir(parents=True)
image = OUT / "Input With Spaces" / "sample image.img"
image.parent.mkdir()
shutil.copyfile("E:/Forensics/Validation/20261015/image/synthetic-fat12.img", image)
launcher = str(ROOT / "scripts/forensic-tools.ps1")
shells = ["C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", shutil.which("pwsh.exe")]
assert all(shells), "Both Windows PowerShell and current PowerShell are required"
results = []
for index, shell in enumerate(shells):
    for name, args, success, expected in (
        ("default-list", [], True, b"mmls"),
        ("version", ["mmls", "-V"], True, b"4.14.0"),
        ("disk-type-and-spaces", ["mmls", "-t", "dos", str(image)], True, b"0000002048"),
        ("native-failure", ["icat", "-o", "2048", str(image), "999999"], False, b"metadata address"),
        ("unknown-tool", ["not-a-tool"], False, b"unknown tool"),
    ):
        run = subprocess.run([shell, "-NoProfile", "-File", launcher, *args], capture_output=True, timeout=60)
        (OUT / f"{index}-{name}.stdout").write_bytes(run.stdout)
        (OUT / f"{index}-{name}.stderr").write_bytes(run.stderr)
        results.append({"shell": shell, "test": name, "exit_code": run.returncode,
                        "passed": (run.returncode == 0) == success and expected in (run.stdout + run.stderr).lower()})
    for tool, source, marker in (
        ("aleapp", "android-input", "FORENSIC-ANDROID-20261015"),
        ("ileapp", "ios-input", "FORENSIC-IOS-20261015"),
    ):
        output = OUT / f"{index}-{tool} output"
        output.mkdir()
        with (OUT / f"{index}-{tool}.stdout").open("wb") as stdout, (OUT / f"{index}-{tool}.stderr").open("wb") as stderr:
            run = subprocess.run([shell, "-NoProfile", "-File", launcher, tool, "-t", "fs", "-i",
                                  f"E:/Forensics/Validation/20261015/mobile/{source}", "-o", str(output)],
                                 stdout=stdout, stderr=stderr, timeout=180)
        matches = [str(path) for path in output.rglob("*.tsv")
                   if marker in path.read_text(encoding="utf-8", errors="replace")]
        results.append({"shell": shell, "test": tool, "exit_code": run.returncode,
                        "passed": run.returncode == 0 and bool(matches), "matches": matches})
    check = OUT / f"{index}-environment.ps1"
    check.write_text("$env:__COMPAT_LAYER = 'ForensicValidationMarker'\n"
                     f"& '{launcher}' photorec /version | Out-Null\n"
                     "if ($LASTEXITCODE -ne 0) { exit 98 }\n"
                     "if ($env:__COMPAT_LAYER -ne 'ForensicValidationMarker') { exit 99 }\nexit 0\n",
                     encoding="utf-8-sig")
    run = subprocess.run([shell, "-NoProfile", "-File", str(check)], capture_output=True, timeout=60)
    results.append({"shell": shell, "test": "environment-restored", "exit_code": run.returncode,
                    "passed": run.returncode == 0})
(OUT / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
print(json.dumps({"passed": all(item["passed"] for item in results), "checks": len(results), "evidence": str(OUT)}))
raise SystemExit(not all(item["passed"] for item in results))
