"""Development-only packager. Never imported by the forensic runtime."""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import subprocess
import sys
import tomllib
import zipfile

from packaging.utils import canonicalize_name, parse_wheel_filename

root = Path(__file__).resolve().parents[1]
offline = root / "offline"
wheels = offline / "wheelhouse"
wheels.mkdir(parents=True, exist_ok=True)
packages = sorted((canonicalize_name(item.metadata["Name"]), item.version)
                  for item in importlib.metadata.distributions()
                  if canonicalize_name(item.metadata["Name"]) not in {"forensic-agent", "pip"})
plain = offline / "requirements-pinned.txt"
plain.write_text("".join(f"{name}=={version}\n" for name, version in packages), encoding="utf-8")
commands = [
    [sys.executable, "-m", "pip", "wheel", "--no-deps", "--disable-pip-version-check", "--wheel-dir", str(wheels),
     "-r", str(plain)],
    [sys.executable, "-m", "pip", "wheel", "--no-deps", "--no-build-isolation", "--disable-pip-version-check",
     "--wheel-dir", str(wheels), str(root)],
]
for command in commands:
    subprocess.run(command, cwd=root, shell=False, check=True)
hashes = {}
lines = []
licenses = offline / "licenses"
licenses.mkdir(exist_ok=True)
project_version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
expected = {**dict(packages), "forensic-agent": project_version}
for wheel in sorted(wheels.glob("*.whl")):
    name, version, _, _ = parse_wheel_filename(wheel.name)
    if expected.get(str(name)) != str(version):
        continue  # Preserve older local wheels without adding conflicting versions to the lock.
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    hashes[wheel.name] = digest
    lines.append(f"{name}=={version} --hash=sha256:{digest}\n")
    with zipfile.ZipFile(wheel) as package:
        for member in package.namelist():
            if ".dist-info/" in member and ("license" in member.lower() or "copying" in member.lower()) and not member.endswith("/"):
                (licenses / (wheel.stem + "--" + Path(member).name)).write_bytes(package.read(member))
(offline / "requirements.lock").write_text("".join(lines), encoding="utf-8")
(offline / "SHA256SUMS.json").write_text(json.dumps(hashes, indent=2), encoding="utf-8")
print(f"Offline wheelhouse ready: {len(hashes)} wheels, including forensic-agent")
