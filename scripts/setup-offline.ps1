param([string]$PythonExe, [string]$EnvironmentPath = '.venv-offline')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $PythonExe) {
    $known = Join-Path $env:APPDATA 'uv\python\cpython-3.12.13-windows-x86_64-none\python.exe'
    if (Test-Path -LiteralPath $known) { $PythonExe = $known }
    else { $PythonExe = (Get-Command python.exe -ErrorAction Stop).Source }
}
$target = if ([IO.Path]::IsPathRooted($EnvironmentPath)) { $EnvironmentPath } else { Join-Path $projectRoot $EnvironmentPath }
if (Test-Path -LiteralPath $target) { throw '目标虚拟环境已存在；不会覆盖。请选择新的 -EnvironmentPath。' }
& $PythonExe -c "import sys,struct; assert sys.version_info[:2] == (3,12) and struct.calcsize('P') == 8, 'Offline wheelhouse requires CPython 3.12 x64'"
if ($LASTEXITCODE -ne 0) { throw 'Python 版本不满足要求。' }
$offline = Join-Path $projectRoot 'offline'
$hashes = Get-Content -LiteralPath (Join-Path $offline 'SHA256SUMS.json') -Raw | ConvertFrom-Json
foreach ($property in $hashes.PSObject.Properties) {
    $wheel = Join-Path (Join-Path $offline 'wheelhouse') $property.Name
    if ((Get-FileHash -LiteralPath $wheel -Algorithm SHA256).Hash -ine $property.Value) { throw "离线包哈希不匹配：$($property.Name)" }
}
& $PythonExe -m venv $target
if ($LASTEXITCODE -ne 0) { throw '创建虚拟环境失败。' }
$targetPython = Join-Path $target 'Scripts\python.exe'
& $targetPython -m pip --isolated install --no-index --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: --find-links (Join-Path $offline 'wheelhouse') -r (Join-Path $offline 'requirements.lock')
if ($LASTEXITCODE -ne 0) { throw '离线安装失败，请保留日志排查。' }
Write-Output "离线环境已创建：$targetPython"
