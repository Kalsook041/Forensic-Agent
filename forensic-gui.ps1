param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments)
$ErrorActionPreference = 'Stop'
$python = Join-Path $PSScriptRoot '.venv-offline\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { $python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe' }
$previousPythonPath = $env:PYTHONPATH
Push-Location $PSScriptRoot
try {
    if (-not (Test-Path -LiteralPath $python)) { throw 'Python environment missing. Run scripts/setup-offline.ps1 first.' }
    # Use the current local UI and core together; workers inherit this source path.
    $env:PYTHONPATH = Join-Path $PSScriptRoot 'src'
    & $python -m forensic_agent.gui @Arguments
    if ($LASTEXITCODE -ne 0) { throw "GUI exited with code $LASTEXITCODE" }
}
catch {
    $logDirectory = Join-Path $PSScriptRoot 'local-state'
    New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
    $message = $_.Exception.Message
    Add-Content -LiteralPath (Join-Path $logDirectory 'gui-launcher.log') -Value "$(Get-Date -Format o) $message" -Encoding UTF8
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show("GUI could not start.`n$message`nSee local-state/gui-launcher.log", 'Forensic Agent') | Out-Null
    exit 1
}
finally {
    $env:PYTHONPATH = $previousPythonPath
    Pop-Location
}
