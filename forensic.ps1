param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments)
$ErrorActionPreference = 'Stop'
$python = Join-Path $PSScriptRoot '.venv-offline\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { $python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe' }
if (-not (Test-Path -LiteralPath $python)) { throw '虚拟环境不存在。请先执行 scripts/setup-offline.ps1。' }
Push-Location $PSScriptRoot
try {
    # Preserve JSON quotes and Chinese arguments under Windows PowerShell 5.1.
    $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @($Arguments) -Compress)))
    & $python -m forensic_agent --encoded-argv $payload
    exit $LASTEXITCODE
}
finally { Pop-Location }
