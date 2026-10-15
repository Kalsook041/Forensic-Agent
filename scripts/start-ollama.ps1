param([string]$OllamaPath)
$ErrorActionPreference = 'Stop'
if (-not $OllamaPath) {
    $command = Get-Command ollama.exe -ErrorAction SilentlyContinue
    if ($command) { $OllamaPath = $command.Source }
    elseif (Test-Path -LiteralPath 'E:\Ollama\app\ollama.exe') { $OllamaPath = 'E:\Ollama\app\ollama.exe' }
    else { $OllamaPath = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe' }
}
if (-not (Test-Path -LiteralPath $OllamaPath -PathType Leaf)) { throw '尚未找到 ollama.exe。安装后传入 -OllamaPath 绝对路径。' }
if (Get-NetTCPConnection -LocalPort 11434 -State Listen -ErrorAction SilentlyContinue) {
    throw '11434 已有服务监听。请先自行退出已有 Ollama，再启动此本地专用服务；本脚本不会终止其他进程。'
}
$env:OLLAMA_HOST = '127.0.0.1:11434'
$env:OLLAMA_NO_CLOUD = '1'
$env:OLLAMA_NUM_PARALLEL = '1'
$env:OLLAMA_MAX_LOADED_MODELS = '1'
$env:OLLAMA_CONTEXT_LENGTH = '4096'
foreach ($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
Write-Output '启动仅监听 127.0.0.1 的 Ollama；不下载模型、不修改现有模型目录。'
$projectRoot = Split-Path -Parent $PSScriptRoot
$stateDir = Join-Path $projectRoot 'local-state'
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
$upAdapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up')
$process = Start-Process -FilePath $OllamaPath -ArgumentList 'serve' -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput (Join-Path $stateDir 'ollama.stdout.log') `
    -RedirectStandardError (Join-Path $stateDir 'ollama.stderr.log')
$ready = $false
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    Start-Sleep -Milliseconds 500
    if ($process.HasExited) { throw 'Ollama 启动失败，请查看 local-state/ollama.stderr.log。' }
    $listeners = @(Get-NetTCPConnection -LocalPort 11434 -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -gt 0 -and @($listeners | Where-Object { $_.OwningProcess -ne $process.Id -or $_.LocalAddress -ne '127.0.0.1' }).Count -eq 0) {
        $ready = $true
        break
    }
}
if (-not $ready) { throw 'Ollama 尚未在回环地址就绪；不记录冷启动成功。请检查进程与日志。' }
@{pid=$process.Id;startedUtc=$process.StartTime.ToUniversalTime().ToString('o');ollamaPath=$OllamaPath;
  network_adapter_count=$upAdapters.Count;host='127.0.0.1:11434';cloudDisabled=$true} |
  ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stateDir 'ollama-session.json') -Encoding utf8
Write-Output "已在后台启动 PID $($process.Id)。服务日志保存在 $stateDir；本终端可以关闭。"
