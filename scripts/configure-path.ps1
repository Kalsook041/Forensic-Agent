param([switch]$Restore, [string]$Backup)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$stateDir = Join-Path $projectRoot 'local-state'
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
if ($Restore) {
    if (-not $Backup) { throw '恢复需要 -Backup 指定本脚本生成的备份文件。' }
    $saved = Get-Content -LiteralPath $Backup -Raw | ConvertFrom-Json
    [Environment]::SetEnvironmentVariable('Path', $saved.userPath, 'User')
    Write-Output '已恢复备份中的用户 PATH。请重新打开终端。'
    exit
}
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$backupPath = Join-Path $stateDir ('path-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '.json')
@{userPath=$userPath;machinePath=$machinePath;createdUtc=[DateTime]::UtcNow.ToString('o')} |
    ConvertTo-Json | Set-Content -LiteralPath $backupPath -Encoding utf8
$entries = @($userPath -split ';' | Where-Object { $_ })
$combined = @((($userPath + ';' + $machinePath) -split ';') | Where-Object { $_ } |
    ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')).TrimEnd('\') })
$candidates = @('C:\Program Files\7-Zip', 'E:\Wireshark', 'E:\exiftool-13.59_64')
$candidates += @('E:\Ollama\app','E:\Forensics\EZTools\net9',
                 'E:\Forensics\EZTools\net9\EvtxeCmd','E:\Forensics\EZTools\net9\RECmd',
                 'E:\Forensics\EZTools\net9\SQLECmd')
$ollama = Get-Command ollama.exe -ErrorAction SilentlyContinue
if ($ollama) { $candidates += Split-Path -Parent $ollama.Source }
$candidates += Join-Path $env:LOCALAPPDATA 'Programs\Ollama'
$added = @()
foreach ($directory in $candidates) {
    if ((Test-Path -LiteralPath $directory -PathType Container) -and -not ($combined -icontains $directory.TrimEnd('\'))) {
        $entries += $directory
        $combined += $directory.TrimEnd('\')
        $added += $directory
    }
}
if ($added.Count -gt 0) { [Environment]::SetEnvironmentVariable('Path', ($entries -join ';'), 'User') }
@{backup=$backupPath;added=$added;note='保留已有 PATH 顺序。新终端或重新启动 Codex 后生效。'} | ConvertTo-Json
