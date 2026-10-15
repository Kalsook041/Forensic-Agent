$ErrorActionPreference = 'Stop'
# No named parameters: PowerShell otherwise binds native -t to an abbreviated Tool.
# Keeping this a basic script also preserves native flags such as -V.
$rawArguments = @($args)
$Tool = 'list'
$Arguments = @()
if ($rawArguments.Count -gt 0) {
  $Tool = [string]$rawArguments[0]
  if ($rawArguments.Count -gt 1) { $Arguments = @($rawArguments[1..($rawArguments.Count - 1)]) }
}
$allowedTools = @('list','volatility3','mmls','fls','icat','tsk_recover','img_stat','photorec','testdisk','aleapp','ileapp','autopsy','pecmd','mftecmd','recmd','sqlecmd')
if ($Tool -notin $allowedTools) { throw "Unknown tool: $Tool" }
$projectRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $projectRoot 'config\local-tools.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "Missing local tool configuration: $manifestPath" }
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($Tool -eq 'list') {
    $manifest.tools.PSObject.Properties | ForEach-Object {
        [pscustomobject]@{Tool=$_.Name;Version=$_.Value.version;Installed=(Test-Path -LiteralPath $_.Value.executable -PathType Leaf);AgentAdapter=$_.Value.agent_adapter;Path=$_.Value.executable}
    } | Format-Table -AutoSize
    exit 0
}
$entry = $manifest.tools.$Tool
if (-not $entry -or -not (Test-Path -LiteralPath $entry.executable -PathType Leaf)) { throw "Tool is not installed: $Tool" }
$hashStream = [IO.File]::OpenRead([string]$entry.executable)
try {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $actualHash = ([BitConverter]::ToString($hasher.ComputeHash($hashStream))).Replace('-', '').ToLowerInvariant() }
    finally { $hasher.Dispose() }
}
finally { $hashStream.Dispose() }
if ($actualHash -ne $entry.sha256) { throw "Tool has changed since configuration: $Tool. Verify the new installation before updating its hash." }
$savedEnvironment = @{}
try {
    if ($entry.environment) {
        foreach ($property in $entry.environment.PSObject.Properties) {
            $savedEnvironment[$property.Name] = [Environment]::GetEnvironmentVariable($property.Name, 'Process')
            [Environment]::SetEnvironmentVariable($property.Name, [string]$property.Value, 'Process')
        }
    }
    if ($Tool -eq 'volatility3') {
        $cacheIndex = [Array]::IndexOf(@($entry.arguments), '--cache-path')
        if ($cacheIndex -lt 0 -or $cacheIndex + 1 -ge @($entry.arguments).Count) { throw 'Missing Volatility cache configuration' }
        New-Item -ItemType Directory -Path $entry.arguments[$cacheIndex + 1] -Force | Out-Null
    }
    $launchArguments = @($entry.arguments) + @($Arguments)
    & $entry.executable @launchArguments
    $toolExitCode = $LASTEXITCODE
    if ($null -eq $toolExitCode) { $toolExitCode = 0 }
}
finally {
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
}
exit $toolExitCode
