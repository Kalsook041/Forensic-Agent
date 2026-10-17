param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments)
$ErrorActionPreference = 'Stop'

# Preserve all workstation settings; only the operator-selected snapshot budget changes.
$baseConfig = Join-Path $PSScriptRoot 'config\default.toml'
$content = [IO.File]::ReadAllText($baseConfig, [Text.Encoding]::UTF8)
$pattern = '(?m)^[ \t]*snapshot_bytes[ \t]*=[ \t]*\d+[^\r\n]*'
if ([regex]::Matches($content, $pattern).Count -ne 1) {
    throw 'Expected exactly one snapshot_bytes setting in config/default.toml.'
}
if (@($Arguments | Where-Object { $_ -eq '--config' -or $_ -like '--config=*' }).Count) {
    throw 'This launcher selects its own 64 GiB profile. Use forensic-gui.ps1 for a custom configuration.'
}
$profileContent = [regex]::Replace($content, $pattern, 'snapshot_bytes = 68719476736')
$bytes = [Text.Encoding]::UTF8.GetBytes($profileContent)
$hasher = [Security.Cryptography.SHA256]::Create()
try { $digest = ([BitConverter]::ToString($hasher.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
finally { $hasher.Dispose() }

# A content-addressed profile keeps an existing GUI's child-process configuration stable.
# Keep it directly under config/ so knowledge_dir still resolves to the project knowledge/.
$profile = Join-Path $PSScriptRoot ("config\local-large-evidence-{0}.toml" -f $digest)
if (Test-Path -LiteralPath $profile) {
    if ([IO.File]::ReadAllText($profile, [Text.Encoding]::UTF8) -cne $profileContent) {
        throw 'Existing large-evidence profile does not match its content digest.'
    }
}
else {
    [IO.File]::WriteAllText($profile, $profileContent, (New-Object Text.UTF8Encoding($false)))
}
& (Join-Path $PSScriptRoot 'forensic-gui.ps1') --config $profile @Arguments
exit $LASTEXITCODE
