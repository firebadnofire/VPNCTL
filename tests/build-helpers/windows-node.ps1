$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot '../../build-helpers/windows/build.ps1'
$tokens = $null; $parseErrors = $null
$tree = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
# Load definitions only, without running installers or the packaging entrypoint.
foreach ($definition in $tree.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
$NodeVersionRequired = '24.18.0'
$NodeVersionRequiredWithPrefix = 'v24.18.0'
$NasmVersionRequired = '3.02'
$SkipToolInstall = $false
$AssumeYes = $true
$originalPath = $env:PATH
$fixture = Join-Path $env:TEMP ('vpnctl-node-hash-' + [Guid]::NewGuid().ToString('N') + '.txt')
try {
    foreach ($case in @(
        @('AMD64', '', 'x64'),
        @('ARM64', '', 'arm64'),
        @('x86', 'AMD64', 'x64'),
        @('AMD64', 'ARM64', 'arm64')
    )) {
        $actual = Get-NodeArchitecture -ProcessArchitecture $case[0] -NativeArchitecture $case[1]
        if ($actual -ne $case[2]) { throw "Incorrect architecture mapping: $($case -join ', ')" }
    }
    $rejected = $false
    try { Get-NodeArchitecture -ProcessArchitecture 'unknown' -NativeArchitecture '' } catch {
        if ($_.Exception.Message -notlike '*Unsupported Windows architecture*') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'Unknown architecture was accepted.' }
    # Exercise the startup call before installing/selecting Node as build.ps1 does.
    Update-SessionPath
    Set-Content -LiteralPath $fixture -Value 'corrupt archive'
    $rejected = $false
    try { Assert-NodeArchiveHash -Path $fixture -Expected ('0' * 64) } catch {
        if ($_.Exception.Message -notlike '*checksum mismatch*') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'Corrupt archive was accepted.' }
    Ensure-NodeVersion
    if ((& node --version).Trim() -ne 'v24.18.0') { throw 'Pinned Node was not selected.' }
    $selectedPath = (Get-Command node).Source
    $SkipToolInstall = $true
    Update-SessionPath
    Ensure-NodeVersion
    if ((Get-Command node).Source -ne $selectedPath) { throw 'PATH refresh replaced pinned Node.' }
    if ((& node --version).Trim() -ne 'v24.18.0') { throw 'Cached runtime was not reused.' }
    Write-Host 'PASS: architecture detection, startup PATH setup, checksum rejection, pinned runtime selection, and cache reuse.'
} finally {
    $env:PATH = $originalPath
    Remove-Item -LiteralPath $fixture -ErrorAction Stop
}
