$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot '../../build-helpers/windows/build.ps1'
$tokens = $null; $parseErrors = $null
$tree = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($definition in $tree.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('vpnctl-helper-test-' + [Guid]::NewGuid().ToString('N'))
$previousBundle = $env:VAM_HELPER_BUNDLE_DIR
try {
    New-Item -ItemType Directory -Path $fixture | Out-Null
    if (Test-HelperPayloads $fixture) { throw 'Missing payloads accepted.' }
    $env:VAM_HELPER_BUNDLE_DIR = $fixture
    $rejected = $false
    try { Ensure-HelperBundles $fixture } catch {
        if ($_.Exception.Message -notlike '*is incomplete*') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'Incomplete explicit bundle directory accepted.' }
    foreach ($entry in @(@('x86_64', 62), @('aarch64', 183))) {
        $directory = Join-Path $fixture "$($entry[0])-unknown-linux-musl"
        New-Item -ItemType Directory -Path $directory | Out-Null
        $bytes = New-Object byte[] 64
        $bytes[0] = 127; $bytes[1] = 69; $bytes[2] = 76; $bytes[3] = 70
        $bytes[4] = 2; $bytes[5] = 1; $bytes[18] = $entry[1]
        [IO.File]::WriteAllBytes((Join-Path $directory 'vam-server'), $bytes)
    }
    if (-not (Test-HelperPayloads $fixture)) { throw 'Matching ELF headers rejected.' }
    Ensure-HelperBundles $fixture
    $path = Join-Path $fixture 'aarch64-unknown-linux-musl\vam-server'
    $bytes[18] = 62
    [IO.File]::WriteAllBytes($path, $bytes)
    $rejected = $false
    try { Test-HelperPayloads $fixture } catch {
        if ($_.Exception.Message -notlike '*Invalid aarch64 Linux ELF*') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'Wrong architecture accepted.' }
    $entrypoint = $tree.Extent.Text.Substring($tree.Extent.Text.LastIndexOf("`nUpdate-SessionPath"))
    if ($entrypoint.IndexOf('Ensure-HelperBundles') -gt $entrypoint.IndexOf('Ensure-VisualCppTools') -or
        $entrypoint.IndexOf('Ensure-HelperBundles') -lt 0) { throw 'Helper preflight must precede tool installation and verification.' }
    Write-Host 'PASS: missing bundles, explicit bundle validation, both ELF architectures, wrong architecture rejection, and early preflight ordering.'
} finally {
    $env:VAM_HELPER_BUNDLE_DIR = $previousBundle
    $resolved = [IO.Path]::GetFullPath($fixture)
    $prefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\vpnctl-helper-test-'
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Unsafe test cleanup: $resolved" }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
