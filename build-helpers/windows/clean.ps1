[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (
    -not (Test-Path -LiteralPath (Join-Path $repoRoot "Cargo.toml") -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $repoRoot "pnpm-workspace.yaml") -PathType Leaf)
) {
    throw "Refusing to clean an unrecognized repository root."
}

$generatedPaths = @(
    (Join-Path $repoRoot "target"),
    (Join-Path $repoRoot "node_modules"),
    (Join-Path $repoRoot "apps\desktop\node_modules"),
    (Join-Path $repoRoot "apps\desktop\dist")
)

$rootPrefix = $repoRoot.TrimEnd("\") + "\"
foreach ($generatedPath in $generatedPaths) {
    $fullPath = [System.IO.Path]::GetFullPath($generatedPath)
    if (-not $fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing unsafe clean path: $fullPath"
    }
    if (Test-Path -LiteralPath $fullPath) {
        Remove-Item -LiteralPath $fullPath -Recurse -Force
    }
}

Write-Host "Removed generated Windows build outputs and dependencies."
