[CmdletBinding()]
param(
    [switch]$SkipToolInstall,
    [switch]$AssumeYes
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$NodeVersionRequired = "24.18.0"
$NodeVersionRequiredWithPrefix = "v$NodeVersionRequired"
$PnpmVersionRequired = "11.9.0"
$RustToolchainRequired = "1.97.1"
$NasmVersionRequired = "3.02"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$CommandArguments
    )

    & $Command @CommandArguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command exited with status $LASTEXITCODE"
    }
}

function Set-SessionPath {
    param(
        [string[]]$PrependPaths
    )

    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $pathParts = [System.Collections.Generic.List[string]]::new()

    foreach ($rawPathList in @($PrependPaths, ($env:Path -split ";"), ($machinePath -split ";"), ($userPath -split ";"))) {
        foreach ($pathPart in $rawPathList) {
            if ([string]::IsNullOrWhiteSpace($pathPart)) {
                continue
            }

            $trimmedPathPart = $pathPart.Trim()
            if ($seen.Add($trimmedPathPart)) {
                $pathParts.Add($trimmedPathPart)
            }
        }
    }

    $env:Path = ($pathParts -join ";")
}

function Update-SessionPath {
    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    $nodeBin = Join-Path $env:ProgramFiles "nodejs"
    $nasmBin = Join-Path $env:ProgramFiles "NASM"
    $nasmPortableBin = Join-Path $env:LOCALAPPDATA "dnswg\build-tools\nasm\$NasmVersionRequired\nasm-$NasmVersionRequired"
    $corepackBin = Join-Path $env:LOCALAPPDATA "dnswg\build-tools\corepack-bin"
    $nsisBin = Join-Path ${env:ProgramFiles(x86)} "NSIS"

    Set-SessionPath -PrependPaths @($cargoBin, $nodeBin, $nasmPortableBin, $nasmBin, $corepackBin, $nsisBin)
}

function Assert-WingetAvailable {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "winget is required to install missing Windows build tools. Install App Installer from Microsoft Store, then rerun this helper."
    }
}

function Confirm-ToolInstall {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$InstallDescription
    )

    if ($AssumeYes) {
        return
    }

    Write-Host ""
    Write-Host "Missing required Windows build tool: $Name"
    Write-Host "This helper can install it with:"
    Write-Host "  $InstallDescription"
    $answer = Read-Host "Install $Name now and continue? [y/N]"

    if ($answer -notin @("y", "Y", "yes", "YES", "Yes")) {
        throw "Installation declined for $Name. Install it manually or rerun this helper and approve the prompt."
    }
}

function Invoke-WingetInstall {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [string]$Version,

        [string]$Override
    )

    Assert-WingetAvailable

    $arguments = @(
        "install",
        "--id", $Id,
        "--exact",
        "--accept-package-agreements",
        "--accept-source-agreements",
        "--disable-interactivity",
        "--silent"
    )

    if (-not [string]::IsNullOrWhiteSpace($Version)) {
        $arguments += @("--version", $Version)
    }

    if (-not [string]::IsNullOrWhiteSpace($Override)) {
        $arguments += @("--override", $Override)
    }

    Confirm-ToolInstall -Name $Name -InstallDescription "winget $($arguments -join ' ')"

    Write-Host "Installing $Name with winget..."
    Invoke-Checked winget @arguments
    Update-SessionPath
}

function Test-VisualCppToolsInstalled {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        return $false
    }

    $installationPath = (& $vswhere -products * -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath) -join ""
    return $LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($installationPath)
}

function Ensure-VisualCppTools {
    if (Test-VisualCppToolsInstalled) {
        Write-Host "Visual Studio C++ build tools are already available."
        return
    }

    if ($SkipToolInstall) {
        throw "Visual Studio C++ build tools are required. Rerun without -SkipToolInstall to install them."
    }

    Invoke-WingetInstall `
        -Id "Microsoft.VisualStudio.2022.BuildTools" `
        -Name "Visual Studio 2022 Build Tools" `
        -Override "--wait --quiet --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"

    if (-not (Test-VisualCppToolsInstalled)) {
        throw "Visual Studio C++ build tools were installed, but the VC tools workload was not detected. Rerun this helper from a new PowerShell window or repair Visual Studio Build Tools."
    }
}

function Ensure-CommandAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string]$InstallId,

        [Parameter(Mandatory = $true)]
        [string]$InstallName,

        [string]$Version
    )

    if (Get-Command $Command -ErrorAction SilentlyContinue) {
        return
    }

    if ($SkipToolInstall) {
        throw "Required command not found: $Command. Rerun without -SkipToolInstall to install $InstallName."
    }

    Invoke-WingetInstall -Id $InstallId -Name $InstallName -Version $Version

    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "$InstallName was installed, but '$Command' is still not on PATH. Open a new PowerShell window and rerun this helper."
    }
}

function Find-Nasm {
    $candidatePaths = @(
        (Join-Path $env:ProgramFiles "NASM\nasm.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "NASM\nasm.exe"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links\nasm.exe"),
        (Join-Path $env:LOCALAPPDATA "dnswg\build-tools\nasm\$NasmVersionRequired\nasm-$NasmVersionRequired\nasm.exe")
    )

    foreach ($candidatePath in $candidatePaths) {
        if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidatePath).Path
        }
    }

    $command = Get-Command nasm -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    return $null
}

function Install-PortableNasm {
    if ($SkipToolInstall) {
        throw "Required command not found: nasm. Rerun without -SkipToolInstall to install portable NASM $NasmVersionRequired."
    }

    $platform = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
    $archiveName = "nasm-$NasmVersionRequired-$platform.zip"
    $archivePath = Join-Path $env:TEMP $archiveName
    $installRoot = Join-Path $env:LOCALAPPDATA "dnswg\build-tools\nasm\$NasmVersionRequired"
    $downloadUrl = "https://www.nasm.us/pub/nasm/releasebuilds/$NasmVersionRequired/$platform/$archiveName"

    Confirm-ToolInstall -Name "NASM $NasmVersionRequired" -InstallDescription "download and extract $downloadUrl to $installRoot"

    $resolvedInstallRoot = [System.IO.Path]::GetFullPath($installRoot)
    $allowedRoot = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "dnswg\build-tools\nasm"))
    if (-not $resolvedInstallRoot.StartsWith($allowedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing unsafe NASM install path: $resolvedInstallRoot"
    }

    Remove-Item -LiteralPath $resolvedInstallRoot -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $resolvedInstallRoot -Force | Out-Null

    Write-Host "Downloading portable NASM $NasmVersionRequired..."
    Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $archivePath

    try {
        Expand-Archive -LiteralPath $archivePath -DestinationPath $resolvedInstallRoot -Force
    }
    finally {
        Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
    }
}

function Ensure-Nasm {
    $nasmPath = Find-Nasm
    if ([string]::IsNullOrWhiteSpace($nasmPath)) {
        Install-PortableNasm
        Update-SessionPath
        $nasmPath = Find-Nasm
    }

    if ([string]::IsNullOrWhiteSpace($nasmPath)) {
        throw "NASM was installed or detected, but nasm.exe could not be found."
    }

    $nasmDirectory = Split-Path -Parent $nasmPath
    Set-SessionPath -PrependPaths @($nasmDirectory)
    $nasmVersion = (& $nasmPath -v) -join " "
    if ($LASTEXITCODE -ne 0) {
        throw "NASM was found at $nasmPath, but version detection failed."
    }

    Write-Host "$nasmVersion is available."
}

function Test-WebView2RuntimeInstalled {
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
        "HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    )

    foreach ($path in $registryPaths) {
        if (Test-Path -LiteralPath $path) {
            return $true
        }
    }

    return $false
}

function Ensure-WebView2Runtime {
    if (Test-WebView2RuntimeInstalled) {
        Write-Host "Microsoft Edge WebView2 Runtime is already available."
        return
    }

    if ($SkipToolInstall) {
        throw "Microsoft Edge WebView2 Runtime is required. Rerun without -SkipToolInstall to install it."
    }

    Invoke-WingetInstall -Id "Microsoft.EdgeWebView2Runtime" -Name "Microsoft Edge WebView2 Runtime"

    if (-not (Test-WebView2RuntimeInstalled)) {
        throw "Microsoft Edge WebView2 Runtime was installed, but it was not detected in the registry. Open a new PowerShell window and rerun this helper."
    }
}

function Ensure-NodeVersion {
    $currentNode = $null
    if (Get-Command node -ErrorAction SilentlyContinue) {
        $currentNode = (& node --version).Trim()
    }

    if ($currentNode -eq $NodeVersionRequiredWithPrefix) {
        Write-Host "Node $NodeVersionRequiredWithPrefix is already available."
        return
    }

    if ($SkipToolInstall) {
        if ($null -eq $currentNode) {
            throw "Required command not found: node. Rerun without -SkipToolInstall to install Node $NodeVersionRequiredWithPrefix."
        }

        throw "Node $NodeVersionRequiredWithPrefix is required; found $currentNode. Rerun without -SkipToolInstall to install the required version."
    }

    Invoke-WingetInstall -Id "OpenJS.NodeJS.LTS" -Name "Node.js $NodeVersionRequired" -Version $NodeVersionRequired

    $currentNode = (& node --version).Trim()
    if ($currentNode -ne $NodeVersionRequiredWithPrefix) {
        throw "Node $NodeVersionRequiredWithPrefix is required; found $currentNode after installation. Remove the conflicting Node installation or adjust PATH, then rerun this helper."
    }
}

function Ensure-RustToolchain {
    Ensure-CommandAvailable -Command "rustup" -InstallId "Rustlang.Rustup" -InstallName "Rustup"
    Update-SessionPath

    Write-Host "Ensuring Rust $RustToolchainRequired with clippy and rustfmt..."
    Invoke-Checked rustup toolchain install $RustToolchainRequired --profile minimal --component clippy --component rustfmt

    foreach ($command in @("cargo", "rustc")) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "Rust command not found after toolchain install: $command"
        }
    }
}

function Ensure-Pnpm {
    $corepackCommand = Get-Command corepack -All -CommandType Application -ErrorAction SilentlyContinue |
        Where-Object { $_.Source -match "\.(cmd|exe|bat|com)$" } |
        Select-Object -First 1

    if (-not $corepackCommand) {
        throw "Corepack was not found after Node installation. Reinstall Node.js $NodeVersionRequiredWithPrefix and rerun this helper."
    }

    $corepackBin = Join-Path $env:LOCALAPPDATA "dnswg\build-tools\corepack-bin"
    $pnpmShim = Join-Path $corepackBin "pnpm.cmd"
    New-Item -ItemType Directory -Path $corepackBin -Force | Out-Null
    Set-SessionPath -PrependPaths @($corepackBin)

    Write-Host "Ensuring pnpm $PnpmVersionRequired through Corepack..."
    Invoke-Checked $corepackCommand.Source enable pnpm --install-directory $corepackBin
    Invoke-Checked $corepackCommand.Source install --global "pnpm@$PnpmVersionRequired"

    @"
@echo off
call "$($corepackCommand.Source)" pnpm %*
exit /b %errorlevel%
"@ | Set-Content -LiteralPath $pnpmShim -Encoding Ascii

    $cmdPnpmVersion = (& cmd.exe /d /c "`"$corepackBin\pnpm.cmd`" --version").Trim()
    if ($LASTEXITCODE -ne 0 -or $cmdPnpmVersion -ne $PnpmVersionRequired) {
        throw "pnpm $PnpmVersionRequired must be available through cmd.exe lifecycle scripts; found '$cmdPnpmVersion'."
    }

    Write-Host "pnpm $cmdPnpmVersion is available to cmd.exe lifecycle scripts."
}

if ($env:OS -ne "Windows_NT") {
    throw "The Windows helper must run on Windows."
}

Update-SessionPath
Ensure-VisualCppTools
Ensure-NodeVersion
Ensure-WebView2Runtime
Ensure-Nasm
Ensure-CommandAvailable -Command "makensis" -InstallId "NSIS.NSIS" -InstallName "NSIS"
Ensure-RustToolchain
Ensure-Pnpm

$nodeVersion = (& node --version).Trim()
if ($nodeVersion -ne $NodeVersionRequiredWithPrefix) {
    throw "Node $NodeVersionRequiredWithPrefix is required; found $nodeVersion"
}

$pnpmVersion = (& pnpm --version).Trim()
if ($pnpmVersion -ne $PnpmVersionRequired) {
    throw "pnpm $PnpmVersionRequired is required; found $pnpmVersion"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Push-Location $repoRoot
try {
    $env:CI = "true"
    Invoke-Checked pnpm install --frozen-lockfile

    if ($env:VAM_SKIP_CHECKS -ne "1") {
        Invoke-Checked pnpm verify
    }

    Invoke-Checked pnpm --dir apps/desktop tauri build --bundles nsis --ci
    Write-Host "Windows installer: $repoRoot\target\release\bundle\nsis"
}
finally {
    Pop-Location
}
