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

function Get-NodeArchitecture {
    param(
        [string]$ProcessArchitecture = $env:PROCESSOR_ARCHITECTURE,
        [string]$NativeArchitecture = $env:PROCESSOR_ARCHITEW6432
    )
    # Windows PowerShell 5.1 can run on .NET versions without OSArchitecture.
    # WOW64 exposes the native OS architecture separately from the shell's.
    $architecture = if ([string]::IsNullOrWhiteSpace($NativeArchitecture)) {
        $ProcessArchitecture
    } else {
        $NativeArchitecture
    }
    switch ($architecture) {
        'AMD64' { return 'x64' }
        'ARM64' { return 'arm64' }
        default { throw "Unsupported Windows architecture '$architecture'. The build helper requires x64 or ARM64 Windows." }
    }
}

function Update-SessionPath {
    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    $nodeBin = Join-Path $env:ProgramFiles "nodejs"
    $portableNodeBin = Join-Path $env:LOCALAPPDATA "dnswg\build-tools\node\$NodeVersionRequired\node-v$NodeVersionRequired-win-$(Get-NodeArchitecture)"
    $nasmBin = Join-Path $env:ProgramFiles "NASM"
    $nasmPortableBin = Join-Path $env:LOCALAPPDATA "dnswg\build-tools\nasm\$NasmVersionRequired\nasm-$NasmVersionRequired"
    $corepackBin = Join-Path $env:LOCALAPPDATA "dnswg\build-tools\corepack-bin"
    $nsisBin = Join-Path ${env:ProgramFiles(x86)} "NSIS"

    Set-SessionPath -PrependPaths @($cargoBin, $portableNodeBin, $nodeBin, $nasmPortableBin, $nasmBin, $corepackBin, $nsisBin)
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

function Assert-NodeArchiveHash {
    param([string]$Path, [string]$Expected)
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ne $Expected) {
        throw "Node archive checksum mismatch. Expected $Expected; got $actual. The archive was not extracted."
    }
}

function Install-PortableNode {
    $architecture = Get-NodeArchitecture
    # Official v24.18.0 SHASUMS256.txt, pinned with the toolchain version.
    $checksums = @{
        x64 = "0ae68406b42d7725661da979b1403ec9926da205c6770827f33aac9d8f26e821"
        arm64 = "f274669adb93b1fd0fbf8f21fd078609e9dcc84333d4f2718d2dde3f9a161a01"
    }
    if ($NodeVersionRequired -ne "24.18.0" -or -not $checksums.ContainsKey($architecture)) {
        throw "No verified portable Node $NodeVersionRequired archive is configured for $architecture. Update the version and official checksums together."
    }
    $archiveName = "node-v$NodeVersionRequired-win-$architecture"
    $parent = Join-Path $env:LOCALAPPDATA "dnswg\build-tools\node"
    $destination = Join-Path $parent $NodeVersionRequired
    $nodePath = Join-Path $destination "$archiveName\node.exe"
    if (Test-Path -LiteralPath $nodePath -PathType Leaf) {
        $version = (& $nodePath --version).Trim()
        if ($LASTEXITCODE -ne 0 -or $version -ne $NodeVersionRequiredWithPrefix) {
            throw "Cached Node is invalid at $nodePath. Repair that build-tools cache and retry."
        }
        Set-SessionPath -PrependPaths @((Split-Path $nodePath))
        return
    }
    if ($SkipToolInstall) {
        throw "Node $NodeVersionRequiredWithPrefix is required. Rerun without -SkipToolInstall to install a verified portable copy without changing system Node."
    }
    if (Test-Path -LiteralPath $destination) {
        throw "Incomplete Node cache at $destination. Repair that build-tools cache and retry."
    }
    $url = "https://nodejs.org/dist/v$NodeVersionRequired/$archiveName.zip"
    Confirm-ToolInstall -Name "portable Node.js $NodeVersionRequired" -InstallDescription "download $url, verify its pinned SHA-256, and extract to $destination (system Node unchanged)"
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $staging = Join-Path $parent (".node-stage-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $staging | Out-Null
    try {
        $archive = Join-Path $staging "node.zip"
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $archive
        Assert-NodeArchiveHash -Path $archive -Expected $checksums[$architecture]
        Expand-Archive -LiteralPath $archive -DestinationPath $staging
        Remove-Item -LiteralPath $archive
        $stagedNode = Join-Path $staging "$archiveName\node.exe"
        $version = (& $stagedNode --version).Trim()
        if ($LASTEXITCODE -ne 0 -or $version -ne $NodeVersionRequiredWithPrefix) {
            throw "Downloaded Node reports '$version'; expected $NodeVersionRequiredWithPrefix."
        }
        Move-Item -LiteralPath $staging -Destination $destination
    } finally {
        $resolvedStaging = [IO.Path]::GetFullPath($staging)
        $allowedPrefix = [IO.Path]::GetFullPath($parent).TrimEnd('\') + '\.node-stage-'
        if (-not $resolvedStaging.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing unsafe Node staging cleanup: $resolvedStaging"
        }
        if (Test-Path -LiteralPath $resolvedStaging) { Remove-Item -LiteralPath $resolvedStaging -Recurse -Force }
    }
    Set-SessionPath -PrependPaths @((Split-Path $nodePath))
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

    Write-Host "Selecting pinned Node $NodeVersionRequiredWithPrefix (current: $currentNode) for this build session."
    Install-PortableNode

    $currentNode = (& node --version).Trim()
    if ($currentNode -ne $NodeVersionRequiredWithPrefix) {
        throw "Node $NodeVersionRequiredWithPrefix is required; found $currentNode after selecting the portable runtime. Check PATH command overrides."
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

function Test-HelperPayloads {
    param([string]$BundleRoot)
    $complete = $true
    foreach ($entry in @(@('x86_64', 62), @('aarch64', 183))) {
        $path = Join-Path $BundleRoot "$($entry[0])-unknown-linux-musl\vam-server"
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            $complete = $false
            continue
        }
        $file = Get-Item -LiteralPath $path
        if ($file.Length -lt 64 -or $file.Length -gt 150MB) { throw "Invalid helper size: $path" }
        $stream = [IO.File]::OpenRead($path)
        try {
            $header = New-Object byte[] 20
            if ($stream.Read($header, 0, 20) -ne 20) { throw "Cannot read helper header: $path" }
        } finally { $stream.Dispose() }
        if ($header[0] -ne 127 -or $header[1] -ne 69 -or $header[2] -ne 76 -or
            $header[3] -ne 70 -or $header[4] -ne 2 -or $header[5] -ne 1 -or
            $header[18] -ne $entry[1] -or $header[19] -ne 0) {
            throw "Invalid $($entry[0]) Linux ELF helper: $path. Rebuild the helper bundles from this source."
        }
    }
    return $complete
}

function Ensure-HelperBundles {
    param([string]$RepoRoot)
    $bundleRoot = Join-Path $RepoRoot 'target\vam-server-dist'
    if (-not [string]::IsNullOrWhiteSpace($env:VAM_HELPER_BUNDLE_DIR)) {
        $bundleRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($env:VAM_HELPER_BUNDLE_DIR)
        if (-not (Test-HelperPayloads $bundleRoot)) {
            throw "VAM_HELPER_BUNDLE_DIR is incomplete: $bundleRoot. Supply both Linux architectures from a trusted build of this source."
        }
        $env:VAM_HELPER_BUNDLE_DIR = $bundleRoot
        Write-Host "Using supplied Linux helper bundles: $bundleRoot"
        return
    }
    if (Test-HelperPayloads $bundleRoot) {
        Write-Host "Both Linux helper bundles are available: $bundleRoot"
        return
    }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'Linux helpers are missing. Start Docker Desktop with Linux containers and Docker Buildx, then rerun; or set VAM_HELPER_BUNDLE_DIR to trusted matching-source bundles for both architectures.'
    }
    Invoke-Checked docker info
    Invoke-Checked docker buildx version
    $git = Get-Command git -CommandType Application -ErrorAction Stop
    $gitRoot = Split-Path (Split-Path $git.Source)
    $bash = Join-Path $gitRoot 'bin\bash.exe'
    if (-not (Test-Path -LiteralPath $bash -PathType Leaf)) {
        throw "Git Bash is required to build Linux helpers. Expected $bash. Install Git for Windows or provide VAM_HELPER_BUNDLE_DIR."
    }
    $previousArchitectures = $env:VAM_HELPER_ARCHITECTURES
    Push-Location $RepoRoot
    try {
        $env:VAM_HELPER_ARCHITECTURES = 'x86_64 aarch64'
        Write-Host 'Building both Linux helper architectures with Docker (requires amd64/arm64 emulation or native builder nodes)...'
        Invoke-Checked $bash build-helpers/server/bundle.sh
    } finally {
        $env:VAM_HELPER_ARCHITECTURES = $previousArchitectures
        Pop-Location
    }
    if (-not (Test-HelperPayloads $bundleRoot)) { throw "Helper build did not produce both payloads in $bundleRoot." }
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
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Ensure-HelperBundles -RepoRoot $repoRoot
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
