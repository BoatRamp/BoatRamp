<#
.SYNOPSIS
    boatramp installer for Windows. Downloads the right release
    archive from GitHub Releases, verifies its SHA-256 against the release's
    SHA256SUMS, and installs boatramp.exe.

.EXAMPLE
    irm https://raw.githubusercontent.com/BoatRamp/BoatRamp/main/packaging/install/install.ps1 | iex

.NOTES
    Env knobs:
      BOATRAMP_VERSION      release tag to install (default: latest)
      BOATRAMP_INSTALL_DIR  install location (default: %LOCALAPPDATA%\boatramp\bin)
#>
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Repo = "BoatRamp/BoatRamp"
$Bin = "boatramp.exe"
$Version = if ($env:BOATRAMP_VERSION) { $env:BOATRAMP_VERSION } else { "latest" }
$InstallDir = if ($env:BOATRAMP_INSTALL_DIR) { $env:BOATRAMP_INSTALL_DIR } `
    else { Join-Path $env:LOCALAPPDATA "boatramp\bin" }

# --- detect target triple ---------------------------------------------------
$arch = (Get-CimInstance Win32_Processor).Architecture  # 9 = x64, 12 = ARM64
switch ($arch) {
    9 { $target = "x86_64-pc-windows-msvc" }
    12 { $target = "aarch64-pc-windows-msvc" }
    default { throw "boatramp-install: unsupported CPU architecture ($arch)" }
}
$asset = "boatramp-$target.zip"

$base = if ($Version -eq "latest") {
    "https://github.com/$Repo/releases/latest/download"
} else {
    "https://github.com/$Repo/releases/download/$Version"
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("boatramp-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "boatramp-install: downloading $asset ($Version)"
    Invoke-WebRequest -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset) -UseBasicParsing
    Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp "SHA256SUMS") -UseBasicParsing

    # Verify: computed digest must equal the one SHA256SUMS lists for our asset.
    $want = (Get-Content (Join-Path $tmp "SHA256SUMS") |
        Where-Object { $_ -match "\s$([regex]::Escape($asset))$" } |
        ForEach-Object { ($_ -split '\s+')[0] } | Select-Object -First 1)
    if (-not $want) { throw "boatramp-install: no checksum for $asset in SHA256SUMS" }
    $got = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $asset)).Hash.ToLower()
    if ($want.ToLower() -ne $got) {
        throw "boatramp-install: checksum mismatch for $asset (expected $want, got $got)"
    }

    Expand-Archive -Path (Join-Path $tmp $asset) -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path (Join-Path $tmp $Bin) -Destination (Join-Path $InstallDir $Bin) -Force

    Write-Host "boatramp-install: installed $(Join-Path $InstallDir $Bin)"
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$InstallDir*") {
        Write-Host "boatramp-install: add $InstallDir to your PATH to run 'boatramp'."
    }
    & (Join-Path $InstallDir $Bin) --version
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
