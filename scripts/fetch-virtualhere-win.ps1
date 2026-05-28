#requires -version 5.1
<#
.SYNOPSIS
  Fetches the VirtualHere headless client into resources/win32/ so
  electron-builder bundles it via extraResources.

.DESCRIPTION
  VirtualHere replaces the com0com + rud1-bridge stack that didn't
  survive Windows HVCI. The Windows client uses WinUSB (in-box,
  Microsoft-signed, HVCI-friendly) plus usbser.sys for CDC devices.
  Arduinos appear as native COM ports without any kernel driver
  installation step for the operator.

  We bundle vhclientx86_64.exe — the headless variant controllable
  via -t "<command>" CLI args. The tray-icon client (vhui64.exe) is
  NOT what we want: it surfaces its own UI that competes with rud1.

  License: VirtualHere is proprietary. Free tier limits each server
  to 1 simultaneous device, which we surface in the rud1 UI. For
  redistribution at scale we'd need to negotiate an embedded licence
  with the upstream; the fetch URL below is the publicly-available
  binary.

  Idempotent: skips when the file is already present.
#>
param(
  [switch]$Force
)

$ErrorActionPreference = "Stop"

$VH_VERSION = "5.6.5"
$VH_URL     = "https://www.virtualhere.com/sites/default/files/usbclient/vhclientx86_64.exe"

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Split-Path -Parent $ScriptDir
$ResourceDir = Join-Path $RepoRoot "resources\win32"
$OutBin      = Join-Path $ResourceDir "vhclient.exe"
$OutVersion  = Join-Path $ResourceDir "virtualhere.version"

if (-not (Test-Path $ResourceDir)) {
    New-Item -ItemType Directory -Path $ResourceDir | Out-Null
}

if ((-not $Force) -and (Test-Path $OutBin) -and (Test-Path $OutVersion)) {
    $existingVersion = (Get-Content $OutVersion -Raw -ErrorAction SilentlyContinue).Trim()
    if ($existingVersion -eq $VH_VERSION) {
        Write-Host "VirtualHere client already at $VH_VERSION (use -Force to refetch)." -ForegroundColor DarkGray
        exit 0
    }
}

Write-Host "Downloading VirtualHere client $VH_VERSION ..." -ForegroundColor Cyan
$UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) rud1-desktop/0.1"
Invoke-WebRequest -Uri $VH_URL -OutFile $OutBin -UseBasicParsing -UserAgent $UA

if (-not (Test-Path $OutBin)) {
    throw "Download failed: $OutBin missing after Invoke-WebRequest."
}

# Authenticode signature check — the user shouldn't see "Unknown
# publisher" on first run.
$sig = Get-AuthenticodeSignature $OutBin
if ($sig.Status -ne "Valid") {
    Write-Warning "Signature status is $($sig.Status). VirtualHere distributes signed binaries; check the download URL."
} else {
    Write-Host "Signature: $($sig.SignerCertificate.Subject)" -ForegroundColor Green
}

Set-Content -Path $OutVersion -Value $VH_VERSION -Encoding ASCII -NoNewline

Write-Host ""
Write-Host "VirtualHere client $VH_VERSION bundled at $OutBin." -ForegroundColor Green
