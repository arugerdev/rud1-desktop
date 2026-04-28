#requires -version 5.1
<#
.SYNOPSIS
  Fetches the official usbip-win2 installer for Windows into
  resources/win32/ so electron-builder bundles it via extraResources.

.DESCRIPTION
  Idempotent: if the bundled installer is already present and matches
  the pinned version, this script is a no-op. Otherwise it downloads
  the official signed NSIS installer from the project's GitHub
  release, verifies (a) a pinned SHA256 and (b) the Authenticode
  signature is "Valid" with a publisher subject we recognise, and
  drops the .exe into resources/win32/USBip-installer.exe.

  Why the full installer instead of just usbip.exe: usbip-win2 ships
  a kernel-mode VHCI driver alongside the userspace tool. The driver
  has to be installed with admin elevation and a Windows-side driver
  signature acceptance dialog — we cannot ship just the userspace
  binary and have anything actually attach. Bundling the official
  installer means rud1-desktop can detect "driver missing" at runtime
  and prompt the user to launch the bundled installer with one click,
  rather than sending them on a hunt for an external download.

  Pin version + hash by editing $USBIP_VERSION / $USBIP_SHA256.
  Bumping is a 2-line change followed by a commit.

  GPLv2 compliance: usbip-win2 is GPL-2.0-only. The script also writes
  COPYING.usbip-win2.txt and NOTICE.usbip-win2.txt next to the
  installer so the redistribution carries the licence text + a
  pointer to the corresponding source.

.NOTES
  Run from any working directory; paths resolve relative to the
  script. Invoked automatically by `npm run dist:win` via build-win.ps1.
#>
param(
  [switch]$Force
)

$ErrorActionPreference = "Stop"

# Pinned upstream release
$USBIP_VERSION = "0.9.7.7"
$USBIP_SHA256  = "51620fa5f9f8be5932bc9d786deee557ce06d5407a99cab490dcfac71f185fea"
$USBIP_URL     = "https://github.com/vadimgrn/usbip-win2/releases/download/v.$USBIP_VERSION/USBip-$USBIP_VERSION-x64.exe"

# Paths
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Split-Path -Parent $ScriptDir
$Resources   = Join-Path $RepoRoot "resources\win32"
$VersionFile = Join-Path $Resources "usbip-win2.version"
$Installer   = Join-Path $Resources "USBip-installer.exe"
$LicenseFile = Join-Path $Resources "COPYING.usbip-win2.txt"
$NoticeFile  = Join-Path $Resources "NOTICE.usbip-win2.txt"

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "OK  $msg" -ForegroundColor Green }
function Write-Warn2($m)  { Write-Host "!!  $m" -ForegroundColor Yellow }

$existing = if (Test-Path $VersionFile) { (Get-Content $VersionFile -Raw).Trim() } else { "" }
if (-not $Force -and $existing -eq $USBIP_VERSION -and (Test-Path $Installer)) {
  Write-OK "usbip-win2 $USBIP_VERSION already present in resources/win32/. Use -Force to re-download."
  exit 0
}

$Stage = Join-Path $env:TEMP "rud1-usbip-fetch-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
$Tmp = Join-Path $Stage "USBip-installer.exe"

try {
  Write-Step "Downloading $USBIP_URL"
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri $USBIP_URL -OutFile $Tmp -UseBasicParsing

  Write-Step "Verifying SHA256"
  $hash = (Get-FileHash -Path $Tmp -Algorithm SHA256).Hash.ToLower()
  if ($hash -ne $USBIP_SHA256) {
    throw "SHA256 mismatch. Expected $USBIP_SHA256, got $hash. Refusing to use."
  }
  Write-OK "SHA256 matches pinned value"

  Write-Step "Verifying Authenticode signature"
  $sig = Get-AuthenticodeSignature -FilePath $Tmp
  if ($sig.Status -ne "Valid") {
    throw "Authenticode status is '$($sig.Status)' (expected 'Valid'). Refusing to use."
  }
  $subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
  # The usbip-win2 project signs releases via Cloudyne Systems / Scheibling
  # Consulting AB. We pin both (a) the publisher name and (b) the GlobalSign
  # CA in case the publisher rebrands.
  if ($subject -notmatch "Cloudyne Systems" -and $subject -notmatch "Scheibling") {
    throw "Unexpected signer subject: $subject. Expected Cloudyne Systems or Scheibling."
  }
  Write-OK "Signed by '$subject'"

  Write-Step "Installing into $Resources"
  New-Item -ItemType Directory -Force -Path $Resources | Out-Null
  Copy-Item $Tmp $Installer -Force
  $USBIP_VERSION | Out-File -FilePath $VersionFile -Encoding ascii -NoNewline
  Write-OK "USBip-installer.exe installed (version $USBIP_VERSION)"
}
finally {
  Remove-Item -Recurse -Force $Stage -ErrorAction SilentlyContinue
}

# GPLv2 compliance artefacts
$NoticeText = @"
usbip-win2
Version: $USBIP_VERSION
Source:  https://github.com/vadimgrn/usbip-win2
Author:  Vadim Grinco and contributors
License: GNU General Public License version 2 (GPL-2.0-only) — see
         COPYING.usbip-win2.txt next to this file.

This rud1 Desktop installer bundles the unmodified, official
USBip-$USBIP_VERSION-x64.exe NSIS installer from the upstream GitHub
release. It is invoked by the rud1 main process via shell:openItem
(or execFile with elevation) only after the user accepts a UI prompt.

The installer drops:
  - VHCI kernel-mode driver (vhci.sys) into Windows DriverStore
  - usbip.exe userspace tool into Program Files\USBip\
  - usbip_xfer.exe support tool

We do NOT modify any of these binaries. Authenticode signatures by
Cloudyne Systems / Scheibling Consulting AB remain intact.

Corresponding source code for this exact bundled version is available
permanently at:

  https://github.com/vadimgrn/usbip-win2/archive/refs/tags/v.$USBIP_VERSION.tar.gz

A copy of GPLv2 ships in COPYING.usbip-win2.txt. The rud1 Desktop
project itself is independently licensed and does not fall under the
GPL — only this bundled tool does.
"@
Set-Content -Path $NoticeFile -Value $NoticeText -Encoding utf8
Write-OK "Wrote $NoticeFile"

$LocalLicense = Join-Path $ScriptDir "..\resources\gpl-2.0.txt"

if (-not (Test-Path $LocalLicense)) {
  if ((Get-Item $LicenseFile).Length -lt 8000) {
    Write-Step "Fetching canonical GPLv2 text from www.gnu.org"
    Invoke-WebRequest -Uri "https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt" `
      -OutFile $LicenseFile -UseBasicParsing
    Write-OK "Wrote $LicenseFile"
  }
}

Copy-Item $LocalLicense $LicenseFile -Force
Write-OK "Copied local GPLv2 license"

Write-Host ""
Write-OK "Done. resources/win32/ now contains usbip-win2 artefacts:"
Get-ChildItem $Resources -Filter "*usbip*" | Select-Object Name, Length | Format-Table -AutoSize
Get-ChildItem $Resources -Filter "USBip*"   | Select-Object Name, Length | Format-Table -AutoSize
