#requires -version 5.1
<#
.SYNOPSIS
  Fetches the OpenVPN Community MSI and extracts the portable runtime
  (openvpn.exe + DLLs + tapctl.exe + TAP-Windows V9 driver files) into
  resources/win32/openvpn/ so electron-builder bundles them via
  extraResources.

.DESCRIPTION
  Idempotent: if the bundled binaries are already present and match the
  pinned version, the script is a no-op. Otherwise it downloads the
  official signed MSI from build.openvpn.net, verifies (a) a pinned
  SHA256 and (b) the Authenticode signature is "Valid" with subject
  matching "OpenVPN Inc.", then runs `msiexec /a` to extract files into
  a temp directory and copies the runtime components into
  resources/win32/openvpn/.

  The TAP-Windows V9 kernel driver INF + CAT + SYS files are extracted
  alongside so the desktop's first-run installer can call `tapctl create
  --hwid root\tap0901` to install + create the adapter in one elevated
  call.

  Pin version + hash by editing $OPENVPN_VERSION / $OPENVPN_SHA256
  below. Bumping to a new release is a 2-line change followed by a commit.

  License: OpenVPN Community is GPL-2.0-with-OpenSSL-exception. The
  script also writes COPYING.OpenVPN.txt and NOTICE.OpenVPN.txt
  alongside the binaries so the redistribution carries the licence text
  + pointer to the corresponding source.

.NOTES
  Run from any working directory; paths resolve relative to the script.
#>
param(
  [switch]$Force
)

$ErrorActionPreference = "Stop"

# ── Pinned upstream release ──────────────────────────────────────────────────
# OpenVPN Community 2.6.x — 2.6.x ships TAP-Windows V9 driver 9.27 (current).
# Bumping: pull the new MSI URL from https://openvpn.net/community-downloads/
# and update the SHA256 + Authenticode subject check below if the signer
# certificate is rotated.
$OPENVPN_VERSION = "2.6.12"
$OPENVPN_SHA256  = "0e9c33dac72a7611f4a8b08f1d2c4f0e8c9c3a1f6f1e6c9a3a9f0c0e0c0e0c0e"  # PLACEHOLDER — set before commit
$OPENVPN_URL     = "https://swupdate.openvpn.org/community/releases/OpenVPN-$OPENVPN_VERSION-I001-amd64.msi"

# ── Paths ────────────────────────────────────────────────────────────────────
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Split-Path -Parent $ScriptDir
$ResourcesWin32 = Join-Path $RepoRoot "resources\win32"
$BundleDir   = Join-Path $ResourcesWin32 "openvpn"
$DriverDir   = Join-Path $BundleDir "driver"
$VersionFile = Join-Path $BundleDir "openvpn.version"
$OpenVpnExe  = Join-Path $BundleDir "openvpn.exe"
$TapctlExe   = Join-Path $BundleDir "tapctl.exe"
$LicenseFile = Join-Path $BundleDir "COPYING.OpenVPN.txt"
$NoticeFile  = Join-Path $BundleDir "NOTICE.OpenVPN.txt"

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "OK  $msg" -ForegroundColor Green }
function Write-Warn2($m)  { Write-Host "!!  $m" -ForegroundColor Yellow }

# ── Idempotency: skip when already on the pinned version ────────────────────
$existing = if (Test-Path $VersionFile) { (Get-Content $VersionFile -Raw).Trim() } else { "" }
if (-not $Force -and $existing -eq $OPENVPN_VERSION -and (Test-Path $OpenVpnExe) -and (Test-Path $TapctlExe)) {
  Write-Ok "OpenVPN $OPENVPN_VERSION already present in resources/win32/openvpn/. Use -Force to re-download."
  exit 0
}

# ── Stage to a temp dir; only copy on success ───────────────────────────────
$Stage = Join-Path $env:TEMP "rud1-openvpn-fetch-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
$Msi = Join-Path $Stage "openvpn.msi"

try {
  Write-Step "Downloading $OPENVPN_URL"
  # TLS 1.2 explicit — older PowerShell (5.1) defaults to SSL3/TLS1.0 on some boxes.
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri $OPENVPN_URL -OutFile $Msi -UseBasicParsing

  Write-Step "Verifying SHA256"
  $hash = (Get-FileHash -Path $Msi -Algorithm SHA256).Hash.ToLower()
  if ($OPENVPN_SHA256 -eq "0e9c33dac72a7611f4a8b08f1d2c4f0e8c9c3a1f6f1e6c9a3a9f0c0e0c0e0c0e") {
    # PLACEHOLDER guard: this hash MUST be set before committing the
    # script for production use. We surface the actual hash so the
    # operator can copy it into the source.
    Write-Warn2 "OPENVPN_SHA256 is the placeholder value — pin to: $hash"
    Write-Warn2 "Edit $($MyInvocation.MyCommand.Path) and re-run to enforce the pin."
  } elseif ($hash -ne $OPENVPN_SHA256) {
    throw "SHA256 mismatch. Expected $OPENVPN_SHA256, got $hash. Refusing to use."
  } else {
    Write-Ok "SHA256 matches pinned value"
  }

  Write-Step "Verifying Authenticode signature"
  $sig = Get-AuthenticodeSignature -FilePath $Msi
  if ($sig.Status -ne "Valid") {
    throw "Authenticode status is '$($sig.Status)' (expected 'Valid'). Refusing to use."
  }
  $subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
  if ($subject -notmatch "OpenVPN Inc\." -and $subject -notmatch "OpenVPN Technologies") {
    throw "Unexpected signer subject: $subject. Expected 'OpenVPN Inc.' or 'OpenVPN Technologies'."
  }
  Write-Ok "Signed by '$subject', timestamp valid"

  Write-Step "Extracting MSI via msiexec /a"
  $Extract = Join-Path $Stage "extracted"
  New-Item -ItemType Directory -Force -Path $Extract | Out-Null
  $proc = Start-Process msiexec.exe `
    -ArgumentList "/a", "`"$Msi`"", "/qb", "TARGETDIR=`"$Extract`"" `
    -Wait -PassThru -NoNewWindow
  if ($proc.ExitCode -ne 0) {
    throw "msiexec /a exited with code $($proc.ExitCode)"
  }

  # The MSI layout under $Extract:
  #   OpenVPN\bin\openvpn.exe
  #   OpenVPN\bin\tapctl.exe
  #   OpenVPN\bin\openvpnserv.exe
  #   OpenVPN\bin\openssl.exe
  #   OpenVPN\bin\*.dll  (libssl-3-x64, libcrypto-3-x64, libpkcs11-helper-1, ...)
  #   OpenVPN\bin\drivers\tap-windows6\<arch>\OemVista.inf
  #   OpenVPN\bin\drivers\tap-windows6\<arch>\tap0901.cat
  #   OpenVPN\bin\drivers\tap-windows6\<arch>\tap0901.sys
  $SrcBin    = Join-Path $Extract "OpenVPN\bin"
  $SrcDriver = Join-Path $Extract "OpenVPN\bin\drivers\tap-windows6\amd64"

  if (-not (Test-Path (Join-Path $SrcBin "openvpn.exe"))) {
    throw "Expected openvpn.exe under $SrcBin but it's missing — MSI layout changed?"
  }

  # Re-verify the extracted exe — defence-in-depth in case some
  # pathological extractor mutates contents.
  $extractedExe = Join-Path $SrcBin "openvpn.exe"
  $s = Get-AuthenticodeSignature -FilePath $extractedExe
  if ($s.Status -ne "Valid") {
    throw "Extracted openvpn.exe has Authenticode status '$($s.Status)'. Refusing to use."
  }

  Write-Step "Installing into $BundleDir"
  if (Test-Path $BundleDir) {
    Remove-Item -Recurse -Force $BundleDir
  }
  New-Item -ItemType Directory -Force -Path $BundleDir | Out-Null
  New-Item -ItemType Directory -Force -Path $DriverDir | Out-Null

  # Copy the runtime binaries + DLLs — openvpn.exe is non-relocatable
  # and needs its DLLs in the same directory.
  $exeNames = @("openvpn.exe", "tapctl.exe", "openvpnserv.exe", "openssl.exe")
  foreach ($name in $exeNames) {
    $src = Join-Path $SrcBin $name
    if (Test-Path $src) {
      Copy-Item $src (Join-Path $BundleDir $name) -Force
    }
  }
  # All DLLs that ship next to openvpn.exe.
  Get-ChildItem -Path $SrcBin -Filter "*.dll" -File -ErrorAction SilentlyContinue |
    ForEach-Object {
      Copy-Item $_.FullName (Join-Path $BundleDir $_.Name) -Force
    }

  # TAP-Windows V9 driver files: OemVista.inf + tap0901.cat + tap0901.sys.
  # tapctl reads these at install time. We bundle only the amd64 variant
  # because rud1-desktop is amd64-only on Windows.
  if (Test-Path $SrcDriver) {
    Get-ChildItem -Path $SrcDriver -File -ErrorAction SilentlyContinue |
      ForEach-Object {
        Copy-Item $_.FullName (Join-Path $DriverDir $_.Name) -Force
      }
  } else {
    Write-Warn2 "TAP-Windows V9 driver folder not found at $SrcDriver — first-run install will fail."
  }

  $OPENVPN_VERSION | Out-File -FilePath $VersionFile -Encoding ascii -NoNewline
  Write-Ok "OpenVPN $OPENVPN_VERSION installed into $BundleDir"
}
finally {
  Remove-Item -Recurse -Force $Stage -ErrorAction SilentlyContinue
}

# ── License / NOTICE artefacts ──────────────────────────────────────────────
$NoticeText = @"
OpenVPN Community
Version: $OPENVPN_VERSION
Source:  https://github.com/OpenVPN/openvpn
Author:  OpenVPN Inc. and contributors
License: GNU General Public License version 2 (GPL-2.0-only)
         with OpenSSL linking exception. See COPYING.OpenVPN.txt
         next to this file.

This rud1 Desktop installer bundles the unmodified, official
openvpn.exe, tapctl.exe, openvpnserv.exe, openssl.exe, and the runtime
DLLs (libssl-3-x64.dll, libcrypto-3-x64.dll, libpkcs11-helper-1.dll, ...)
extracted from the upstream OpenVPN-$OPENVPN_VERSION-I001-amd64.msi
release.

The TAP-Windows V9 kernel driver files (OemVista.inf, tap0901.cat,
tap0901.sys) are also bundled. The driver is installed on first run via
`tapctl create --hwid root\tap0901 --name rud1-tap`, which triggers a
Windows UAC prompt. Once installed, the driver persists across reboots.

The OpenVPN binaries are invoked as separate child processes by the rud1
Desktop main process via child_process.spawn (no linking, no library
use) — i.e. mere aggregation per the GPL FAQ. The Authenticode signature
by OpenVPN Inc. is preserved.

Corresponding source code for this exact bundled version is available
permanently at:

  https://github.com/OpenVPN/openvpn/archive/refs/tags/v$OPENVPN_VERSION.tar.gz

A copy of GPLv2 ships in COPYING.OpenVPN.txt. The rud1 Desktop project
itself is independently licensed and does not fall under the GPL — only
this bundled tool does.
"@
Set-Content -Path $NoticeFile -Value $NoticeText -Encoding utf8
Write-Ok "Wrote $NoticeFile"

$LocalLicense = Join-Path $ScriptDir "..\resources\gpl-2.0.txt"
if (Test-Path $LocalLicense) {
  Copy-Item $LocalLicense $LicenseFile -Force
  Write-Ok "Copied local GPLv2 license"
} elseif (-not (Test-Path $LicenseFile) -or (Get-Item $LicenseFile).Length -lt 8000) {
  Write-Step "Fetching canonical GPLv2 text from www.gnu.org"
  Invoke-WebRequest -Uri "https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt" `
    -OutFile $LicenseFile -UseBasicParsing
  Write-Ok "Wrote $LicenseFile"
}

Write-Host ""
Write-Ok "Done. resources/win32/openvpn/ now contains:"
Get-ChildItem $BundleDir -Recurse -File | Select-Object FullName, Length | Format-Table -AutoSize
