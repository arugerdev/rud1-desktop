#requires -version 5.1
<#
.SYNOPSIS
  Fetches WireGuard for Windows binaries (wireguard.exe + wg.exe) into
  resources/win32/ so electron-builder can bundle them via extraResources.

.DESCRIPTION
  Idempotent: if the binaries are already present and match the pinned
  version, the script is a no-op. Otherwise it downloads the official
  signed MSI from download.wireguard.com, verifies (a) a pinned SHA256
  and (b) the Authenticode signature is "Valid" with subject containing
  "WireGuard LLC", then runs `msiexec /a` to extract the files into a
  temp directory and copies wireguard.exe / wg.exe into resources/win32/.

  Pin version + hash by editing $WG_VERSION / $WG_SHA256 below. Bumping
  to a new release is a 2-line change followed by a commit.

  GPLv2 compliance: the WireGuard Windows components are GPL-2.0-only.
  This script also writes COPYING.WireGuard.txt and NOTICE.WireGuard.txt
  alongside the binaries so the redistribution carries the license and
  pointers to the corresponding source.

.NOTES
  Run from any working directory; paths are resolved relative to the
  script location.
#>
param(
  [switch]$Force
)

$ErrorActionPreference = "Stop"

# ── Pinned upstream release ──────────────────────────────────────────────────
$WG_VERSION = "1.0.1"
$WG_SHA256  = "2b7e230c26e533f21c67498517f23d3c8677e144d34353d3a27ad54092c21214"
$WG_URL     = "https://download.wireguard.com/windows-client/wireguard-amd64-$WG_VERSION.msi"

# ── Paths ────────────────────────────────────────────────────────────────────
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Split-Path -Parent $ScriptDir
$Resources   = Join-Path $RepoRoot "resources\win32"
$VersionFile = Join-Path $Resources "wireguard.version"
$WgExe       = Join-Path $Resources "wireguard.exe"
$WgCli       = Join-Path $Resources "wg.exe"
$LicenseFile = Join-Path $Resources "COPYING.WireGuard.txt"
$NoticeFile  = Join-Path $Resources "NOTICE.WireGuard.txt"

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "OK  $msg" -ForegroundColor Green }
function Write-Warn2($m)  { Write-Host "!!  $m" -ForegroundColor Yellow }

# ── Idempotency: skip when already on the pinned version ────────────────────
$existing = if (Test-Path $VersionFile) { (Get-Content $VersionFile -Raw).Trim() } else { "" }
if (-not $Force -and $existing -eq $WG_VERSION -and (Test-Path $WgExe) -and (Test-Path $WgCli)) {
  Write-Ok "WireGuard $WG_VERSION already present in resources/win32/. Use -Force to re-download."
  exit 0
}

# ── Stage to a temp dir; only copy on success ───────────────────────────────
$Stage = Join-Path $env:TEMP "rud1-wg-fetch-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
$Msi = Join-Path $Stage "wireguard.msi"

try {
  Write-Step "Downloading $WG_URL"
  # TLS 1.2 explicit — older PowerShell (5.1) defaults to SSL3/TLS1.0 on some boxes.
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri $WG_URL -OutFile $Msi -UseBasicParsing

  Write-Step "Verifying SHA256"
  $hash = (Get-FileHash -Path $Msi -Algorithm SHA256).Hash.ToLower()
  if ($hash -ne $WG_SHA256) {
    throw "SHA256 mismatch. Expected $WG_SHA256, got $hash. Refusing to use."
  }
  Write-Ok "SHA256 matches pinned value"

  Write-Step "Verifying Authenticode signature"
  $sig = Get-AuthenticodeSignature -FilePath $Msi
  if ($sig.Status -ne "Valid") {
    throw "Authenticode status is '$($sig.Status)' (expected 'Valid'). Refusing to use."
  }
  $subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
  if ($subject -notmatch "WireGuard LLC") {
    throw "Unexpected signer subject: $subject. Expected 'WireGuard LLC'."
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
  $extractedExe = Join-Path $Extract "WireGuard\wireguard.exe"
  $extractedCli = Join-Path $Extract "WireGuard\wg.exe"
  if (-not (Test-Path $extractedExe) -or -not (Test-Path $extractedCli)) {
    throw "Expected wireguard.exe + wg.exe under $Extract\WireGuard, but they're missing."
  }

  # Re-verify the extracted binaries — defence-in-depth in case some
  # pathological extractor mutates contents.
  foreach ($p in @($extractedExe, $extractedCli)) {
    $s = Get-AuthenticodeSignature -FilePath $p
    if ($s.Status -ne "Valid") {
      throw "Extracted $p has Authenticode status '$($s.Status)'. Refusing to use."
    }
  }

  Write-Step "Installing into $Resources"
  New-Item -ItemType Directory -Force -Path $Resources | Out-Null
  Copy-Item $extractedExe $WgExe -Force
  Copy-Item $extractedCli $WgCli -Force

  $WG_VERSION | Out-File -FilePath $VersionFile -Encoding ascii -NoNewline
  Write-Ok "wireguard.exe + wg.exe installed (version $WG_VERSION)"
}
finally {
  Remove-Item -Recurse -Force $Stage -ErrorAction SilentlyContinue
}

# ── GPLv2 compliance artefacts ──────────────────────────────────────────────
# Always (re-)write these so they stay aligned with the pinned version.
$NoticeText = @"
WireGuard for Windows
Version: $WG_VERSION
Source:  https://git.zx2c4.com/wireguard-windows/
Author:  Jason A. Donenfeld and contributors
License: GNU General Public License version 2 (GPL-2.0-only) — see
         COPYING.WireGuard.txt next to this file.

This rud1 Desktop installer bundles the unmodified, official
wireguard.exe and wg.exe binaries from the upstream MSI release. They
are invoked as separate processes by the rud1 Desktop main process via
execFile (no linking, no library use) — i.e. mere aggregation per the
GPL FAQ. The signing certificate (WireGuard LLC) and Authenticode
timestamp are preserved.

Corresponding source code for this exact bundled version is available
permanently at:

  https://git.zx2c4.com/wireguard-windows/snapshot/wireguard-windows-$WG_VERSION.tar.xz

If that URL ever moves, the canonical archive lives under
https://git.zx2c4.com/wireguard-windows/. A copy of GPLv2 ships in
COPYING.WireGuard.txt.

The rud1 Desktop project itself is independently licensed and does not
fall under the GPL — only this bundled tool does.
"@
Set-Content -Path $NoticeFile -Value $NoticeText -Encoding utf8
Write-Ok "Wrote $NoticeFile"

# Embed the canonical GPLv2 text. We pull it from the official GNU URL
# the first time, then never re-fetch (the text is immutable).
if (-not (Test-Path $LicenseFile) -or (Get-Item $LicenseFile).Length -lt 8000) {
  Write-Step "Fetching canonical GPLv2 text from www.gnu.org"
  Invoke-WebRequest -Uri "https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt" `
    -OutFile $LicenseFile -UseBasicParsing
  Write-Ok "Wrote $LicenseFile"
}

Write-Host ""
Write-Ok "Done. resources/win32/ now contains:"
Get-ChildItem $Resources | Select-Object Name, Length | Format-Table -AutoSize
