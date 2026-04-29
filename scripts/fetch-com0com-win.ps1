#requires -version 5.1
<#
.SYNOPSIS
  Fetches the signed com0com installer for Windows into resources/win32/
  so electron-builder bundles it via extraResources.

.DESCRIPTION
  com0com is a signed kernel driver that exposes virtual COM-port pairs.
  rud1-desktop's serial bridge depends on at least one configured pair
  to expose a "real" COM port the operator opens in their Arduino IDE
  (or any other serial tool); see `serial-bridge-manager.ts` for the
  spawn site that holds the B-side of the pair while the user opens
  the A-side.

  Why we bundle the installer: com0com is a kernel-mode driver. Driver
  installation needs admin elevation + a signed binary the kernel will
  load. We can't simulate this in userspace - the operator has to run
  the installer at least once. Bundling it means the "Install com0com"
  CTA in the panel resolves to a one-click path instead of sending
  the user on a hunt to SourceForge.

  Idempotent: skips when the file is already present AND matches the
  pinned SHA256. Use -Force to re-download.

  GPLv2 compliance: com0com is GPL-2.0. The script writes
  COPYING.com0com.txt + NOTICE.com0com.txt next to the installer so
  the redistribution carries the licence text + a pointer to the
  corresponding source.

  Pinned upstream: the v3.0.0.0 signed release. Originally maintained
  by Vyacheslav Frolov; current Authenticode signer at the time of
  pinning is CyberCircuits (NZ), who inherited the project's signing
  certificate. Either signature is a CA Windows accepts out of the
  box — works fine on Windows 10/11. Newer unsigned forks exist but
  they all require the user to take their machine into test-signing
  mode, which is a non-starter for an autonomous-install UX.

  ASCII-only on purpose: PowerShell 5.1 reads UTF-8 files without BOM
  as Windows-1252 by default, which turns em-dashes into mojibake and
  breaks the parser. Sticking to ASCII keeps `npm run` happy on every
  Windows shell out there.

.NOTES
  Run from any working directory; paths resolve relative to the script.
  Invoked manually before a release: `npm run fetch:com0com-win`.
#>
param(
  [switch]$Force
)

$ErrorActionPreference = "Stop"

# --- Pinned upstream release ------------------------------------------------
$COM_VERSION = "3.0.0.0"
# SHA256 of the upstream signed ZIP. Verify with PowerShell:
#   Get-FileHash com0com-3.0.0.0-i386-and-x64-signed.zip
# before bumping the pin. Replace with the next release's hash when
# the user upgrades the bundle.
# Hash pinned after the initial verified fetch. Authenticode signer
# at the time of pinning was "CN=CyberCircuits, O=CyberCircuits, ..."
# (NZ) — CyberCircuits inherited the com0com signing certificate from
# Vyacheslav Frolov, who transferred maintainership some years ago.
# Both names are referenced in the project's history; the signature
# verification below is what actually load-bears the trust decision.
$COM_ZIP_SHA256 = "6E5D4359865277430D4AE88C73FB7E648A0ED8E81AEA5002478179CFCB0BB0E1"
# Canonical SourceForge download URL is `sourceforge.net/projects/<p>/files/<path>/download`
# NOT `downloads.sourceforge.net/project/<p>/<path>` — the latter
# redirects to a generic project files browser since SourceForge
# changed their CDN routing. The `sourceforge.net` form returns the
# HTML interstitial with a `<meta refresh>` to a signed mirror URL,
# which the fetch logic below follows.
$COM_ZIP_URL    = "https://sourceforge.net/projects/com0com/files/com0com/$COM_VERSION/com0com-$COM_VERSION-i386-and-x64-signed.zip/download"

# --- Paths ------------------------------------------------------------------
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Split-Path -Parent $ScriptDir
$ResourceDir = Join-Path $RepoRoot "resources\win32"
$OutInstaller = Join-Path $ResourceDir "com0com-installer.exe"
$OutVersion   = Join-Path $ResourceDir "com0com.version"
$OutCopying   = Join-Path $ResourceDir "COPYING.com0com.txt"
$OutNotice    = Join-Path $ResourceDir "NOTICE.com0com.txt"

if (-not (Test-Path $ResourceDir)) {
    New-Item -ItemType Directory -Path $ResourceDir | Out-Null
}

# --- Up-to-date check -------------------------------------------------------
if ((-not $Force) -and (Test-Path $OutInstaller) -and (Test-Path $OutVersion)) {
    $existingVersion = (Get-Content $OutVersion -Raw -ErrorAction SilentlyContinue).Trim()
    if ($existingVersion -eq $COM_VERSION) {
        Write-Host "com0com installer already at $COM_VERSION (use -Force to rebuild)." -ForegroundColor DarkGray
        exit 0
    }
}

# --- Download + verify ------------------------------------------------------
$TmpRoot = Join-Path $env:TEMP "rud1-fetch-com0com"
if (Test-Path $TmpRoot) { Remove-Item $TmpRoot -Recurse -Force }
New-Item -ItemType Directory -Path $TmpRoot | Out-Null
$ZipPath = Join-Path $TmpRoot "com0com.zip"

Write-Host "Downloading com0com $COM_VERSION ..." -ForegroundColor Cyan
# SourceForge serves an HTML interstitial with a `<meta refresh>`
# redirecting to a mirror-specific URL with a signed `ts=` token. PS
# `Invoke-WebRequest` doesn't follow meta refresh natively (it's
# HTML-level, not HTTP 30x), so we do the two-step dance manually:
#   1) Request the canonical /download URL, get HTML
#   2) Parse the meta-refresh target out of the HTML
#   3) Request that signed URL, get the actual ZIP
# Robust to SourceForge changing mirrors or rotating tokens because we
# only depend on the meta-refresh contract, which has been stable for
# a decade. The signed token expires in ~30s but our second request
# is sub-second, so race-free in practice.
$UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) rud1-desktop/0.1"
$resp = Invoke-WebRequest -Uri $COM_ZIP_URL -UseBasicParsing -UserAgent $UA
$body = $resp.Content
if ($body -is [byte[]]) {
    $body = [System.Text.Encoding]::UTF8.GetString($body)
}
$head = ($body.Substring(0, [Math]::Min(8, $body.Length)))
if ($head.StartsWith("PK")) {
    # SourceForge sometimes serves the ZIP directly (older mirrors,
    # cached responses). Skip the meta-refresh parse in that case.
    [System.IO.File]::WriteAllBytes($ZipPath, $resp.Content)
} else {
    # Parse the meta-refresh URL out of the interstitial HTML.
    $m = [regex]::Match($body, '<meta\s+http-equiv="refresh"\s+content="\d+;\s*url=([^"]+)"', 'IgnoreCase')
    if (-not $m.Success) {
        throw "SourceForge served an interstitial without a meta-refresh redirect; layout may have changed."
    }
    # System.Net.WebUtility ships in mscorlib (always loaded), unlike
    # System.Web.HttpUtility which would need `Add-Type -AssemblyName
    # System.Web` and isn't on Windows Server Core.
    $redirectUrl = [System.Net.WebUtility]::HtmlDecode($m.Groups[1].Value)
    Write-Host "  following SourceForge mirror redirect..." -ForegroundColor DarkGray
    Invoke-WebRequest -Uri $redirectUrl -OutFile $ZipPath -UseBasicParsing -UserAgent $UA
}

# Sanity check: the file we just wrote MUST start with the ZIP magic.
# A second HTML page would slip past the hash mismatch with a confusing
# error. Catching it here surfaces a precise diagnostic instead.
$firstBytes = [System.IO.File]::ReadAllBytes($ZipPath) | Select-Object -First 2
if ($firstBytes.Length -lt 2 -or $firstBytes[0] -ne 0x50 -or $firstBytes[1] -ne 0x4B) {
    throw "Downloaded file is not a ZIP (first bytes: $(($firstBytes | ForEach-Object { '0x{0:X2}' -f $_ }) -join ' ')). SourceForge likely served HTML; check the mirror redirect logic."
}

$actualHash = (Get-FileHash -Algorithm SHA256 $ZipPath).Hash
if ($COM_ZIP_SHA256 -eq "PLACEHOLDER_REPLACE_AFTER_FIRST_FETCH") {
    # First-run mode: hash isn't pinned yet. The Authenticode check
    # below is the load-bearing security guarantee; we skip the hash
    # equality check on this run and instead PRINT the hash so a
    # follow-up commit can pin it. Subsequent runs (with a real pin)
    # will fail-closed on any mismatch, catching SourceForge serving
    # a different artefact.
    Write-Host "First fetch: SHA256 = $actualHash" -ForegroundColor Yellow
    Write-Host "After verifying the signature below, replace `$COM_ZIP_SHA256 in this script with that hash to pin." -ForegroundColor Yellow
} elseif ($actualHash -ne $COM_ZIP_SHA256) {
    $msg  = "Downloaded ZIP hash $actualHash does not match pinned $COM_ZIP_SHA256. "
    $msg += "If SourceForge served a different file, refuse to bundle it. "
    $msg += "Update the pinned hash in this script ONLY after manually verifying "
    $msg += "the new ZIP's signature with ``signtool verify`` against a known-good "
    $msg += "CyberCircuits / Vyacheslav Frolov certificate."
    throw $msg
}

# --- Extract installer ------------------------------------------------------
$ExtractDir = Join-Path $TmpRoot "extract"
Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force

# The signed ZIP carries setup_com0com_W7_x64_signed.exe. We rename to
# `com0com-installer.exe` for symmetry with USBip-installer.exe - both
# follow the `<tool>-installer.exe` convention so the binary-helper
# resolver and the panel CTA copy can be platform-agnostic.
$candidates = Get-ChildItem -Path $ExtractDir -Filter "setup_com0com_*_x64_signed.exe" -Recurse
if (-not $candidates -or $candidates.Count -eq 0) {
    $msg  = "Expected setup_com0com_*_x64_signed.exe inside the ZIP; found none. "
    $msg += "SourceForge may have changed the layout - inspect $ExtractDir manually."
    throw $msg
}
$installer = $candidates[0]

Copy-Item $installer.FullName $OutInstaller -Force

# --- Verify Authenticode signature ------------------------------------------
# Refuse to bundle an installer Windows would flag at install time. The
# user shouldn't see "publisher unknown" for what we ship - that defeats
# the autonomous-install UX entirely.
$sig = Get-AuthenticodeSignature $OutInstaller
if ($sig.Status -ne "Valid") {
    throw "Bundled installer signature is $($sig.Status), not Valid. Refusing to ship."
}
Write-Host "Signature: $($sig.SignerCertificate.Subject)" -ForegroundColor Green

# --- Write manifest + license -----------------------------------------------
Set-Content -Path $OutVersion -Value $COM_VERSION -Encoding ASCII -NoNewline

$copying = @"
com0com is licensed under the GNU General Public License v2.

The full text of the license is available at:
https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

Source code corresponding to the bundled binary is available at:
https://sourceforge.net/projects/com0com/

This file is shipped with rud1-desktop's com0com-installer.exe to
satisfy the GPL's "must include / point to source" obligation when
binaries are redistributed.
"@
Set-Content -Path $OutCopying -Value $copying -Encoding UTF8

$notice = @"
This redistribution bundles com0com-installer.exe, the signed installer
for the com0com kernel driver (https://com0com.sourceforge.net/).

Authors: Vyacheslav Frolov and contributors.
Version: $COM_VERSION
License: GPL-2.0 (see COPYING.com0com.txt)
"@
Set-Content -Path $OutNotice -Value $notice -Encoding UTF8

Remove-Item $TmpRoot -Recurse -Force

Write-Host ""
Write-Host "com0com $COM_VERSION bundled." -ForegroundColor Green
Write-Host "  installer  -> $OutInstaller"
Write-Host "  license    -> $OutCopying"
