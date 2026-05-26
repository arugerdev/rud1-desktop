#requires -version 5.1
<#
.SYNOPSIS
  Fetches the OpenVPN Community runtime + the standalone TAP-Windows V9
  driver installer, verifies signatures + pinned SHA256 hashes, and
  stages everything under resources/win32/openvpn/ for electron-builder
  to pick up via extraResources.

.DESCRIPTION
  Idempotent: skips work when both bundles already match the pinned
  versions. Otherwise downloads two signed artefacts from openvpn.org:

    1. OpenVPN-2.6.12-I001-amd64.msi
       Signed by "OpenVPN Inc.". Contains openvpn.exe + tapctl.exe +
       openssl + runtime DLLs. We extract it via msiexec /a (admin
       install - no elevation needed) into a temp dir and copy the
       portable runtime into resources/win32/openvpn/.

    2. tap-windows-9.21.2.exe
       Signed by "OpenVPN Technologies, Inc.". NSIS installer for the
       TAP-Windows V9 kernel driver (DriverVer 9.21.2). We DO NOT
       extract it here -- we bundle it AS IS to
       resources/win32/openvpn/driver/tap-windows-installer.exe and
       run it silently with elevation at app first-launch (the
       .inf/.cat/.sys files live inside the NSIS package and are
       unpacked by its installer).

       This is necessary because OpenVPN 2.6.x MSI dropped the bundled
       TAP driver -- msiexec /a ADDLOCAL=ALL does NOT extract the
       driver feature; the MSI's CustomActions install it only during
       a real (not administrative) install. Bundling the standalone
       installer is the only reliable way to ship the driver with the
       app for offline first-runs.

  License: OpenVPN Community is GPL-2.0-with-OpenSSL-exception. We
  write COPYING.OpenVPN.txt + NOTICE.OpenVPN.txt alongside the binaries.

.NOTES
  Run from any working directory; paths resolve relative to the script.
#>
param(
  [switch]$Force
)

$ErrorActionPreference = "Stop"

# Pinned upstream versions + SHA256. To bump, update three pairs of values
# (URL + version + hash), commit, push -- CI re-validates on every run.
$OPENVPN_VERSION = "2.6.12"
$OPENVPN_SHA256  = "525759fe9e52a77a7d2cad99f5af1923d7d3027cab775ccfb7469ce0fd2b1758"
$OPENVPN_URL     = "https://swupdate.openvpn.org/community/releases/OpenVPN-$OPENVPN_VERSION-I001-amd64.msi"

# tap-windows is updated independently of OpenVPN. 9.21.2 is the latest
# standalone build available on swupdate.openvpn.org and is the kernel
# driver that OpenVPN 2.6 uses internally.
$TAP_VERSION = "9.21.2"
$TAP_SHA256  = "645bee92ba4e9f32ddfdd9f8519dc1b9f9ff0b0a8e87e342f08d39da77e499a9"
$TAP_URL     = "https://swupdate.openvpn.org/community/releases/tap-windows-$TAP_VERSION.exe"

# Paths
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Split-Path -Parent $ScriptDir
$ResourcesWin32 = Join-Path $RepoRoot "resources\win32"
$BundleDir   = Join-Path $ResourcesWin32 "openvpn"
$DriverDir   = Join-Path $BundleDir "driver"
$VersionFile = Join-Path $BundleDir "openvpn.version"
$TapVerFile  = Join-Path $DriverDir "tap-windows.version"
$OpenVpnExe  = Join-Path $BundleDir "openvpn.exe"
$TapctlExe   = Join-Path $BundleDir "tapctl.exe"
$TapInstall  = Join-Path $DriverDir "tap-windows-installer.exe"
$LicenseFile = Join-Path $BundleDir "COPYING.OpenVPN.txt"
$NoticeFile  = Join-Path $BundleDir "NOTICE.OpenVPN.txt"

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "OK  $msg" -ForegroundColor Green }
function Write-Warn2($m)  { Write-Host "!!  $m" -ForegroundColor Yellow }

# Idempotency: skip if both bundles match their pinned versions.
$openvpnPinned = if (Test-Path $VersionFile) { (Get-Content $VersionFile -Raw).Trim() } else { "" }
$tapPinned     = if (Test-Path $TapVerFile)  { (Get-Content $TapVerFile  -Raw).Trim() } else { "" }
if (-not $Force -and
    $openvpnPinned -eq $OPENVPN_VERSION -and (Test-Path $OpenVpnExe) -and (Test-Path $TapctlExe) -and
    $tapPinned -eq $TAP_VERSION         -and (Test-Path $TapInstall)) {
  Write-Ok "OpenVPN $OPENVPN_VERSION + TAP-Windows $TAP_VERSION already present. Use -Force to re-download."
  exit 0
}

$Stage = Join-Path $env:TEMP "rud1-openvpn-fetch-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
$Msi = Join-Path $Stage "openvpn.msi"
$TapExe = Join-Path $Stage "tap-windows.exe"

function Get-SignedFile {
  param(
    [string]$Url,
    [string]$Destination,
    [string]$ExpectedSha256,
    [string[]]$ExpectedSubjectPatterns,
    [string]$Label
  )
  Write-Step "Downloading $Url"
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing

  Write-Step "Verifying SHA256 ($Label)"
  $hash = (Get-FileHash -Path $Destination -Algorithm SHA256).Hash.ToLower()
  if ($hash -ne $ExpectedSha256) {
    throw "SHA256 mismatch for $Label. Expected $ExpectedSha256, got $hash. Refusing to use."
  }
  Write-Ok "SHA256 matches pinned value"

  Write-Step "Verifying Authenticode signature ($Label)"
  $sig = Get-AuthenticodeSignature -FilePath $Destination
  if ($sig.Status -ne "Valid") {
    throw "Authenticode status not Valid for $Label. Refusing to use."
  }
  $subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
  $subjectOk = $false
  foreach ($p in $ExpectedSubjectPatterns) { if ($subject -match $p) { $subjectOk = $true; break } }
  if (-not $subjectOk) {
    throw ("Unexpected signer subject for " + $Label + ": " + $subject + ". Expected one of: " + ($ExpectedSubjectPatterns -join ', '))
  }
  Write-Ok "Signed by '$subject', timestamp valid"
}

try {
  Get-SignedFile -Url $OPENVPN_URL -Destination $Msi `
    -ExpectedSha256 $OPENVPN_SHA256 `
    -ExpectedSubjectPatterns @("OpenVPN Inc\.") `
    -Label "OpenVPN $OPENVPN_VERSION MSI"

  Get-SignedFile -Url $TAP_URL -Destination $TapExe `
    -ExpectedSha256 $TAP_SHA256 `
    -ExpectedSubjectPatterns @("OpenVPN Technologies, Inc\.", "OpenVPN Inc\.") `
    -Label "TAP-Windows V$TAP_VERSION installer"

  Write-Step "Extracting OpenVPN MSI via msiexec /a"
  $Extract = Join-Path $Stage "extracted"
  New-Item -ItemType Directory -Force -Path $Extract | Out-Null
  $proc = Start-Process msiexec.exe `
    -ArgumentList "/a", "`"$Msi`"", "/qb", "TARGETDIR=`"$Extract`"" `
    -Wait -PassThru -NoNewWindow
  if ($proc.ExitCode -ne 0) {
    throw "msiexec /a exited with code $($proc.ExitCode)"
  }

  # Layout under the staging directory after msiexec /a:
  #   OpenVPN\bin\openvpn.exe
  #   OpenVPN\bin\tapctl.exe
  #   OpenVPN\bin\openvpnserv.exe
  #   OpenVPN\bin\openssl.exe
  #   OpenVPN\bin\*.dll  (libssl-3-x64, libcrypto-3-x64, libpkcs11-helper-1, vcruntime140)
  #
  # NOTE: OpenVPN 2.6 MSI does NOT extract the TAP-Windows V9 driver here
  # (we ship that separately as tap-windows-installer.exe in driver/).
  $SrcBin = Join-Path $Extract "OpenVPN\bin"
  if (-not (Test-Path (Join-Path $SrcBin "openvpn.exe"))) {
    throw "Expected openvpn.exe under $SrcBin but it's missing -- MSI layout changed?"
  }

  $extractedExe = Join-Path $SrcBin "openvpn.exe"
  $s = Get-AuthenticodeSignature -FilePath $extractedExe
  if ($s.Status -ne "Valid") {
    throw "Extracted openvpn.exe has Authenticode status that is not Valid. Refusing to use."
  }

  Write-Step "Installing into $BundleDir"
  if (Test-Path $BundleDir) { Remove-Item -Recurse -Force $BundleDir }
  New-Item -ItemType Directory -Force -Path $BundleDir | Out-Null
  New-Item -ItemType Directory -Force -Path $DriverDir | Out-Null

  # Runtime: openvpn-friendly portable layout (DLLs sit next to exes;
  # libssl/libcrypto are non-relocatable).
  $copy = @(
    "openvpn.exe", "tapctl.exe", "openvpnserv.exe", "openssl.exe",
    "libssl-3-x64.dll", "libcrypto-3-x64.dll",
    "libpkcs11-helper-1.dll", "libopenvpn_plap.dll",
    "vcruntime140.dll"
  )
  foreach ($f in $copy) {
    $src = Join-Path $SrcBin $f
    if (Test-Path $src) {
      Copy-Item $src -Destination $BundleDir -Force
    } else {
      Write-Warn2 "$f missing from MSI extract (non-fatal -- some are optional)"
    }
  }

  # TAP driver: bundle the signed standalone installer for first-launch.
  Copy-Item $TapExe -Destination $TapInstall -Force

  # Pin files so future fetches can short-circuit.
  Set-Content -Path $VersionFile -Value $OPENVPN_VERSION -Encoding ascii
  Set-Content -Path $TapVerFile  -Value $TAP_VERSION    -Encoding ascii

  # GPLv2 license text. Use the OpenVPN-bundled license.txt when present.
  $upstreamLic = Join-Path $Extract "OpenVPN\license.txt"
  if (Test-Path $upstreamLic) {
    Copy-Item $upstreamLic -Destination $LicenseFile -Force
    Write-Ok "Copied upstream license.txt as COPYING.OpenVPN.txt"
  }

  $notice = "This product bundles OpenVPN Community runtime (v$OPENVPN_VERSION) and the`r`n" +
            "TAP-Windows V9 kernel driver installer (v$TAP_VERSION), each redistributed`r`n" +
            "under the GPLv2 license with the OpenSSL exception clause as published by`r`n" +
            "OpenVPN Inc.`r`n`r`n" +
            "Sources:`r`n" +
            "  https://github.com/OpenVPN/openvpn`r`n" +
            "  https://github.com/OpenVPN/tap-windows6`r`n" +
            "  https://openvpn.net/community-downloads/`r`n`r`n" +
            "Both files were downloaded from https://swupdate.openvpn.org and verified`r`n" +
            "to be signed by OpenVPN Inc. / OpenVPN Technologies, Inc.`r`n`r`n" +
            "Original SHA256 hashes:`r`n" +
            "  openvpn-$OPENVPN_VERSION.msi  $OPENVPN_SHA256`r`n" +
            "  tap-windows-$TAP_VERSION.exe  $TAP_SHA256`r`n"
  Set-Content -Path $NoticeFile -Value $notice -Encoding utf8

  Write-Ok "OpenVPN $OPENVPN_VERSION runtime + TAP-Windows V$TAP_VERSION installer staged at $BundleDir"
  Write-Host ""
  Write-Host "Files installed:" -ForegroundColor Cyan
  Get-ChildItem -Path $BundleDir -Recurse -File |
    Select-Object FullName, Length | Format-Table -AutoSize | Out-String -Width 200
}
finally {
  if (Test-Path $Stage) {
    Remove-Item -Recurse -Force $Stage -ErrorAction SilentlyContinue
  }
}
