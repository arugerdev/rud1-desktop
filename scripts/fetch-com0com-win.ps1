#requires -version 5.1
<#
.SYNOPSIS
  Verifies the vendored signed com0com installer in resources/win32/com0com/
  so electron-builder bundles a known-good binary via extraResources.

.DESCRIPTION
  Transport for serial/CDC devices. com0com provides the virtual COM port
  pair (kernel driver); rud1-bridge speaks RFC 2217 to the Pi and drives the
  B-side. See docs/serial-com0com-migration.md §4 for the signing decision.

  The installer is COMMITTED to the repo (like USBip-installer.exe,
  cf. commit 9058b63), not downloaded at build time — SourceForge serves an
  HTML interstitial that breaks scripted download. This script VERIFIES the
  vendored file against the pinned SHA256 and fails CLOSED on mismatch.

  Decisión §4 (2026-06-22): com0com 2.2.2.0 x64 signed. Elegido sobre 3.0.0.0
  porque su driver está cross-signed ANTES del corte del 29-jul-2015 (cert
  Hatchett ~2010) → grandfathered, carga en Win10 1607+/Win11 con Secure Boot.
  El 3.0.0.0 (CyberCircuits, 2017) es post-corte → Error Code 52. El setup.exe
  exterior NO está firmado, pero lo lanza nuestro proceso elevado con /S (sin
  MOTW → sin SmartScreen); lo que importa es el driver, firmado por catálogo
  (com0com.cat = Valid).
#>
param(
  [switch]$Force  # acepto el flag por simetría con los demás fetch:*; no-op aquí
)

$ErrorActionPreference = "Stop"

# --- Pin del instalador vendorizado (opción A, verificado a mano) ----------
$C0C_VERSION = "2.2.2.0"
$C0C_FILE    = "com0com-2.2.2.0-x64-fre-signed.exe"
$C0C_SHA256  = "64CF92E5B56F94C1CA14BBBBDCF0CB38B866241C6400E67B5E41C58DAEC39C12"
# Signer del driver embebido (com0com.cat). Verificado: CN=Steven William Hatchett.
$C0C_DRIVER_SIGNER_SUBSTRING = "Hatchett"
# ---------------------------------------------------------------------------

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Split-Path -Parent $ScriptDir
$C0CDir      = Join-Path $RepoRoot "resources\win32\com0com"
$Installer   = Join-Path $C0CDir $C0C_FILE
$OutVersion  = Join-Path $RepoRoot "resources\win32\com0com.version"

if (-not (Test-Path $Installer)) {
    throw "Falta el instalador vendorizado: $Installer. Cópialo desde el paquete oficial com0com-2.2.2.0-x64-fre-signed (SourceForge)."
}

# 1) Hash pin — fail closed. Garantiza que es EXACTAMENTE el binario cuyo
#    driver embebido se verificó a mano (com0com.cat = Valid, Hatchett).
$actual = (Get-FileHash -Path $Installer -Algorithm SHA256).Hash.ToUpperInvariant()
if ($actual -ne $C0C_SHA256.ToUpperInvariant()) {
    throw "SHA256 mismatch. expected=$C0C_SHA256 actual=$actual — instalador rechazado."
}
Write-Host "SHA256 OK: $actual" -ForegroundColor Green

# 2) Verificación del driver embebido (best-effort, requiere 7-Zip). El pin
#    de hash ya garantiza la identidad; esto es defensa en profundidad.
$sevenz = @(
    "$env:ProgramFiles\7-Zip\7z.exe",
    "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($sevenz) {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("c0c-verify-" + $C0C_VERSION)
    if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
    & $sevenz x "$Installer" "-o$tmp" -y *> $null
    $cat = Get-ChildItem -Path $tmp -Recurse -Filter "com0com.cat" | Select-Object -First 1
    if (-not $cat) { throw "No se encontró com0com.cat en el instalador — inesperado." }
    $sig = Get-AuthenticodeSignature $cat.FullName
    if ($sig.Status -ne "Valid") {
        throw "Firma del driver inválida: com0com.cat = $($sig.Status)."
    }
    if ($sig.SignerCertificate.Subject -notlike "*$C0C_DRIVER_SIGNER_SUBSTRING*") {
        throw "Signer del driver inesperado: $($sig.SignerCertificate.Subject)."
    }
    Write-Host "Driver OK: com0com.cat <- $($sig.SignerCertificate.Subject)" -ForegroundColor Green
    Remove-Item $tmp -Recurse -Force
} else {
    Write-Warning "7-Zip no encontrado: se omite la verificación del driver embebido (el pin de SHA256 ya garantiza la identidad)."
}

Set-Content -Path $OutVersion -Value $C0C_VERSION -Encoding ASCII -NoNewline
Write-Host ""
Write-Host "com0com $C0C_VERSION verificado en $Installer." -ForegroundColor Green
