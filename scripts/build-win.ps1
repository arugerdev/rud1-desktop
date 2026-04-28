#requires -version 5.1
<#
.SYNOPSIS
  Orchestrates `dist:win` end-to-end with a graceful fallback when the
  default `release/` output directory is locked by an external process
  (Vanguard, Defender, a leftover instance, etc).

.DESCRIPTION
  Runs in this order:
    1. Fetch + verify WireGuard binaries into resources/win32/.
    2. tsc compile.
    3. Decide output directory:
         - default `release/` if it's writable (or doesn't exist yet),
         - else `release-<timestamp>/` so the build can proceed
           regardless of who holds the old one.
    4. Invoke electron-builder with --config.directories.output set to
       the chosen path.

  Why this exists: Riot's Vanguard anti-cheat (vgc.exe), Windows
  Defender, SmartScreen, and the like sometimes pin a handle on
  release\win-unpacked\rud1.exe long after the previous build's
  rud1.exe has exited. The kernel-level mapping outlives the process.
  In the worst case neither delete nor rename of the directory work
  while the gaming session is live, but a brand-new path is always
  free to write. This script rotates to such a path when needed.

  The orphaned release-* directories persist; clean them up manually
  when you're not gaming. They're listed at the end of every run so
  they don't sneak up on you.

.NOTES
  Invoked by `npm run dist:win`. Run it directly with
      powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-win.ps1
  if you want to skip npm.
#>

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = Split-Path -Parent $ScriptDir

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function OK($m)   { Write-Host "OK  $m" -ForegroundColor Green }
function Warn2($m){ Write-Host "!!  $m" -ForegroundColor Yellow }

# ── 1. Fetch WireGuard ──────────────────────────────────────────────────────
Step "Fetching WireGuard binaries (idempotent)"
try {
  & (Join-Path $ScriptDir "fetch-wireguard-win.ps1")
} catch {
  throw "fetch-wireguard-win.ps1 failed: $_"
}

# ── 1b. Fetch usbip-win2 installer ──────────────────────────────────────────
Step "Fetching usbip-win2 installer (idempotent)"
try {
  & (Join-Path $ScriptDir "fetch-usbip-win.ps1")
} catch {
  throw "fetch-usbip-win.ps1 failed: $_"
}

# ── 1c. Generate app icons from rud1-es favicon ─────────────────────────────
# Idempotente: copia el .ico tal cual y re-renderiza el .png. Si el
# operador no tiene Python instalado, dejamos que el build siga — los
# iconos por defecto de Electron se usan como fallback.
# ────────────────────────────────────────────────────────────────────────────
# Step "Generating app icons (resources/icon.{ico,png})"
# $icons = Join-Path $ScriptDir "generate-app-icons.py"
# $python = Get-Command python -ErrorAction SilentlyContinue
# if ($null -eq $python) {
#   Warn2 "python no encontrado en PATH; saltando generate-app-icons.py."
#   Warn2 "Instala Python 3 y Pillow (`pip install --user Pillow`) para empaquetar los iconos."
# } else {
#   try {
#   & $python.Source $icons
#   } catch {
#     throw "generate-app-icons.py failed: $_"
#   }
# }
# ────────────────────────────────────────────────────────────────────────────

# ── 2. tsc compile ──────────────────────────────────────────────────────────
Step "Running tsc"
$tsc = Join-Path $RepoRoot "node_modules\.bin\tsc.cmd"
if (-not (Test-Path $tsc)) { throw "tsc not found at $tsc - run 'npm install' first" }
try {
  & $tsc --outDir (Join-Path $RepoRoot "dist")
} catch {
  throw "tsc failed: $_"
}

# ── 3. Decide output directory ──────────────────────────────────────────────
$DefaultOut = Join-Path $RepoRoot "release"

# The previous heuristic only probed rud1.exe — but Vanguard / Defender /
# SmartScreen cheerfully scan every executable they see, so any of the
# bundled binaries (wireguard.exe, wg.exe, USBip-installer.exe, the
# unpacked Electron .exe…) can hold the lock too. The only honest test
# is "can we actually clear this directory?" — try it, and if it fails
# rotate. We do this even when the directory exists but looks empty:
# stale tmp from a half-built run could be locking a single .pak.
function Test-DirectoryClearable([string]$path) {
  if (-not (Test-Path $path)) { return $true }
  try {
    Remove-Item -Recurse -Force $path -ErrorAction Stop
    return $true
  } catch {
    return $false
  }
}

$OutDir = $DefaultOut
$Rotated = $false
if (-not (Test-DirectoryClearable $DefaultOut)) {
  $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
  $OutDir = Join-Path $RepoRoot "release-$ts"
  $Rotated = $true
  Warn2 "release\ is locked (likely Vanguard / Defender / SmartScreen)."
  Warn2 "Rotating output to: $OutDir"
  Warn2 "The old release\ keeps its lock holder; clean it up later when you're"
  Warn2 "  not gaming. Run: Remove-Item -Recurse -Force '$DefaultOut'"
}

# ── 4. electron-builder ─────────────────────────────────────────────────────
Step "Running electron-builder --win (output: $(Split-Path -Leaf $OutDir))"
$builder = Join-Path $RepoRoot "node_modules\.bin\electron-builder.cmd"
if (-not (Test-Path $builder)) { throw "electron-builder not found at $builder" }
# `--config.directories.output` is the documented way to override the
# YAML/package.json output dir from the CLI; it wins over the default
# defined in package.json's "build.directories.output".

try {
  & $builder --win --config.directories.output=$OutDir
} catch {
  throw "electron-builder failed: $_"
}

# ── 5. Surface the result ──────────────────────────────────────────────────
Write-Host ""
OK "Build complete."
$installer = Get-ChildItem -Path $OutDir -Filter "*Setup*.exe" -File -ErrorAction SilentlyContinue | Select-Object -First 1
if ($installer) {
  Write-Host "  Installer: $($installer.FullName)" -ForegroundColor Green
  Write-Host "  Size:      $('{0:N1} MB' -f ($installer.Length / 1MB))"
}
Write-Host "  Unpacked:  $(Join-Path $OutDir 'win-unpacked\rud1.exe')"

if ($Rotated) {
  Write-Host ""
  Warn2 "Stale release-* dirs you may want to delete when gaming sessions end:"
  Get-ChildItem -Path $RepoRoot -Filter "release*" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -ne $OutDir -and $_.Name -ne "release" -or ($_.Name -eq "release" -and $_.FullName -ne $OutDir) } |
    Select-Object FullName, @{n='SizeMB';e={[Math]::Round((Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum / 1MB, 1)}} |
    Format-Table -AutoSize
}
