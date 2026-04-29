#requires -version 5.1
<#
.SYNOPSIS
  Cross-compiles the rud1-bridge Go binary for win32 / linux / darwin
  and drops the artefacts into resources/{win32,linux,darwin}/ so
  electron-builder bundles them via extraResources.

.DESCRIPTION
  rud1-bridge is the desktop-side TCP↔serial proxy for rud1's serial
  bridge transport. It runs as a subprocess of the Electron main
  process when the operator attaches a CDC-class device (Arduino,
  ESP32, USB-serial dongle) — see rud1-desktop/src/main/serial-bridge-
  manager.ts for the spawn site.

  Idempotent: by default skips a target whose binary already exists
  AND whose source tree hasn't been modified since the binary's mtime.
  Pass -Force to rebuild everything.

  Cross-compilation is pure Go (no cgo for the runtimes we target),
  so this script runs on a single Windows dev machine and produces
  all three binaries in seconds. No Docker, no Linux toolchain, no
  Apple developer account. The Windows target uses go.bug.st/serial
  which is pure-Go too.

  Linux / macOS binaries don't get a code-signature here. They're
  consumed as supporting binaries inside the Electron AppImage / DMG
  and the Electron app's own signature covers redistribution.

.NOTES
  Requires `go` on PATH. `winget install GoLang.Go` if missing.
  The rud1-bridge module lives at <repo-root>/../rud1-bridge.
#>
param(
  [switch]$Force,
  [string]$Version = "dev"
)

$ErrorActionPreference = "Stop"

# ── Paths ────────────────────────────────────────────────────────────────────
$ScriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot     = Split-Path -Parent $ScriptDir
$BridgeRoot   = Resolve-Path (Join-Path $RepoRoot "..\rud1-bridge")
$ResourceRoot = Join-Path $RepoRoot "resources"

if (-not (Test-Path $BridgeRoot)) {
    throw "rud1-bridge module not found at $BridgeRoot. Expected sibling repo layout."
}

# ── Target matrix ────────────────────────────────────────────────────────────
$Targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; Out = "win32";  Bin = "rud1-bridge.exe" }
    @{ GOOS = "linux";   GOARCH = "amd64"; Out = "linux";  Bin = "rud1-bridge"     }
    @{ GOOS = "darwin";  GOARCH = "amd64"; Out = "darwin"; Bin = "rud1-bridge-x64" }
    @{ GOOS = "darwin";  GOARCH = "arm64"; Out = "darwin"; Bin = "rud1-bridge-arm64" }
)

# ── Source freshness probe ──────────────────────────────────────────────────
# Used to decide whether a target is up-to-date without rebuilding. The
# rud1-bridge source tree is small (~10 files) so a full mtime walk is
# fast; we compare the newest source mtime against each target binary's
# mtime and rebuild only stale ones.
$NewestSource = (Get-ChildItem -Path $BridgeRoot -Recurse -File `
    -Include *.go,go.mod,go.sum |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1).LastWriteTime

if (-not $NewestSource) {
    throw "rud1-bridge source tree appears empty at $BridgeRoot."
}

function Test-NeedsRebuild {
    param([string]$BinPath)
    if ($Force) { return $true }
    if (-not (Test-Path $BinPath)) { return $true }
    $binAge = (Get-Item $BinPath).LastWriteTime
    return $binAge -lt $NewestSource
}

# ── Build loop ───────────────────────────────────────────────────────────────
Push-Location $BridgeRoot
try {
    foreach ($t in $Targets) {
        $outDir = Join-Path $ResourceRoot $t.Out
        $outPath = Join-Path $outDir $t.Bin

        if (-not (Test-Path $outDir)) {
            New-Item -ItemType Directory -Path $outDir | Out-Null
        }

        if (-not (Test-NeedsRebuild $outPath)) {
            Write-Host "[skip] $($t.GOOS)/$($t.GOARCH) -> $outPath (up-to-date)" -ForegroundColor DarkGray
            continue
        }

        Write-Host "[build] $($t.GOOS)/$($t.GOARCH) -> $outPath" -ForegroundColor Cyan

        $env:GOOS   = $t.GOOS
        $env:GOARCH = $t.GOARCH
        $env:CGO_ENABLED = "0"

        # -trimpath strips the local source path from binaries so the
        # diagnostics chip on a user's machine doesn't carry our dev
        # filesystem layout.
        # -ldflags "-s -w" strips the symbol + DWARF tables; saves ~3 MB
        # per binary which adds up across the four targets. PowerShell
        # mangles space-bearing argument values when splatted via `&`, so
        # we pin the flag as a single quoted string passed positionally.
        $ldflags = "-s -w -X main.Version=$Version"
        $goArgs = @("build", "-trimpath", "-ldflags", $ldflags, "-o", $outPath, "./cmd/rud1-bridge")
        & go @goArgs
        if ($LASTEXITCODE -ne 0) {
            throw "go build failed for $($t.GOOS)/$($t.GOARCH) (exit $LASTEXITCODE)"
        }
    }

    # macOS universal binary: lipo isn't available on Windows, so we ship
    # the two arch-specific binaries side-by-side and let the Electron
    # app's main process pick at runtime via process.arch. The launcher
    # in serial-bridge-manager.ts handles the rud1-bridge-x64 vs
    # rud1-bridge-arm64 selection — see the platformBinaryName helper.
} finally {
    Pop-Location
    Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue
}

# ── Version pin file ─────────────────────────────────────────────────────────
# Same pattern wireguard.version uses — lets the desktop's diagnostics
# chip read which build is bundled without spawning the binary just
# to call --version.
$VersionFile = Join-Path $ResourceRoot "win32\rud1-bridge.version"
Set-Content -Path $VersionFile -Value $Version -Encoding ASCII -NoNewline
Copy-Item $VersionFile (Join-Path $ResourceRoot "linux\rud1-bridge.version")  -Force
Copy-Item $VersionFile (Join-Path $ResourceRoot "darwin\rud1-bridge.version") -Force

Write-Host ""
Write-Host "rud1-bridge $Version built for all platforms." -ForegroundColor Green
Write-Host "  win32  -> $ResourceRoot\win32\rud1-bridge.exe"
Write-Host "  linux  -> $ResourceRoot\linux\rud1-bridge"
Write-Host "  darwin -> $ResourceRoot\darwin\rud1-bridge-{x64,arm64}"
