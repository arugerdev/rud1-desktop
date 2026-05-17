# Regenerates the tray icon set from the main brand asset.
#
# Inputs:  resources/icon.png  (512x512 brand mark)
# Outputs: resources/tray/
#            tray-idle.png         16x16
#            tray-idle@2x.png      32x32
#            tray-attention.png    16x16 + amber tint
#            tray-attention@2x.png 32x32 + amber tint
#
# Run from the rud1-desktop root:
#   pwsh -File scripts/generate-tray-icons.ps1
# or
#   powershell -ExecutionPolicy Bypass -File scripts/generate-tray-icons.ps1
#
# Why PowerShell + System.Drawing instead of a Node script with sharp?
#   - sharp is a 60MB native dep we don't otherwise need.
#   - System.Drawing.Common is built into the Windows .NET runtime.
#   - This script is run once per icon update, committed result.
#   - Maintainers on macOS/Linux can re-run via:
#       npm exec --workspaces -- electron-builder install-app-deps
#     after which the matching Electron `nativeImage` API path can
#     replace this script. Not worth the dependency cost today.

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root "resources/icon.png"
$outDir = Join-Path $root "resources/tray"

if (-not (Test-Path $source)) {
    throw "Source brand icon not found: $source"
}
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

function Resize-Icon {
    param(
        [string] $InputPath,
        [string] $OutputPath,
        [int] $Size,
        [bool] $Tint = $false
    )

    $img = [System.Drawing.Image]::FromFile($InputPath)
    try {
        $bmp = New-Object System.Drawing.Bitmap($Size, $Size)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        try {
            $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $g.SmoothingMode     = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
            $g.PixelOffsetMode   = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
            $g.Clear([System.Drawing.Color]::Transparent)
            $g.DrawImage($img, 0, 0, $Size, $Size)
        } finally {
            $g.Dispose()
        }

        if ($Tint) {
            # Overlay an amber wash on the lit pixels so the "attention"
            # variant is visually distinct in the tray. Iterate per-pixel
            # because System.Drawing's ColorMatrix path requires building
            # a fresh Bitmap and is slower for icons this small.
            for ($y = 0; $y -lt $bmp.Height; $y++) {
                for ($x = 0; $x -lt $bmp.Width; $x++) {
                    $c = $bmp.GetPixel($x, $y)
                    if ($c.A -eq 0) { continue }
                    # Blend each non-transparent pixel ~70% towards amber
                    # (#F2A33C) so the rud1 silhouette is still readable
                    # but obviously "alert" rather than the neutral grey
                    # idle state.
                    $r = [int]([Math]::Round($c.R * 0.3 + 0xF2 * 0.7))
                    $g2 = [int]([Math]::Round($c.G * 0.3 + 0xA3 * 0.7))
                    $b = [int]([Math]::Round($c.B * 0.3 + 0x3C * 0.7))
                    $bmp.SetPixel(
                        $x, $y,
                        [System.Drawing.Color]::FromArgb($c.A, $r, $g2, $b))
                }
            }
        }

        $bmp.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()
    } finally {
        $img.Dispose()
    }

    Write-Host "  wrote $OutputPath  ($Size x $Size)"
}

Write-Host "Regenerating tray icons from $source"
Resize-Icon -InputPath $source -OutputPath (Join-Path $outDir "tray-idle.png")         -Size 16
Resize-Icon -InputPath $source -OutputPath (Join-Path $outDir "tray-idle@2x.png")      -Size 32
Resize-Icon -InputPath $source -OutputPath (Join-Path $outDir "tray-attention.png")    -Size 16 -Tint $true
Resize-Icon -InputPath $source -OutputPath (Join-Path $outDir "tray-attention@2x.png") -Size 32 -Tint $true
Write-Host "Done."
