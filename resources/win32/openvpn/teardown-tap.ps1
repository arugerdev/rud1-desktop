# =============================================================================
# rud1-desktop NSIS uninstall hook — removes the rud1-tap adapter from
# Network Connections. The TAP-Windows V9 kernel driver itself is left in
# place (other OpenVPN-based apps share it, and dropping it would force
# a reboot for the user — too aggressive for an "uninstall rud1" action).
#
# Always exits 0 — uninstall must never abort over a cosmetic adapter
# cleanup failure.
# =============================================================================

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version 3.0

$ovpnDir = $PSScriptRoot
$tapctl  = Join-Path $ovpnDir 'tapctl.exe'

if (-not (Test-Path $tapctl)) { exit 0 }

try {
    $a = Get-NetAdapter -Name 'rud1-tap' -IncludeHidden -ErrorAction SilentlyContinue
    if ($a) {
        Write-Host "[rud1-teardown] Deleting rud1-tap adapter..."
        & $tapctl delete 'rud1-tap' 2>&1 | Out-Null
    } else {
        Write-Host "[rud1-teardown] rud1-tap adapter already absent — no-op."
    }
} catch {
    Write-Host "[rud1-teardown] Cleanup failed (non-fatal): $($_.Exception.Message)"
}
exit 0
