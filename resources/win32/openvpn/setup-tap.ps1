# =============================================================================
# rud1-desktop setup-time TAP-Windows provisioning.
#
# Invoked by build/installer.nsh during NSIS install (and silently on upgrade,
# since electron-builder re-runs customInstall on every setup). Each step is
# idempotent so re-runs over an existing install are safe and fast.
#
# Steps:
#   1. Install the TAP-Windows V9 kernel driver into the Windows driver store
#      if it's missing (via the bundled tap-windows-installer.exe /S).
#   2. Create the `rud1-tap` adapter via `tapctl create` if it doesn't exist.
#   3. Re-skin the adapter's user-visible labels to "rud1" so engineering
#      tools (TIA Portal, Codesys, Set PG/PC Interface) show a friendly name.
#
# Exit codes:
#   0 - All steps succeeded (or were no-ops because everything was already set up).
#   1 - tapctl.exe is missing.
#   2 - tap-windows-installer.exe is missing AND driver isn't in store.
#   3 - tapctl create failed for non-idempotent reasons.
#   4 - rename failed (not blocking — adapter still works).
# =============================================================================

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version 3.0

# This script lives next to the binaries in
# <INSTDIR>\resources\bin\openvpn\, so PSScriptRoot points there.
$ovpnDir       = $PSScriptRoot
$tapctl        = Join-Path $ovpnDir 'tapctl.exe'
$tapInstaller  = Join-Path $ovpnDir 'driver\tap-windows-installer.exe'

function Write-Step($msg) { Write-Host "[rud1-setup] $msg" }

if (-not (Test-Path $tapctl)) {
    Write-Step "ERROR: tapctl.exe not found at $tapctl"
    exit 1
}

# ---- Step 1: ensure TAP-Windows V9 driver is in the Windows driver store ----

Write-Step "Probing Windows driver store for TAP-Windows V9..."
$pnpOutput = & pnputil.exe /enum-drivers 2>&1
$driverInStore = ($pnpOutput | Out-String) -match 'tap0901\.inf|OpenVPN\s+Technologies,?\s*Inc'

if ($driverInStore) {
    Write-Step "TAP-Windows V9 driver already in store — skipping installer."
} else {
    if (-not (Test-Path $tapInstaller)) {
        Write-Step "ERROR: driver not in store AND tap-windows-installer.exe missing at $tapInstaller"
        exit 2
    }
    Write-Step "Running tap-windows-installer.exe /S (silent)..."
    $proc = Start-Process -FilePath $tapInstaller -ArgumentList '/S' -Wait -PassThru -WindowStyle Hidden
    if ($proc.ExitCode -ne 0) {
        # The NSIS installer occasionally returns non-zero even when the
        # driver lands successfully (collision with a prior install). Re-probe
        # the store; if the driver is there we proceed.
        $pnpOutput = & pnputil.exe /enum-drivers 2>&1
        $driverInStore = ($pnpOutput | Out-String) -match 'tap0901\.inf|OpenVPN\s+Technologies,?\s*Inc'
        if (-not $driverInStore) {
            Write-Step "WARN: installer exited $($proc.ExitCode) and driver still not in store"
        } else {
            Write-Step "Installer exited $($proc.ExitCode) but driver is in store — continuing."
        }
    } else {
        Write-Step "Driver installed."
    }
}

# ---- Step 2: clean up stray TAP adapters + create rud1-tap if missing ----

# The bundled NSIS installer auto-creates a default adapter ("Ethernet N",
# description "TAP-Windows Adapter V9"). Delete every TAP V9 instance that
# ISN'T ours so the Network Connections panel stays clean.
try {
    $strays = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceDescription -match '^TAP-Windows Adapter V9' -and $_.Name -ne 'rud1-tap' }
    foreach ($a in $strays) {
        Write-Step "Deleting stray TAP adapter '$($a.Name)' (desc: $($a.InterfaceDescription))..."
        & $tapctl delete $a.Name 2>&1 | Out-Null
    }
} catch {
    Write-Step "WARN: stray adapter cleanup failed: $($_.Exception.Message)"
}

# Create the rud1-tap adapter if it doesn't already exist.
$rud1Tap = Get-NetAdapter -Name 'rud1-tap' -IncludeHidden -ErrorAction SilentlyContinue
if ($rud1Tap) {
    Write-Step "rud1-tap adapter already present (alias=$($rud1Tap.Name), desc=$($rud1Tap.InterfaceDescription))."
} else {
    Write-Step "Creating rud1-tap adapter via tapctl..."
    $createOutput = & $tapctl create --hwid 'root\tap0901' --name 'rud1-tap' 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Step "ERROR: tapctl create failed (exit $LASTEXITCODE): $createOutput"
        exit 3
    }
    Write-Step "Adapter created: $createOutput"
    # Brief wait for NDIS to publish the new device — sometimes Get-NetAdapter
    # returns null for ~1s after tapctl create.
    Start-Sleep -Milliseconds 800
}

# ---- Step 3: rewrite the adapter's user-visible labels to "rud1" ----

$NEW_NAME = 'rud1'
$adapter = $null
for ($i = 0; $i -lt 25; $i++) {
    try {
        $adapter = Get-NetAdapter -Name 'rud1-tap' -IncludeHidden -ErrorAction Stop
        if ($adapter) { break }
    } catch { }
    Start-Sleep -Milliseconds 200
}

if (-not $adapter) {
    Write-Step "WARN: rud1-tap adapter not found after creation — skipping rename."
    exit 4
}

$guid = $adapter.InterfaceGuid
$classRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'
$match = Get-ChildItem $classRoot -ErrorAction SilentlyContinue | Where-Object {
    try { (Get-ItemProperty $_.PsPath -Name NetCfgInstanceId -ErrorAction Stop).NetCfgInstanceId -eq $guid } catch { $false }
} | Select-Object -First 1

if (-not $match) {
    Write-Step "WARN: class subkey for rud1-tap not found — skipping rename."
    exit 4
}

# Fast-path: skip the slow disable/enable when description is already correct.
$currentDesc = (Get-ItemProperty -Path $match.PsPath -Name 'DriverDesc' -ErrorAction SilentlyContinue).DriverDesc
if ($currentDesc -eq $NEW_NAME) {
    Write-Step "rud1-tap description already '$NEW_NAME' — no-op."
    exit 0
}

Write-Step "Renaming rud1-tap labels (was '$currentDesc') -> '$NEW_NAME'..."
Set-ItemProperty -Path $match.PsPath -Name 'DriverDesc'   -Value $NEW_NAME -Force
Set-ItemProperty -Path $match.PsPath -Name 'FriendlyName' -Value $NEW_NAME -Force
Set-ItemProperty -Path $match.PsPath -Name 'ProviderName' -Value $NEW_NAME -Force
if (Get-ItemProperty -Path $match.PsPath -Name '*IfDescription' -ErrorAction SilentlyContinue) {
    Set-ItemProperty -Path $match.PsPath -Name '*IfDescription' -Value $NEW_NAME -Force
}

# NetworkCards legacy table (older Siemens enumerators read this).
$ncRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards'
$ncMatch = Get-ChildItem $ncRoot -ErrorAction SilentlyContinue | Where-Object {
    try { (Get-ItemProperty $_.PsPath -Name ServiceName -ErrorAction Stop).ServiceName -eq $guid } catch { $false }
} | Select-Object -First 1
if ($ncMatch) {
    Set-ItemProperty -Path $ncMatch.PsPath -Name 'Description' -Value $NEW_NAME -Force
}

# Disable+Enable so PnP re-publishes the new labels to NDIS listeners.
try { Disable-NetAdapter -Name 'rud1-tap' -Confirm:$false -ErrorAction Stop } catch { }
Start-Sleep -Milliseconds 600
try { Enable-NetAdapter -Name 'rud1-tap' -Confirm:$false -ErrorAction Stop } catch { }

Write-Step "Done."
exit 0
