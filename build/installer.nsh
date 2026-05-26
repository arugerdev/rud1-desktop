; ============================================================================
; rud1-desktop NSIS post-install hooks.
;
; Runs the heavy "first-launch setup" work during install (where we already
; hold UAC elevation) rather than on every Connect click — driver install,
; rud1-tap adapter creation and the rename to "rud1" together cost 10-30s,
; and doing them at setup time means the operator's first Connect is
; sub-second instead of waiting for a UAC prompt + driver install.
;
; The actual work is delegated to PowerShell because (a) it can call
; tapctl/pnputil correctly, (b) errors are far easier to diagnose, and
; (c) it mirrors the runtime-fallback code-path in openvpn-installer.ts
; line-for-line so we don't have two sources of truth.
;
; All sections are idempotent: re-running the installer over an existing
; install (upgrade path) safely no-ops when the driver / adapter is
; already present.
; ============================================================================

!macro customInstall
  ; $INSTDIR is the install root chosen by the user (e.g.
  ; C:\Program Files\rud1\). resources/bin/openvpn/{tapctl.exe,
  ; driver/tap-windows-installer.exe} were copied by electron-builder
  ; via the extraResources entry in package.json.
  SetOutPath "$INSTDIR\resources\bin\openvpn"
  DetailPrint "rud1: provisioning TAP-Windows V9 driver + rud1-tap adapter..."
  nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\bin\openvpn\setup-tap.ps1"'
  Pop $0
  ${If} $0 == 0
    DetailPrint "rud1: TAP setup OK."
  ${Else}
    DetailPrint "rud1: TAP setup exited $0 (non-fatal; app falls back at Connect)."
  ${EndIf}
!macroend

!macro customUnInstall
  ; Remove the rud1-tap adapter on uninstall so the operator's
  ; "Network Connections" panel is clean. We leave the TAP-Windows V9
  ; driver itself in the driver store — other OpenVPN-based apps may
  ; rely on it, and removing it would require a reboot.
  ${If} ${FileExists} "$INSTDIR\resources\bin\openvpn\teardown-tap.ps1"
    DetailPrint "rud1: removing rud1-tap adapter..."
    nsExec::ExecToLog 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\bin\openvpn\teardown-tap.ps1"'
    Pop $0
  ${EndIf}
!macroend
