#requires -version 5.1
<#
.SYNOPSIS
  Pre-flight for `dist:win`. Aborts with an actionable error when a
  process still has a handle on release/win-unpacked/rud1.exe (or any
  file under release/), so electron-builder doesn't fail mid-pack with
  the cryptic "el archivo está siendo utilizado por otro proceso".

.DESCRIPTION
  Uses the Windows Restart Manager API (rstrtmgr.dll) - the same
  service Windows Update uses to identify processes blocking a file.
  Unlike `tasklist` / `Get-Process`, RM can identify holders even when
  this shell isn't elevated and the holder is, AND it can report when
  a freshly-deleted file is still mapped by an old process.

  Exits 0 when nothing holds the build outputs.
  Exits 1 with a clear list of holding PIDs + suggested Stop-Process
  commands when one or more processes are pinning the build dir.
#>

$ErrorActionPreference = "Stop"

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Split-Path -Parent $ScriptDir
$ReleaseRoot = Join-Path $RepoRoot "release"
$Target      = Join-Path $ReleaseRoot "win-unpacked\rud1.exe"

if (-not (Test-Path $Target)) {
  # Nothing to clobber - clean state.
  exit 0
}

# ── Restart Manager P/Invoke ────────────────────────────────────────────────
# PS 5.1's Add-Type returns one Type when there's a single class; the typed
# member-definition shape below has all P/Invokes on a single class so we
# can call them directly. Verified against the public rstrtmgr.dll surface.
$rmTypeDef = @"
using System;
using System.Runtime.InteropServices;

public static class Rm {
  [StructLayout(LayoutKind.Sequential)]
  public struct RM_UNIQUE_PROCESS {
    public int dwProcessId;
    public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct RM_PROCESS_INFO {
    public RM_UNIQUE_PROCESS Process;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]  public string strServiceShortName;
    public int  ApplicationType;
    public uint AppStatus;
    public uint TSSessionId;
    [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
  }

  [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)]
  public static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, System.Text.StringBuilder strSessionKey);

  [DllImport("rstrtmgr.dll")]
  public static extern int RmEndSession(uint pSessionHandle);

  [DllImport("rstrtmgr.dll", CharSet=CharSet.Unicode)]
  public static extern int RmRegisterResources(
    uint pSessionHandle,
    uint nFiles, [MarshalAs(UnmanagedType.LPArray, ArraySubType=UnmanagedType.LPWStr)] string[] rgsFilenames,
    uint nApplications, [In] RM_UNIQUE_PROCESS[] rgApplications,
    uint nServices, [MarshalAs(UnmanagedType.LPArray, ArraySubType=UnmanagedType.LPWStr)] string[] rgsServiceNames);

  [DllImport("rstrtmgr.dll")]
  public static extern int RmGetList(
    uint dwSessionHandle,
    out uint pnProcInfoNeeded,
    ref uint pnProcInfo,
    [In, Out] RM_PROCESS_INFO[] rgAffectedApps,
    ref uint lpdwRebootReasons);
}
"@
if (-not ([System.Management.Automation.PSTypeName]'Rm').Type) {
  Add-Type -TypeDefinition $rmTypeDef -Language CSharp | Out-Null
}

$key = New-Object System.Text.StringBuilder 64
$session = 0
$rc = [Rm]::RmStartSession([ref]$session, 0, $key)
if ($rc -ne 0) {
  Write-Warning "RmStartSession failed (rc=$rc) - falling back to a plain delete probe."
  try {
    $stream = [System.IO.File]::Open($Target, 'Open', 'Read', 'None')
    $stream.Close()
    exit 0  # We could open it exclusively → nobody holds it.
  } catch {
    Write-Host "==> $Target is locked but Restart Manager is unavailable." -ForegroundColor Yellow
    Write-Host "    Close any running rud1.exe (system tray included) and retry."
    exit 1
  }
}

try {
  $rc = [Rm]::RmRegisterResources($session, 1, @($Target), 0, $null, 0, $null)
  if ($rc -ne 0) {
    Write-Warning "RmRegisterResources rc=$rc - assuming clean state."
    exit 0
  }

  [uint32]$needed = 0
  [uint32]$count  = 0
  [uint32]$reasons = 0
  [void][Rm]::RmGetList($session, [ref]$needed, [ref]$count, $null, [ref]$reasons)

  if ($needed -eq 0) {
    # RM saw no holders. Most of the time that's the truth - but on Windows
    # an .exe whose image was loaded by a process that has since exited can
    # still be locked by the kernel's section/VAD mapping until references
    # drain (Defender's MsMpEng scanning the file post-exit is the typical
    # culprit). Confirm with an exclusive-open probe before declaring victory.
    try {
      $stream = [System.IO.File]::Open($Target, 'Open', 'ReadWrite', 'None')
      $stream.Close()
      exit 0
    } catch {
      Write-Host ""
      Write-Host "Cannot run dist:win - $Target is locked, but no holding" -ForegroundColor Red
      Write-Host "process is visible to the Restart Manager. This usually means:" -ForegroundColor Red
      Write-Host "  - Windows Defender is mid-scan on the file (transient, wait 10-30s)."
      Write-Host "  - A process loaded the .exe, exited, and its image mapping is"
      Write-Host "    still pinned by the kernel until the last reference drains."
      Write-Host "  - A SmartScreen / SmartApp Control evaluation is running."
      Write-Host ""
      Write-Host "Find the holder (one of these works):" -ForegroundColor Yellow
      Write-Host "  - Resource Monitor: run 'resmon', CPU tab > Associated Handles >"
      Write-Host "    search 'rud1.exe'. The PID/Image column names the holder."
      Write-Host "  - Sysinternals Handle: handle64.exe -accepteula -nobanner '$Target'"
      Write-Host ""
      Write-Host "Or skip the diagnosis and clear the lock:" -ForegroundColor Yellow
      Write-Host "  - In an admin PowerShell:"
      Write-Host "      Remove-Item -Recurse -Force '$ReleaseRoot'"
      Write-Host "      # If still locked: Restart-Service WinDefend -Force"
      Write-Host "  - Last resort: reboot. The kernel mapping always drains across boots."
      exit 1
    }
  }

  $arr = New-Object 'Rm+RM_PROCESS_INFO[]' $needed
  $count = $needed
  $rc = [Rm]::RmGetList($session, [ref]$needed, [ref]$count, $arr, [ref]$reasons)
  if ($rc -ne 0) {
    Write-Warning "RmGetList rc=$rc - assuming clean state."
    exit 0
  }

  $holders = @()
  for ($i = 0; $i -lt $count; $i++) {
    $pid_ = $arr[$i].Process.dwProcessId
    if ($pid_ -le 0) { continue }
    $procName = "(elevated/inaccessible)"
    try {
      $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$pid_"
      if ($proc -and $proc.Name) { $procName = $proc.Name }
    } catch {}
    $holders += [PSCustomObject]@{
      PID     = $pid_
      Name    = $procName
      AppName = $arr[$i].strAppName
    }
  }

  if ($holders.Count -eq 0) { exit 0 }

  Write-Host ""
  Write-Host "Cannot run dist:win - release/win-unpacked/rud1.exe is locked." -ForegroundColor Red
  Write-Host "  The following process(es) hold a handle on it:" -ForegroundColor Red
  $holders | Format-Table PID, Name, AppName -AutoSize
  Write-Host "Suggested fix (run in an ADMIN PowerShell):" -ForegroundColor Yellow
  foreach ($h in $holders) {
    Write-Host ("  Stop-Process -Id {0} -Force   # {1}" -f $h.PID, $h.Name) -ForegroundColor Yellow
  }
  Write-Host "  Remove-Item -Recurse -Force '$ReleaseRoot'" -ForegroundColor Yellow
  Write-Host "Then re-run: npm run dist:win"
  exit 1
}
finally {
  [void][Rm]::RmEndSession($session)
}
