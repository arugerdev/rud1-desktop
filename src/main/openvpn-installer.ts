/**
 * First-run OpenVPN runtime detection + TAP-Windows V9 driver installer.
 *
 * Bundled approach (Option A per docs/architecture/vpn.md):
 *   The rud1-desktop installer ships portable openvpn.exe + the runtime
 *   DLLs + the TAP-Windows V9 INF/CAT files under
 *   `resources/win32/openvpn/`. The OpenVPN binary itself never needs
 *   installation — we spawn it as a child process with the app's already-
 *   elevated privileges (NSIS manifest is `requireAdministrator`).
 *
 *   The TAP-Windows V9 KERNEL DRIVER is the only piece that has to be
 *   installed on the host so Windows accepts the openvpn.exe call to open
 *   the virtual adapter. We detect its presence via `Get-NetAdapter`
 *   filtered by `InterfaceDescription -match "TAP-Windows Adapter V9"`,
 *   and install via the bundled `tapctl.exe create` command when missing.
 *
 *   The install fires a UAC prompt. We pre-warn the user via the renderer
 *   (Liquid Glass modal: pastel pill button + glassmorphism surface) so
 *   the OS prompt isn't a surprise. Once the driver is installed it's
 *   persistent — subsequent app launches detect it and skip the prompt.
 *
 * The module exports:
 *   detectOpenVpnRuntime()       — checks for openvpn.exe + TAP driver
 *   ensureTapDriverInstalled()   — install TAP driver with elevation
 *   ensureOpenVpnRuntime()       — top-level helper used at app start
 */

import { execFile } from "child_process";
import { promisify } from "util";
import fs from "fs/promises";
import path from "path";
import { app } from "electron";
import {
  isBinaryAvailable,
  openvpnPath,
  tapctlPath,
  tapWindowsInfPath,
  openvpnBundledDir,
} from "./binary-helper";

const execFileAsync = promisify(execFile);

// Marker file dropped under `<userData>/.tap-installed` after a successful
// driver install. Lets us skip the (slow) `Get-NetAdapter` probe on
// subsequent boots — we still re-verify on first connect of each session.
const TAP_INSTALL_MARKER = ".tap-installed";

export interface OpenVpnRuntimeStatus {
  /** Bundled (or system) openvpn binary is reachable. */
  openvpnAvailable: boolean;
  /** Path that resolved on the lookup chain, or null when nothing was found. */
  openvpnPath: string | null;
  /** TAP-Windows V9 driver is detected via Windows adapter enumeration.
   *  Always true on non-Windows platforms (Unix uses tun/tap kernel). */
  tapDriverInstalled: boolean;
  /** Set when a NetAdapter probe failed (PowerShell unavailable, exotic
   *  Win box, etc.) — distinguishes "definitely missing" from "couldn't
   *  determine". The caller may treat unknown as "needs install" with
   *  a hint that the OS may surface a "driver already installed" path. */
  tapDriverProbeError: string | null;
}

/**
 * Best-effort probe for the TAP-Windows V9 driver.
 *
 * `Get-NetAdapter -IncludeHidden` enumerates every adapter the kernel knows
 * about, including hidden ones that openvpn doesn't bind yet. Filtering
 * on InterfaceDescription rather than Name is robust to user-renamed
 * adapters ("rud1-tap" vs "Local Area Connection 5", etc.) — the
 * InterfaceDescription is set by the driver itself.
 */
async function probeTapDriverWindows(): Promise<{
  installed: boolean;
  error: string | null;
}> {
  if (process.platform !== "win32") return { installed: true, error: null };
  try {
    const { stdout } = await execFileAsync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        // -ErrorAction SilentlyContinue keeps an empty pipeline from
        // exiting non-zero when there are no matches; we rely on the
        // stdout text being empty in that case.
        "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | " +
          "Where-Object { $_.InterfaceDescription -match 'TAP-Windows Adapter V9' } | " +
          "Select-Object -First 1 | ConvertTo-Json -Compress",
      ],
      { timeout: 10_000, windowsHide: true, maxBuffer: 512 * 1024 },
    );
    const trimmed = (stdout || "").trim();
    return { installed: trimmed.length > 0, error: null };
  } catch (err) {
    return {
      installed: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Read the install marker so a subsequent app launch can short-circuit
 * the (slow) NetAdapter probe. Returns false on missing / unreadable
 * marker so the next call re-probes.
 */
async function readTapMarker(): Promise<boolean> {
  try {
    const marker = path.join(app.getPath("userData"), TAP_INSTALL_MARKER);
    await fs.access(marker);
    return true;
  } catch {
    return false;
  }
}

async function writeTapMarker(): Promise<void> {
  try {
    const marker = path.join(app.getPath("userData"), TAP_INSTALL_MARKER);
    await fs.mkdir(path.dirname(marker), { recursive: true });
    await fs.writeFile(
      marker,
      JSON.stringify({ installedAt: new Date().toISOString() }),
      { encoding: "utf8" },
    );
  } catch {
    /* best-effort — a missing marker just means we re-probe on the next call */
  }
}

/**
 * Run the bundled `tapctl.exe create` to install + create a fresh
 * TAP-Windows V9 adapter named "rud1-tap". Triggers UAC.
 *
 * tapctl is the modern (OpenVPN >= 2.5) tool replacing the old
 * `tapinstall.exe` / `devcon` flow. It speaks directly to the Windows
 * SetupAPI and registers the driver from its embedded resources, then
 * creates a virtual adapter and prints its GUID. Two-step:
 *
 *   1. (one-time) `tapctl create --hwid root\tap0901 --name rud1-tap`
 *      installs the driver from the bundled .inf + .cat + .sys files
 *      if it isn't already installed, and creates a fresh adapter.
 *   2. subsequent calls (`tapctl list`) just enumerate; the driver
 *      persists.
 *
 * UAC handling: we call PowerShell's `Start-Process -Verb RunAs` so
 * the OS surfaces the elevation dialog. tapctl returns non-zero on
 * failure; we read the elevated process's exit code via `-Wait`.
 */
export async function ensureTapDriverInstalled(): Promise<void> {
  if (process.platform !== "win32") return;
  const tapctl = tapctlPath();
  if (!tapctl) {
    throw new Error(
      "Bundled tapctl.exe is missing — re-run the rud1 installer or " +
        "`npm run fetch:openvpn-win` to repopulate resources/win32/openvpn/.",
    );
  }
  const inf = tapWindowsInfPath();
  // PowerShell's Start-Process with -Verb RunAs is the only way to
  // trigger UAC for a non-admin parent. We're already
  // `requireAdministrator` per the NSIS manifest, so this is belt-and-
  // braces: even if a future build relaxes that flag, the driver
  // install still elevates correctly.
  //
  // Two `tapctl` invocations:
  //   1. `tapctl create --hwid root\tap0901 --name rud1-tap`
  //      — installs the driver from the bundled package (if missing) AND
  //        creates the adapter in one call. Idempotent at the driver
  //        level (returns success if the driver is already present), but
  //        will create a duplicate adapter if "rud1-tap" already exists.
  //   2. Pre-check: if "rud1-tap" exists, skip the create.
  //
  // We collapse the two by trying `list` first; if a row named
  // "rud1-tap" exists we're done.
  //
  // Spawning PowerShell via execFile keeps argv safely structured — the
  // tapctl path is interpolated into a PS single-quoted literal which
  // doesn't allow command injection from the string contents.
  const argList = [
    "create",
    "--hwid", "root\\tap0901",
    "--name", "rud1-tap",
  ];
  // Build the embedded PS command. We single-quote the executable path
  // for safety (it lives under Program Files\rud1\resources\bin\openvpn\)
  // and use `-ArgumentList @('a','b','c')` which PowerShell passes
  // verbatim to the child without re-quoting on the cmd.exe layer.
  const psArgList = argList
    .map((arg) => `'${arg.replace(/'/g, "''")}'`)
    .join(",");
  const psCmd = [
    `$ErrorActionPreference = 'Stop';`,
    // Test for an existing rud1-tap adapter via Get-NetAdapter; if
    // present, return 0 without prompting.
    `try {`,
    `  $existing = Get-NetAdapter -Name 'rud1-tap' -ErrorAction SilentlyContinue;`,
    `  if ($existing) { exit 0 }`,
    `} catch { }`,
    `$proc = Start-Process -FilePath '${tapctl.replace(/'/g, "''")}' ` +
      `-ArgumentList ${psArgList} -Verb RunAs -Wait -PassThru ` +
      `-WindowStyle Hidden;`,
    `if (-not $proc) { exit 2 }`,
    `exit $proc.ExitCode`,
  ].join(" ");
  try {
    await execFileAsync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", psCmd],
      { timeout: 60_000, windowsHide: true },
    );
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ETIMEDOUT") {
      throw new Error(
        "Timed out waiting for the TAP driver install to finish. The " +
          "UAC prompt may still be open — accept it and retry Connect.",
      );
    }
    // execFile with a non-zero exit code throws; the message includes
    // the stderr we want to surface verbatim (truncated).
    const msg = err instanceof Error ? err.message : String(err);
    if (/canceled|cancelled|denied/i.test(msg)) {
      throw new Error(
        "The OS elevation prompt was dismissed. The TAP-Windows V9 " +
          "driver is required for the VPN — click Connect again to retry.",
      );
    }
    throw new Error(
      `TAP driver install via tapctl failed (${msg}). ` +
        (inf
          ? `Manual fallback: right-click '${inf}' and choose Install.`
          : "Re-run the rud1 installer to repopulate the bundled driver."),
    );
  }
  await writeTapMarker();
}

/**
 * One-shot probe of the runtime state — the renderer's iter-71 modal
 * uses this on app start to decide whether to surface the "install
 * driver" CTA before the user even tries Connect.
 */
export async function detectOpenVpnRuntime(): Promise<OpenVpnRuntimeStatus> {
  const ovpnAvail = isBinaryAvailable("openvpn");
  const ovpnP = ovpnAvail ? openvpnPath() : null;

  if (process.platform !== "win32") {
    return {
      openvpnAvailable: ovpnAvail,
      openvpnPath: ovpnP,
      tapDriverInstalled: true,
      tapDriverProbeError: null,
    };
  }

  // Marker fast-path so a healthy install doesn't pay the PowerShell
  // round-trip on every boot.
  if (await readTapMarker()) {
    return {
      openvpnAvailable: ovpnAvail,
      openvpnPath: ovpnP,
      tapDriverInstalled: true,
      tapDriverProbeError: null,
    };
  }

  const probe = await probeTapDriverWindows();
  // Sync the marker if the adapter is genuinely present (e.g. a user
  // who installed OpenVPN manually before rud1-desktop ran).
  if (probe.installed) {
    await writeTapMarker();
  }

  return {
    openvpnAvailable: ovpnAvail,
    openvpnPath: ovpnP,
    tapDriverInstalled: probe.installed,
    tapDriverProbeError: probe.error,
  };
}

/**
 * Bundled-binaries dir (Windows). The IPC handler exposes this so the
 * renderer can render a "files we'll install" detail row in the
 * Liquid Glass driver-install modal.
 */
export function openvpnRuntimeDir(): string | null {
  if (process.platform !== "win32") return null;
  return openvpnBundledDir();
}
