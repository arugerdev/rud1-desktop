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
  tapWindowsInstallerPath,
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
  /** The actual `rud1-tap` virtual adapter is present (driver installed AND
   *  an instance named rud1-tap exists in Get-NetAdapter). A user can
   *  uninstall the adapter from Device Manager while leaving the driver
   *  installed — this flag distinguishes that case from "driver missing"
   *  so the connect flow can re-create the adapter without re-installing
   *  the driver. Always true on non-Windows platforms. */
  rud1TapAdapterPresent: boolean;
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
  // Two-stage probe: live adapter first (cheap), then the Windows driver
  // store. The store probe catches the "driver installed but no adapter
  // instance" case — a user who deleted the rud1-tap from Device Manager
  // leaves the driver registered; we don't want to re-run the bundled
  // installer in that case (it tends to error with the opaque "An error
  // occurred installing the TAP device driver" dialog when the driver is
  // already in the store), we just need `tapctl create`.
  try {
    const { stdout } = await execFileAsync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | " +
          "Where-Object { $_.InterfaceDescription -match 'TAP-Windows Adapter V9' } | " +
          "Select-Object -First 1 | ConvertTo-Json -Compress",
      ],
      { timeout: 10_000, windowsHide: true, maxBuffer: 512 * 1024 },
    );
    if ((stdout || "").trim().length > 0) {
      return { installed: true, error: null };
    }
  } catch {
    /* fall through to the driver-store probe */
  }
  return probeTapDriverInDriverStore();
}

/**
 * Look up the TAP-Windows V9 driver in the Windows third-party driver
 * store via `pnputil /enum-drivers`. Match by published name suffix
 * (`tap0901.inf`) AND by signer subject ("OpenVPN Technologies, Inc."
 * or "OpenVPN Inc.") so a locale-translated pnputil header (Spanish:
 * "Nombre del proveedor") doesn't false-negative.
 *
 * Returns `installed: true` when the driver is registered in the store
 * even if no adapter instance exists right now — that's the failure
 * mode we want to detect (driver present, adapter deleted manually).
 */
async function probeTapDriverInDriverStore(): Promise<{
  installed: boolean;
  error: string | null;
}> {
  try {
    const { stdout } = await execFileAsync(
      "pnputil.exe",
      ["/enum-drivers"],
      { timeout: 15_000, windowsHide: true, maxBuffer: 8 * 1024 * 1024 },
    );
    const installed =
      /tap0901\.inf/i.test(stdout) ||
      /OpenVPN\s+Technologies,?\s*Inc/i.test(stdout);
    return { installed, error: null };
  } catch (err) {
    return {
      installed: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Verify that the actual `rud1-tap` adapter exists on the host. This is
 * a strictly stronger check than {@link probeTapDriverWindows}: the
 * driver can be installed while no rud1-tap instance exists (user
 * uninstalled it manually from Device Manager, or another OpenVPN client
 * removed it via `tapctl delete`).
 *
 * We match on the adapter alias (`-Name 'rud1-tap'`) AND require the
 * InterfaceDescription to indicate it's still a TAP-Windows V9 instance
 * — this protects against a stale empty NetAdapter entry from a half-
 * uninstalled adapter. `-IncludeHidden` enumerates disconnected /
 * disabled adapters too, so a user-disabled adapter still counts as
 * present (we can re-enable it later if needed).
 *
 * Note: rud1-desktop renames the description to plain "rud1" so it
 * surfaces nicely in TIA Portal / Codesys dropdowns — we accept either
 * the original "TAP-Windows Adapter V9" string OR the renamed "rud1"
 * description in the regex.
 */
async function probeRud1TapAdapter(): Promise<{
  present: boolean;
  error: string | null;
}> {
  if (process.platform !== "win32") return { present: true, error: null };
  try {
    const { stdout } = await execFileAsync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "$a = Get-NetAdapter -Name 'rud1-tap' -IncludeHidden -ErrorAction SilentlyContinue; " +
          "if ($a -and ($a.InterfaceDescription -match 'TAP-Windows Adapter V9' " +
          "  -or $a.InterfaceDescription -match '^rud1')) { " +
          "  $a | Select-Object -First 1 | ConvertTo-Json -Compress " +
          "}",
      ],
      { timeout: 10_000, windowsHide: true, maxBuffer: 512 * 1024 },
    );
    const trimmed = (stdout || "").trim();
    return { present: trimmed.length > 0, error: null };
  } catch (err) {
    return {
      present: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

// True when a rud1-tap with this NetAdapter Status needs re-enabling before
// openvpn can open it. 'Up'/'Disconnected' are usable; ''/null means the
// adapter is absent (the create path's job); anything else ('Disabled',
// 'Not Present') still enumerates under -IncludeHidden but openvpn can't open
// it (CreateFile errno=2), so it has to be re-enabled.
export function tapAdapterNeedsEnable(status: string | null | undefined): boolean {
  if (typeof status !== "string") return false;
  const s = status.trim().toLowerCase();
  if (s === "") return false;
  return s !== "up" && s !== "disconnected";
}

// Cheap, non-elevated read of the rud1-tap NetAdapter Status. null = absent.
async function probeRud1TapStatus(): Promise<{
  status: string | null;
  error: string | null;
}> {
  if (process.platform !== "win32") return { status: null, error: null };
  try {
    const { stdout } = await execFileAsync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "$a = Get-NetAdapter -Name 'rud1-tap' -IncludeHidden -ErrorAction SilentlyContinue; " +
          "if ($a) { ($a | Select-Object -First 1).Status }",
      ],
      { timeout: 10_000, windowsHide: true, maxBuffer: 256 * 1024 },
    );
    const status = (stdout || "").trim();
    return { status: status.length > 0 ? status : null, error: null };
  } catch (err) {
    return { status: null, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Re-enable rud1-tap when Windows has it administratively disabled. A
 * disabled adapter still enumerates as "present" (so detectOpenVpnRuntime
 * passes) but openvpn can't open it — CreateFile fails errno=2 right after
 * the TLS handshake. This is the missing "re-enable it later" half of
 * probeRud1TapAdapter's contract. Cheap no-op when already up; throws with
 * a Device Manager hint when the enable can't be made to stick.
 */
export async function ensureRud1TapEnabled(): Promise<void> {
  if (process.platform !== "win32") return;
  const { status } = await probeRud1TapStatus();
  if (!tapAdapterNeedsEnable(status)) return;

  // Enable via the NetAdapter cmdlet, falling back to the PnP layer
  // (PnpDeviceID is the ROOT\NET\NNNN instance id, straight off the adapter).
  // Verify with a short retry loop — the PnP enable is async. Runs in the
  // app's already-elevated context (requireAdministrator manifest).
  const psCmd = [
    "$ErrorActionPreference = 'Stop';",
    "$a = Get-NetAdapter -Name 'rud1-tap' -IncludeHidden -ErrorAction SilentlyContinue;",
    "if (-not $a) { exit 0 }",
    "try { $a | Enable-NetAdapter -Confirm:$false -ErrorAction Stop } catch {",
    "  if ($a.PnpDeviceID) { Enable-PnpDevice -InstanceId $a.PnpDeviceID -Confirm:$false -ErrorAction Stop }",
    "}",
    "for ($i = 0; $i -lt 25; $i++) {",
    "  Start-Sleep -Milliseconds 200;",
    "  $a = Get-NetAdapter -Name 'rud1-tap' -IncludeHidden -ErrorAction SilentlyContinue;",
    "  if ($a -and ($a.Status -eq 'Up' -or $a.Status -eq 'Disconnected')) { exit 0 }",
    "}",
    "exit 5",
  ].join(" ");
  try {
    await execFileAsync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", psCmd],
      { timeout: 30_000, windowsHide: true },
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(
      `Could not re-enable the rud1-tap adapter (${msg}). Open Device ` +
        "Manager → Network adapters, right-click rud1-tap → Enable, then retry Connect.",
    );
  }
}

/**
 * Read the install marker so a subsequent app launch can short-circuit
 * the (slow) NetAdapter driver probe. Returns false on missing /
 * unreadable marker so the next call re-probes. The marker only signals
 * "the kernel driver has been installed at least once" — it intentionally
 * does NOT imply the rud1-tap adapter is still present, since users can
 * delete the adapter from Device Manager. Adapter presence is always
 * verified via {@link probeRud1TapAdapter}.
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
/**
 * Injected operations for {@link createTapAdapterWithFallback} — keeps the
 * decision logic unit-testable without an Electron/Windows host (mirrors
 * the `tapAdapterNeedsEnable` split: pure logic here, shell-out in callers).
 */
export interface TapCreateFallbackOps {
  /** True when we SKIPPED our bundled installer because the driver-store
   *  probe reported the driver present — so a create failure may be a
   *  false positive worth forcing the installer for. False once the
   *  installer has already run this pass (a create failure is then real). */
  allowInstallerFallback: boolean;
  /** Force-run the bundled tap-windows-installer.exe /S (elevated) and
   *  clear the stray adapter it creates. */
  forceInstallDriver: () => Promise<void>;
  /** `tapctl create --hwid root\tap0901 --name rud1-tap` (no-op if the
   *  adapter already exists). Throws on failure. */
  createAdapter: () => Promise<void>;
}

/**
 * Create the rud1-tap adapter, recovering from a false-positive driver
 * probe. A coexisting OpenVPN client — notably Ewon eCatcher — signs its
 * own TAP driver as "OpenVPN Technologies, Inc.", which satisfies
 * probeTapDriverInDriverStore() even though the root\tap0901 ComponentId
 * `tapctl create` needs isn't registered (eCatcher may ship tap0801 / a
 * Talk2m NDIS5 INF). When that makes us skip our installer and the create
 * then fails, force the bundled installer in and retry the create once.
 */
export async function createTapAdapterWithFallback(
  ops: TapCreateFallbackOps,
): Promise<{ forcedInstaller: boolean }> {
  try {
    await ops.createAdapter();
    return { forcedInstaller: false };
  } catch (createErr) {
    // Installer already ran this pass → the failure is real, surface it.
    if (!ops.allowInstallerFallback) throw createErr;
    await ops.forceInstallDriver();
    await ops.createAdapter(); // single retry; let this error be the final one
    return { forcedInstaller: true };
  }
}

export async function ensureTapDriverInstalled(): Promise<void> {
  if (process.platform !== "win32") return;
  const tapctl = tapctlPath();
  if (!tapctl) {
    throw new Error(
      "Bundled tapctl.exe is missing — re-run the rud1 installer or " +
        "`npm run fetch:openvpn-win` to repopulate resources/win32/openvpn/.",
    );
  }

  // Step 1: ensure the TAP-Windows V9 kernel driver is in the Windows
  // driver store. We skip the bundled NSIS installer when the driver is
  // already registered — running it against an already-installed driver
  // tends to bail with the opaque "An error occurred installing the TAP
  // device driver" dialog (the installer's silent path treats an existing
  // .inf in the store as a fatal collision). When the driver is present
  // but no rud1-tap adapter exists (user deleted it from Device Manager),
  // `tapctl create` alone is enough to recover.
  //
  // OpenVPN 2.6.x dropped the bundled TAP driver from its MSI's
  // administrative install, so the .inf/.cat/.sys live exclusively inside
  // the standalone tap-windows-9.21.2.exe NSIS installer (signed by
  // OpenVPN Technologies, Inc.). When we DO need it, we run it silently
  // with `/S` and elevation.
  //
  // forceInstallDriver runs that installer, forgiving its spurious non-zero
  // exit when the driver actually landed in the store.
  const forceInstallDriver = async (): Promise<void> => {
    const tapInstaller = tapWindowsInstallerPath();
    if (!tapInstaller) {
      throw new Error(
        "Bundled tap-windows-installer.exe is missing — run " +
          "`npm run fetch:openvpn-win` to repopulate " +
          "resources/win32/openvpn/driver/.",
      );
    }
    try {
      await runElevatedSilentInstaller(tapInstaller);
    } catch (err) {
      // The NSIS installer occasionally surfaces "An error occurred
      // installing the TAP device driver" even when the driver IS in the
      // store on exit — typically when a partial prior install left
      // residue. Re-probe; if the driver is now registered we forge ahead
      // to `tapctl create` instead of bailing on the operator.
      const postProbe = await probeTapDriverInDriverStore();
      if (!postProbe.installed) throw err;
      console.warn(
        "openvpn-installer: installer threw but driver is in the store — continuing to tapctl create:",
        err instanceof Error ? err.message : err,
      );
    }
  };

  const driverProbe = await probeTapDriverInDriverStore();
  if (!driverProbe.installed) {
    await forceInstallDriver();
  }
  // The NSIS installer auto-creates one default TAP adapter named
  // something like "Ethernet N" (description "TAP-Windows Adapter V9").
  // We don't want that — we want exactly one named "rud1-tap". Clean up
  // any TAP adapters that aren't ours BEFORE creating the rud1-tap one.
  // Safe to call even when we skipped the installer (no-op if there are
  // no strays). Matches `^TAP-Windows Adapter V9`, so a coexisting eCatcher
  // tap0801 ("TAP-Win32 Adapter V9") is left untouched.
  await cleanupStrayTapAdapters();

  // Step 2: create rud1-tap. When the driver-store probe was a false
  // positive (eCatcher's "OpenVPN Technologies, Inc." signature satisfied
  // it but root\tap0901 isn't really registered), the create fails — force
  // our bundled installer in and retry once. allowInstallerFallback is
  // true only when we SKIPPED the installer above, so we never loop.
  await createTapAdapterWithFallback({
    allowInstallerFallback: driverProbe.installed,
    forceInstallDriver: async () => {
      await forceInstallDriver();
      await cleanupStrayTapAdapters();
    },
    createAdapter: () => runTapctlCreateRud1(tapctl),
  });

  // Rename the adapter's description so TIA Portal, Codesys, and other
  // engineering tools list it as "rud1" in their PG/PC interface
  // dropdowns instead of the generic "TAP-Windows Adapter V9". The
  // adapter alias (Get-NetAdapter -Name) is already "rud1-tap" — this
  // tweak only touches the InterfaceDescription / DriverDesc that
  // Siemens & friends enumerate against.
  await renameRud1TapAdapterDescription("rud1");

  await writeTapMarker();
}

/**
 * Run `tapctl create --hwid root\tap0901 --name rud1-tap` elevated (UAC),
 * skipping the create when the adapter already exists so re-runs are
 * idempotent. Throws a user-facing Error mapping the failure modes
 * (timeout / dismissed UAC / generic tapctl error).
 *
 * PowerShell's Start-Process with -Verb RunAs is the only way to trigger
 * UAC for a non-admin parent. We're already `requireAdministrator` per the
 * NSIS manifest, so this is belt-and-braces. Spawning PowerShell via
 * execFile keeps argv structured — the tapctl path is interpolated into a
 * single-quoted PS literal which can't inject from the string contents.
 */
async function runTapctlCreateRud1(tapctl: string): Promise<void> {
  const argList = ["create", "--hwid", "root\\tap0901", "--name", "rud1-tap"];
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
        "Open Device Manager → Network adapters and verify the " +
        "TAP-Windows V9 driver is listed; if not, re-run the rud1 installer.",
    );
  }
}

/**
 * Delete every TAP-Windows V9 adapter on the host EXCEPT the one named
 * "rud1-tap". This runs right after the tap-windows NSIS installer (which
 * unconditionally creates a default adapter, "Ethernet N") and on every
 * driver-install retry so leftovers from earlier rud1-desktop test
 * builds don't accumulate. Safe to call when no TAP adapters exist
 * (no-op). Requires admin — the rud1-desktop NSIS manifest is already
 * `requireAdministrator`.
 */
async function cleanupStrayTapAdapters(): Promise<void> {
  if (process.platform !== "win32") return;
  // List adapters matching the TAP-Windows V9 description that aren't
  // named rud1-tap, then delete each via `tapctl delete <name>`. The
  // adapter NAME (alias) is what tapctl uses — not the InterfaceGuid.
  const tapctl = tapctlPath();
  if (!tapctl) return;
  const psCmd = [
    "$ErrorActionPreference = 'SilentlyContinue';",
    "$strays = Get-NetAdapter -IncludeHidden | " +
      "Where-Object { $_.InterfaceDescription -match '^TAP-Windows Adapter V9' " +
      "  -and $_.Name -ne 'rud1-tap' };",
    "foreach ($a in $strays) {",
    `  & '${tapctl.replace(/'/g, "''")}' delete $a.Name | Out-Null`,
    "}",
    "exit 0",
  ].join(" ");
  try {
    await execFileAsync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", psCmd],
      { timeout: 30_000, windowsHide: true },
    );
  } catch (err) {
    // Best-effort. A stray adapter is cosmetic, not blocking — log and
    // continue so the rest of the install proceeds.
    console.warn(
      "openvpn-installer: cleanup of stray TAP adapters failed (non-fatal):",
      err instanceof Error ? err.message : err,
    );
  }
}

/**
 * Re-skin the rud1-tap adapter so engineering tools (TIA Portal,
 * Codesys, SINEC PNI, Step 7, "Set PG/PC Interface") list it as just
 * "rud1" — no "TAP-Windows Adapter V9 #N" anywhere visible.
 *
 * Multiple Windows registries cache the user-visible strings; flipping
 * just one of them leaves a stale label somewhere. We overwrite ALL of
 * them inside the device-class subkey, plus the NetworkCards entry
 * NDIS reads at enumeration time, then disable+enable the adapter so
 * PnP republishes the values to listeners (TIA Portal still requires
 * its own restart, but the dropdown reflects the change immediately
 * everywhere else).
 *
 * Registry locations rewritten:
 *   HKLM\SYSTEM\CurrentControlSet\Control\Class\
 *     {4D36E972-E325-11CE-BFC1-08002BE10318}\<NNNN>
 *       DriverDesc                  → "rud1"
 *       FriendlyName                → "rud1"
 *       ProviderName                → "rud1"
 *       *ifDescription              → "rud1"            (when present)
 *   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\
 *     NetworkCards\<N>
 *       Description                 → "rud1"
 *
 * Retries Get-NetAdapter for up to 5 s because tapctl-create returns
 * before NDIS finishes registering the new device. Without the retry
 * loop the rename silently no-ops on a fresh adapter.
 *
 * Non-fatal on failure: the VPN still works with the stock name, the
 * dropdown just stays ugly. Logged and ignored.
 */
async function renameRud1TapAdapterDescription(newDesc: string): Promise<void> {
  if (process.platform !== "win32") return;
  const safe = newDesc.replace(/'/g, "''");
  const psCmd = [
    "$ErrorActionPreference = 'Stop';",
    // Retry up to ~5s for Windows to finish registering the freshly-
    // created adapter. Without this, Get-NetAdapter returns null and
    // the whole rewrite is skipped on a clean install.
    "$adapter = $null;",
    "for ($i = 0; $i -lt 25; $i++) {",
    "  try {",
    "    $adapter = Get-NetAdapter -Name 'rud1-tap' -IncludeHidden -ErrorAction Stop;",
    "    if ($adapter) { break }",
    "  } catch { }",
    "  Start-Sleep -Milliseconds 200;",
    "}",
    "if (-not $adapter) { exit 3 }",
    // Fast-path: ask NDIS what it's reporting as InterfaceDescription.
    // That's the canonical "is rename done" check — checking only
    // DriverDesc was a bug (it could be 'rud1' while NDIS still
    // reported 'TAP-Windows Adapter V9' because the real source is
    // the PnP Enum DeviceDesc, not the Class DriverDesc).
    `if ($adapter.InterfaceDescription -eq '${safe}') { exit 0 }`,
    "$guid = $adapter.InterfaceGuid;",
    "$classRoot = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}';",
    "$match = Get-ChildItem $classRoot -ErrorAction SilentlyContinue | Where-Object {",
    "  try { (Get-ItemProperty $_.PsPath -Name NetCfgInstanceId -ErrorAction Stop).NetCfgInstanceId -eq $guid } catch { $false }",
    "} | Select-Object -First 1;",
    "if (-not $match) { exit 4 }",
    // --- Class subkey (driver layer / "Controlador" tab in Device Manager) ---
    `Set-ItemProperty -Path $match.PsPath -Name 'DriverDesc'   -Value '${safe}' -Force;`,
    `Set-ItemProperty -Path $match.PsPath -Name 'FriendlyName' -Value '${safe}' -Force;`,
    `Set-ItemProperty -Path $match.PsPath -Name 'ProviderName' -Value '${safe}' -Force;`,
    "if (Get-ItemProperty -Path $match.PsPath -Name '*IfDescription' -ErrorAction SilentlyContinue) {",
    `  Set-ItemProperty -Path $match.PsPath -Name '*IfDescription' -Value '${safe}' -Force`,
    "}",
    // --- PnP Enum subkey (device layer — what NDIS reads to set IfDescr) ---
    // Load-bearing for InterfaceDescription. Admins have write access
    // to TAP-Windows V9 ROOT\NET\* entries by default; no take-
    // ownership needed (confirmed on Spanish Win 10 19045).
    `$driverRef = '{4D36E972-E325-11CE-BFC1-08002BE10318}\\' + $match.PSChildName;`,
    "$enum = Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\ROOT\\NET' -ErrorAction SilentlyContinue | Where-Object {",
    "  try { (Get-ItemProperty $_.PsPath -Name Driver -ErrorAction Stop).Driver -eq $driverRef } catch { $false }",
    "} | Select-Object -First 1;",
    "if ($enum) {",
    "  try {",
    `    Set-ItemProperty -Path $enum.PsPath -Name 'DeviceDesc'   -Value '${safe}' -Force`,
    `    Set-ItemProperty -Path $enum.PsPath -Name 'FriendlyName' -Value '${safe}' -Force`,
    `    Set-ItemProperty -Path $enum.PsPath -Name 'Mfg'          -Value '${safe}' -Force`,
    "  } catch { }",
    "}",
    // --- NetworkCards legacy table ---
    "$ncRoot = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards';",
    "$ncMatch = Get-ChildItem $ncRoot -ErrorAction SilentlyContinue | Where-Object {",
    "  try { (Get-ItemProperty $_.PsPath -Name ServiceName -ErrorAction Stop).ServiceName -eq $guid } catch { $false }",
    "} | Select-Object -First 1;",
    "if ($ncMatch) {",
    `  Set-ItemProperty -Path $ncMatch.PsPath -Name 'Description' -Value '${safe}' -Force`,
    "}",
    // Disable+Enable so PnP re-publishes DeviceDesc → NDIS IfDescr.
    "try { Disable-NetAdapter -Name 'rud1-tap' -Confirm:$false -ErrorAction Stop } catch { }",
    "Start-Sleep -Milliseconds 1200;",
    // Re-enable with retries + verify: the early-exit above means later
    // connects won't revisit this, so a swallowed Enable failure here would
    // strand the adapter disabled (openvpn then dies with errno=2).
    "$enabled = $false;",
    "for ($j = 0; $j -lt 10; $j++) {",
    "  try { Enable-NetAdapter -Name 'rud1-tap' -Confirm:$false -ErrorAction Stop } catch { }",
    "  Start-Sleep -Milliseconds 300;",
    "  $chk = Get-NetAdapter -Name 'rud1-tap' -IncludeHidden -ErrorAction SilentlyContinue;",
    "  if ($chk -and ($chk.Status -eq 'Up' -or $chk.Status -eq 'Disconnected')) { $enabled = $true; break }",
    "}",
    "if (-not $enabled) {",
    "  $chk = Get-NetAdapter -Name 'rud1-tap' -IncludeHidden -ErrorAction SilentlyContinue;",
    "  if ($chk -and $chk.PnpDeviceID) { try { Enable-PnpDevice -InstanceId $chk.PnpDeviceID -Confirm:$false -ErrorAction Stop } catch { } }",
    "}",
    "exit 0",
  ].join(" ");
  try {
    const { stdout, stderr } = await execFileAsync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", psCmd],
      { timeout: 20_000, windowsHide: true },
    );
    if (stdout?.trim() || stderr?.trim()) {
      console.log(
        "openvpn-installer: rename ran",
        stdout?.trim() ? "stdout=" + stdout.trim() : "",
        stderr?.trim() ? "stderr=" + stderr.trim() : "",
      );
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const code = (err as { code?: number | string }).code;
    console.warn(
      "openvpn-installer: rename of rud1-tap description failed (non-fatal):",
      "exit=" + String(code ?? "?"),
      msg,
    );
  }
}

/**
 * Public re-skin entry-point. Used by an IPC handler so the renderer
 * can offer the user a "rename adapter" button when the description
 * still shows the upstream default — e.g. on adapters created by an
 * old rud1-desktop build that pre-dates the auto-rename, or after a
 * manual driver reinstall via Device Manager.
 */
export async function renameTapAdapterToRud1(): Promise<void> {
  await renameRud1TapAdapterDescription("rud1");
}

/**
 * Run an NSIS installer (`installer.exe /S`) elevated via UAC. The
 * tap-windows-installer.exe published by openvpn.org accepts the
 * standard NSIS `/S` flag for silent mode. We escalate via PowerShell
 * `Start-Process -Verb RunAs` so the OS surfaces the UAC dialog and
 * we get a real exit code back from the child via `-Wait -PassThru`.
 *
 * Idempotent: if the driver is already installed at the same version,
 * the installer exits 0 quickly without prompting (its INF check sees
 * an existing match in the driver store).
 */
async function runElevatedSilentInstaller(installerPath: string): Promise<void> {
  const psCmd = [
    "$ErrorActionPreference = 'Stop';",
    `$proc = Start-Process -FilePath '${installerPath.replace(/'/g, "''")}' ` +
      `-ArgumentList @('/S') -Verb RunAs -Wait -PassThru -WindowStyle Hidden;`,
    "if (-not $proc) { exit 2 }",
    "exit $proc.ExitCode",
  ].join(" ");
  try {
    await execFileAsync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", psCmd],
      { timeout: 120_000, windowsHide: true },
    );
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ETIMEDOUT") {
      throw new Error(
        "Timed out waiting for the TAP-Windows driver installer. The " +
          "UAC prompt may still be open — accept it and retry Connect.",
      );
    }
    const msg = err instanceof Error ? err.message : String(err);
    if (/canceled|cancelled|denied/i.test(msg)) {
      throw new Error(
        "The OS elevation prompt was dismissed. The TAP-Windows V9 " +
          "driver is required for the VPN — click Connect again to retry.",
      );
    }
    throw new Error(`TAP-Windows driver installer failed: ${msg}`);
  }
}

/**
 * One-shot probe of the runtime state — the renderer surfaces this on
 * app start (to decide whether to show the "install driver" CTA before
 * the user even tries Connect) and the connect flow uses it as the
 * gating precondition.
 *
 * Two-layer probe so we can distinguish "kernel driver missing entirely"
 * from "driver installed, adapter deleted":
 *   1. Probe for the `rud1-tap` adapter (fast, ~50ms via
 *      `Get-NetAdapter -Name rud1-tap`). If present, both flags are true.
 *   2. If the adapter is missing, fall back to the broader TAP-Windows
 *      V9 driver probe to differentiate the two failure modes for the
 *      caller.
 *
 * The install marker is NOT consulted as a fast-path for adapter
 * presence — it only signals that the driver was installed at some
 * point. Adapter presence is re-verified on every call so a user who
 * deletes the adapter from Device Manager is detected immediately.
 */
export async function detectOpenVpnRuntime(): Promise<OpenVpnRuntimeStatus> {
  const ovpnAvail = isBinaryAvailable("openvpn");
  const ovpnP = ovpnAvail ? openvpnPath() : null;

  if (process.platform !== "win32") {
    return {
      openvpnAvailable: ovpnAvail,
      openvpnPath: ovpnP,
      tapDriverInstalled: true,
      rud1TapAdapterPresent: true,
      tapDriverProbeError: null,
    };
  }

  const adapterProbe = await probeRud1TapAdapter();
  if (adapterProbe.present) {
    // Adapter present implies the driver is loaded — the adapter
    // wouldn't enumerate otherwise. Sync the marker as a side-effect so
    // a fresh install that landed via the standalone tap-windows MSI
    // still benefits from the fast-path on subsequent boots.
    await writeTapMarker();
    return {
      openvpnAvailable: ovpnAvail,
      openvpnPath: ovpnP,
      tapDriverInstalled: true,
      rud1TapAdapterPresent: true,
      tapDriverProbeError: null,
    };
  }

  // Adapter missing — probe the driver layer so the caller knows
  // whether they need a full install (UAC + driver) or just the cheaper
  // `tapctl create` step (driver already in store).
  const driverProbe = await probeTapDriverWindows();
  return {
    openvpnAvailable: ovpnAvail,
    openvpnPath: ovpnP,
    tapDriverInstalled: driverProbe.installed,
    rud1TapAdapterPresent: false,
    tapDriverProbeError: adapterProbe.error ?? driverProbe.error,
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
