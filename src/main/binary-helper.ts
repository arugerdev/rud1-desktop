/**
 * Resolves paths to bundled native binaries.
 *
 * Lookup order:
 *   1. Bundled binary (resources/<platform>/<name> in dev,
 *      process.resourcesPath/bin/<name> in production via extraResources).
 *   2. Platform-known system install paths — e.g. on Windows the official
 *      OpenVPN installer drops `openvpn.exe` into
 *      `%ProgramFiles%\OpenVPN\bin\` but does NOT add that directory to
 *      PATH. Without an explicit lookup, `spawn openvpn` fails ENOENT
 *      even when the user has done a clean install.
 *   3. The bare binary name, letting the OS resolve via PATH.
 *
 * Required binaries per platform (bundled = shipped in resources/<platform>/,
 * system = resolved from PATH / package manager):
 *   Windows: openvpn.exe + tapctl.exe (bundled portable), rud1-bridge.exe +
 *            USBip-installer.exe + com0com installer (bundled).
 *   Linux:   rud1-bridge (bundled); openvpn + usbip (system,
 *            via deb `recommends` / PATH).
 *   macOS:   rud1-bridge-{arm64,x64} (bundled); openvpn (system,
 *            Homebrew / PATH).
 */

import path from "path";
import fs from "fs";
import { app } from "electron";

const isDev = !app.isPackaged;

function resourcesDir(): string {
  if (isDev) {
    return path.join(app.getAppPath(), "resources", process.platform);
  }
  return path.join(process.resourcesPath, "bin");
}

/**
 * Windows-only: directory holding the bundled portable OpenVPN binaries
 * (openvpn.exe + the runtime DLLs the official MSI installs into
 * Program Files\OpenVPN\bin\). Lives one level below `resourcesDir()` so
 * the DLLs sit next to openvpn.exe (it's a non-relocatable Windows binary —
 * libcrypto-3-x64.dll, libssl-3-x64.dll, etc. must be in the same folder).
 */
export function openvpnBundledDir(): string {
  return path.join(resourcesDir(), "openvpn");
}

/**
 * Known system install directories per binary, per platform. Only the
 * binaries we ship a UI for (OpenVPN, usbip) are listed; everything
 * else falls through to PATH like before.
 *
 * Windows uses `process.env.ProgramFiles` / `ProgramFiles(x86)` rather
 * than hardcoded `C:\Program Files\` so localised installs (Spanish
 * `Archivos de programa`, locale-overridden drives, etc.) keep working.
 */
function systemInstallCandidates(name: string): string[] {
  if (process.platform !== "win32") return [];
  const exe = `${name}.exe`;
  const out: string[] = [];
  const programFiles = process.env["ProgramFiles"];
  const programFilesX86 = process.env["ProgramFiles(x86)"];
  if (name === "openvpn") {
    if (programFiles) out.push(path.join(programFiles, "OpenVPN", "bin", exe));
    if (programFilesX86) out.push(path.join(programFilesX86, "OpenVPN", "bin", exe));
  }
  if (name === "tapctl") {
    if (programFiles) out.push(path.join(programFiles, "OpenVPN", "bin", exe));
    if (programFilesX86) out.push(path.join(programFilesX86, "OpenVPN", "bin", exe));
  }
  if (name === "usbip") {
    // usbip-win2's NSIS installer drops the userspace tool here. PATH
    // typically isn't updated by the installer, so we look explicitly.
    if (programFiles) out.push(path.join(programFiles, "USBip", exe));
    if (programFilesX86) out.push(path.join(programFilesX86, "USBip", exe));
  }
  return out;
}

export function binaryPath(name: string): string {
  const base = resourcesDir();
  const exeName = process.platform === "win32" ? `${name}.exe` : name;
  // OpenVPN sub-folder takes precedence so the bundled binary stays grouped
  // with its DLLs (libssl, libcrypto). A bare resources/<platform>/openvpn.exe
  // would still work but the runtime DLLs need to be siblings of the .exe
  // on Windows — keeping them together avoids accidental DLL loads from
  // PATH directories.
  if (process.platform === "win32" && (name === "openvpn" || name === "tapctl")) {
    const ovpnBundled = path.join(openvpnBundledDir(), exeName);
    if (fs.existsSync(ovpnBundled)) return ovpnBundled;
  }
  const bundled = path.join(base, exeName);

  if (fs.existsSync(bundled)) return bundled;

  for (const candidate of systemInstallCandidates(name)) {
    if (fs.existsSync(candidate)) return candidate;
  }

  // Fallback: bare name, resolved via system PATH at spawn time.
  return name;
}

/**
 * Path to the bundled portable openvpn.exe. Returns the bare name
 * "openvpn" / "openvpn.exe" as a last-resort PATH fallback so the caller
 * can still spawn against a developer-installed copy.
 */
export function openvpnPath(): string {
  return binaryPath("openvpn");
}

/**
 * Path to tapctl.exe — the CLI tool that installs / lists / removes
 * TAP-Windows V9 virtual adapters. Bundled alongside openvpn.exe in the
 * official MSI distribution. We use this to detect whether the TAP driver
 * is installed and (with UAC elevation) to install it if missing.
 *
 * Windows-only. Returns `null` on other platforms.
 */
export function tapctlPath(): string | null {
  if (process.platform !== "win32") return null;
  return binaryPath("tapctl");
}

/**
 * Absolute path to the bundled standalone TAP-Windows V9 driver installer
 * (signed NSIS .exe from openvpn.org). OpenVPN 2.6.x MSI no longer ships
 * the driver inside its own bundle, so we fetch tap-windows-9.21.2.exe
 * separately and ship it under `resources/win32/openvpn/driver/`. At
 * first-launch the openvpn-installer module runs it silently with UAC
 * elevation to install the .inf/.cat/.sys onto the host before calling
 * `tapctl create` to instantiate the rud1-tap adapter.
 *
 * Returns null on non-Windows or when the file wasn't fetched yet (the
 * caller should surface a "re-run fetch:openvpn-win" hint).
 */
export function tapWindowsInstallerPath(): string | null {
  if (process.platform !== "win32") return null;
  const candidate = path.join(openvpnBundledDir(), "driver", "tap-windows-installer.exe");
  return fs.existsSync(candidate) ? candidate : null;
}

/**
 * Legacy compatibility export — older code paths reference an .inf path
 * for "manual fallback: right-click and choose Install". The standalone
 * installer makes that fallback obsolete, so this now returns the
 * installer .exe path (still usable by Explorer's double-click).
 */
export function tapWindowsInfPath(): string | null {
  return tapWindowsInstallerPath();
}

export function usbipPath(): string {
  return binaryPath("usbip");
}

export function usbipdPath(): string {
  return binaryPath("usbipd");
}

/**
 * Path to the bundled `rud1shim` — the generic flasher interceptor that
 * reroutes uploads to a rud1 device's local job-runner (latency-immune
 * programming). Built from native/rud1shim. On non-Windows it returns the
 * bare name (the shim-lifecycle manager only wraps flashers where a bundled
 * binary is present). See docs / native/rud1shim/README.md.
 */
export function rud1shimPath(): string {
  return binaryPath("rud1shim");
}

export function isRud1shimAvailable(): boolean {
  return path.isAbsolute(rud1shimPath());
}

/**
 * Path to the bundled rud1-bridge binary (TCP↔serial RFC 2217 proxy).
 * Cross-compiled from native/rud1-bridge by scripts/build-rud1-bridge.ps1.
 * Falls back to a PATH copy during dev.
 */
export function rud1BridgePath(): string {
  const base = resourcesDir();
  let candidate: string;
  if (process.platform === "darwin") {
    const arch = process.arch === "arm64" ? "arm64" : "x64";
    candidate = path.join(base, `rud1-bridge-${arch}`);
  } else if (process.platform === "win32") {
    candidate = path.join(base, "rud1-bridge.exe");
  } else {
    candidate = path.join(base, "rud1-bridge");
  }
  if (fs.existsSync(candidate)) return candidate;
  return process.platform === "win32" ? "rud1-bridge.exe" : "rud1-bridge";
}

/**
 * True when the bundled rud1-bridge binary is present (i.e. the
 * `npm run build:rud1-bridge` step has been run). The serial-bridge
 * panel uses this to decide whether to offer bridge mode for CDC devices.
 */
export function isRud1BridgeAvailable(): boolean {
  return path.isAbsolute(rud1BridgePath());
}

/**
 * Returns true when `binaryPath(name)` resolved to a real file. Useful
 * for preflight checks that need to give the user an actionable error
 * ("install OpenVPN from <url>") instead of waiting for spawn ENOENT
 * to bubble up through the IPC bridge.
 */
export function isBinaryAvailable(name: string): boolean {
  return path.isAbsolute(binaryPath(name));
}

/**
 * Path to the bundled USB/IP for Windows installer (`USBip-X.Y.Z-x64.exe`).
 * Transporte para dispositivos USB no-CDC (los CDC/serie van por el
 * serial bridge com0com + rud1-bridge).
 */
export function usbipInstallerPath(): string | null {
  if (process.platform !== "win32") return null;
  const candidate = path.join(resourcesDir(), "USBip-installer.exe");
  return fs.existsSync(candidate) ? candidate : null;
}

/**
 * Path to the bundled com0com 3.0.0.0 base installer
 * (`com0com/Setup_com0com_v3.0.0.0_W7_x64_signed.exe`). Se instala en
 * silencio con `/S` y acto seguido se aplica el parche de firma Win11
 * (ver com0comPatchInfPath) para evitar el Code 52. La app es
 * requireAdministrator (sin UAC extra). Null en no-Windows / no empaquetado.
 * Ver docs/serial-com0com-migration.md §4.
 */
export function com0comInstallerPath(): string | null {
  if (process.platform !== "win32") return null;
  const candidate = path.join(
    resourcesDir(),
    "com0com",
    "Setup_com0com_v3.0.0.0_W7_x64_signed.exe",
  );
  return fs.existsSync(candidate) ? candidate : null;
}

/**
 * Path to the Win11 signature-patch INF (`com0com/win11-patch/cncport.inf`,
 * .sys + .cat firmados por FuJian Newland). Se aplica con
 * `pnputil /add-driver cncport.inf /install` tras el instalador base para
 * que el driver cargue en Win11/Secure Boot (resuelve el Code 52 del .sys
 * SHA-1 del 3.0.0.0 original). Null en no-Windows / no empaquetado.
 */
export function com0comPatchInfPath(): string | null {
  if (process.platform !== "win32") return null;
  const candidate = path.join(
    resourcesDir(),
    "com0com",
    "win11-patch",
    "cncport.inf",
  );
  return fs.existsSync(candidate) ? candidate : null;
}

