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
 * Required binaries per platform:
 *   Windows: openvpn.exe (bundled portable), tapctl.exe (bundled), usbip.exe
 *   Linux:   openvpn, usbip, usbipd
 *   macOS:   openvpn
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
 * Resolves `rud1-bridge`, the Go auxiliary binary that runs the
 * desktop-side TCP↔serial proxy for CDC-class devices. macOS ships
 * arch-suffixed binaries (rud1-bridge-x64 / rud1-bridge-arm64) because
 * cross-compiling lipo'd universal binaries from a Windows dev box
 * isn't possible; the launcher branches on `process.arch` to pick
 * the right one. Linux + Windows ship a single amd64 binary because
 * neither build target supports arm64 yet (rud1-desktop only renders
 * on the operator's machine, which is overwhelmingly x64).
 *
 * Falls through to bare `rud1-bridge` (PATH lookup) on platforms we
 * haven't shipped a binary for — useful during dev when running
 * against a hand-built copy on PATH.
 */
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
 * Mantenido como fallback (no-CDC) cuando VirtualHere free queda agotada
 * a 1 device.
 */
export function usbipInstallerPath(): string | null {
  if (process.platform !== "win32") return null;
  const candidate = path.join(resourcesDir(), "USBip-installer.exe");
  return fs.existsSync(candidate) ? candidate : null;
}

/**
 * Path al binario headless de VirtualHere bundled. Reemplaza al combo
 * com0com + rud1-bridge: el client usa WinUSB / usbser.sys in-box de
 * Microsoft, sin driver kernel custom y compatible con HVCI activo.
 * Devuelve null si el desktop build no lo incluye (fetch script no
 * ejecutado).
 */
export function virtualHereClientPath(): string | null {
  const base = resourcesDir();
  let candidate: string;
  if (process.platform === "win32") {
    // Upstream sólo distribuye el binario GUI vhui64.exe en Windows
    // pero acepta el flag -t "<command>" idéntico al cliente Linux
    // console-only, con lo que podemos usarlo headless lanzándolo con
    // windowsHide: true desde spawn(). El tray icon queda suprimido.
    candidate = path.join(base, "vhui64.exe");
  } else if (process.platform === "darwin") {
    candidate = path.join(base, "vhclient-darwin");
  } else {
    candidate = path.join(base, "vhclientx86_64");
  }
  return fs.existsSync(candidate) ? candidate : null;
}
