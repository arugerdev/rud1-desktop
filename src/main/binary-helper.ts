/**
 * Resolves paths to bundled native binaries.
 *
 * Lookup order:
 *   1. Bundled binary (resources/<platform>/<name> in dev,
 *      process.resourcesPath/bin/<name> in production via extraResources).
 *   2. Platform-known system install paths — e.g. on Windows the official
 *      WireGuard installer drops `wireguard.exe` / `wg.exe` into
 *      `%ProgramFiles%\WireGuard\` but does NOT add that directory to
 *      PATH. Without an explicit lookup, `spawn wireguard` fails ENOENT
 *      even when the user has done a clean install.
 *   3. The bare binary name, letting the OS resolve via PATH.
 *
 * Returning the bare name as the last fallback means `execFile` will
 * surface ENOENT only when the binary is genuinely absent — at that
 * point callers (`vpn-manager`, `usb-manager`) translate the error
 * into an actionable "install X from <url>" message for the panel.
 *
 * Required binaries per platform:
 *   Windows: wireguard.exe, wg.exe, usbip.exe
 *   Linux:   wg, wg-quick, usbip, usbipd
 *   macOS:   wireguard-go, wg, wg-quick
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
 * Known system install directories per binary, per platform. Only the
 * binaries we ship a UI for (WireGuard, usbip) are listed; everything
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
  if (name === "wireguard" || name === "wg") {
    if (programFiles) out.push(path.join(programFiles, "WireGuard", exe));
    if (programFilesX86) out.push(path.join(programFilesX86, "WireGuard", exe));
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
  const bundled = path.join(base, exeName);

  if (fs.existsSync(bundled)) return bundled;

  for (const candidate of systemInstallCandidates(name)) {
    if (fs.existsSync(candidate)) return candidate;
  }

  // Fallback: bare name, resolved via system PATH at spawn time.
  return name;
}

export function wgPath(): string {
  return binaryPath("wg");
}

export function wgQuickPath(): string {
  if (process.platform === "win32") return binaryPath("wireguard");
  return binaryPath("wg-quick");
}

export function usbipPath(): string {
  return binaryPath("usbip");
}

export function usbipdPath(): string {
  return binaryPath("usbipd");
}

/**
 * Returns true when `binaryPath(name)` resolved to a real file. Useful
 * for preflight checks that need to give the user an actionable error
 * ("install WireGuard for Windows from <url>") instead of waiting for
 * spawn ENOENT to bubble up through the IPC bridge.
 */
export function isBinaryAvailable(name: string): boolean {
  return path.isAbsolute(binaryPath(name));
}

/**
 * Path to the bundled USB/IP for Windows installer (`USBip-X.Y.Z-x64.exe`).
 * Returns `null` on non-Windows platforms or when the installer wasn't
 * bundled (developer skipped `npm run fetch:usbip-win`). The caller can
 * spawn this via `shell.openPath` to walk the user through a one-time
 * driver install — usbip-win2 ships a kernel-mode VHCI driver, so a
 * userspace-only bundle wouldn't be enough.
 */
export function usbipInstallerPath(): string | null {
  if (process.platform !== "win32") return null;
  const candidate = path.join(resourcesDir(), "USBip-installer.exe");
  return fs.existsSync(candidate) ? candidate : null;
}
