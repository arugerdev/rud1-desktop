/**
 * Resolves paths to bundled native binaries.
 *
 * In development: looks in resources/<platform>/
 * In production:  binaries are in process.resourcesPath/bin/ (extraResources in electron-builder)
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

export function binaryPath(name: string): string {
  const base = resourcesDir();
  const exeName = process.platform === "win32" ? `${name}.exe` : name;
  const full = path.join(base, exeName);

  if (fs.existsSync(full)) return full;

  // Fallback: system PATH (useful when the user has WireGuard/usbip installed)
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
