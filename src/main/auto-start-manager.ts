/**
 * Auto-start manager — surfaces "launch rud1 at login" as a per-user
 * preference across the three desktop platforms.
 *
 * macOS / Windows: delegates to `app.setLoginItemSettings`. The Electron
 * helper writes to LSSharedFileList (mac) or
 * HKCU\Software\Microsoft\Windows\CurrentVersion\Run (Win) — both
 * scoped to the current user, so the operation never needs admin even
 * though the installer itself is `requireAdministrator`.
 *
 * Linux: Electron's `setLoginItemSettings` is a no-op, so we manage a
 * `~/.config/autostart/rud1.desktop` entry by hand. Honors
 * `$XDG_CONFIG_HOME` when set; falls back to `~/.config` per the XDG
 * Base Directory spec.
 *
 * Dev mode (`process.defaultApp`): we refuse to enable auto-start
 * because the launcher would resolve to `node + main script`, which
 * isn't a useful thing to fire at login. The renderer disables the
 * toggle and surfaces the reason.
 */

import { app } from "electron";
import { promises as fs } from "fs";
import os from "os";
import path from "path";

const LINUX_AUTOSTART_DIRNAME = "autostart";
const LINUX_AUTOSTART_FILENAME = "rud1.desktop";
const APP_NAME = "rud1";

export interface AutoStartState {
  /** Whether the OS is configured to launch rud1 at login. */
  enabled: boolean;
  /**
   * True when toggling auto-start is unsupported in this build:
   *   - dev/unpackaged builds (no stable launcher path)
   *   - exotic platforms not in {win32, darwin, linux}
   * The renderer disables the switch and shows `reason` as a tooltip.
   */
  unsupported: boolean;
  /** Human-readable explanation when `unsupported` is true. */
  reason?: string;
  /** OS platform reported back so the renderer can pick wording. */
  platform: NodeJS.Platform;
}

function isDevBuild(): boolean {
  // Electron exposes `app.isPackaged` (false in dev). `process.defaultApp`
  // is also true when launched via `electron .`. Either is enough — we
  // OR them so a forked Electron run that bypasses one signal still
  // gets caught by the other.
  return !app.isPackaged || process.defaultApp === true;
}

function linuxAutostartPath(): string {
  const xdgConfig =
    process.env.XDG_CONFIG_HOME && process.env.XDG_CONFIG_HOME.trim().length > 0
      ? process.env.XDG_CONFIG_HOME
      : path.join(os.homedir(), ".config");
  return path.join(xdgConfig, LINUX_AUTOSTART_DIRNAME, LINUX_AUTOSTART_FILENAME);
}

function buildLinuxDesktopEntry(execPath: string): string {
  // Quote the Exec path so spaces in install dirs (rare on Linux but
  // possible) don't split arguments. Escape inner double-quotes for
  // good measure — file path with `"` characters is theoretically legal.
  const safeExec = `"${execPath.replace(/"/g, '\\"')}"`;
  return [
    "[Desktop Entry]",
    "Type=Application",
    `Name=${APP_NAME}`,
    "Comment=rud1 desktop — remote device management with VPN and USB/IP",
    `Exec=${safeExec} --autostart`,
    "Terminal=false",
    "Hidden=false",
    "NoDisplay=false",
    "X-GNOME-Autostart-enabled=true",
    "",
  ].join("\n");
}

async function fileExists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

export async function getAutoStart(): Promise<AutoStartState> {
  const platform = process.platform;
  if (isDevBuild()) {
    return {
      enabled: false,
      unsupported: true,
      reason:
        "Auto-start is only available in installed builds. Running from source has no stable launcher path.",
      platform,
    };
  }

  if (platform === "win32" || platform === "darwin") {
    return {
      enabled: app.getLoginItemSettings().openAtLogin,
      unsupported: false,
      platform,
    };
  }

  if (platform === "linux") {
    return {
      enabled: await fileExists(linuxAutostartPath()),
      unsupported: false,
      platform,
    };
  }

  return {
    enabled: false,
    unsupported: true,
    reason: `Auto-start isn't implemented on ${platform}.`,
    platform,
  };
}

export async function setAutoStart(enabled: boolean): Promise<AutoStartState> {
  const platform = process.platform;
  if (isDevBuild()) {
    return {
      enabled: false,
      unsupported: true,
      reason:
        "Auto-start is only available in installed builds. Running from source has no stable launcher path.",
      platform,
    };
  }

  if (platform === "win32" || platform === "darwin") {
    app.setLoginItemSettings({
      openAtLogin: enabled,
      // Start hidden so the user doesn't get a window on every boot —
      // the tray icon is enough; they can click it to reopen.
      openAsHidden: true,
    });
    return {
      enabled: app.getLoginItemSettings().openAtLogin,
      unsupported: false,
      platform,
    };
  }

  if (platform === "linux") {
    const target = linuxAutostartPath();
    if (enabled) {
      const desktopEntry = buildLinuxDesktopEntry(process.execPath);
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, desktopEntry, { encoding: "utf8", mode: 0o644 });
    } else {
      try {
        await fs.unlink(target);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      }
    }
    return {
      enabled: await fileExists(target),
      unsupported: false,
      platform,
    };
  }

  return {
    enabled: false,
    unsupported: true,
    reason: `Auto-start isn't implemented on ${platform}.`,
    platform,
  };
}

// Test-only hooks. Exported so the vitest suite can poke the Linux
// path-derivation + desktop-entry contents without spinning up an
// Electron app context.
export const __test = {
  linuxAutostartPath,
  buildLinuxDesktopEntry,
};
