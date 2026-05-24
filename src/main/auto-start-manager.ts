// mac/Win: app.setLoginItemSettings. Linux: ~/.config/autostart/rud1.desktop.
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
  /** True en dev builds o plataformas no soportadas. */
  unsupported: boolean;
  /** Human-readable explanation when `unsupported` is true. */
  reason?: string;
  /** OS platform reported back so the renderer can pick wording. */
  platform: NodeJS.Platform;
}

function isDevBuild(): boolean {
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

export const __test = {
  linuxAutostartPath,
  buildLinuxDesktopEntry,
};
