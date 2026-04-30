// Real `tray-idle.png` / `tray-attention.png` (and `@2x` HiDPI variants)
// live under `resources/tray/`. We resolve them via `app.getAppPath()`
// first (canonical in dev and packaged), then walk up from `__dirname`
// for vitest-from-repo-root spawns. If nothing matches we fall back to
// `nativeImage.createEmpty()` — invisible on Windows/Linux but better
// than crashing main.

import { Tray, nativeImage, app, screen, type NativeImage } from "electron";
import * as fs from "fs";
import * as path from "path";

export type TrayIconState = "idle" | "attention";

export interface TrayIconResolution {
  idle: string | null;
  idle2x: string | null;
  attention: string | null;
  attention2x: string | null;
}

let trayInstance: Tray | null = null;
let resolution: TrayIconResolution | null = null;
let appliedState: TrayIconState | null = null;

export function resolveTrayIconPath(
  name: string,
  appPath: string,
  scriptDir: string,
  fileExists: (p: string) => boolean = fs.existsSync,
): string | null {
  const candidates = [
    path.join(appPath, "resources", "tray", name),
    path.join(scriptDir, "..", "..", "resources", "tray", name),
    path.join(scriptDir, "..", "resources", "tray", name),
  ];
  for (const c of candidates) {
    if (fileExists(c)) return c;
  }
  return null;
}

export function resolveTrayIcons(
  appPath: string,
  scriptDir: string,
  fileExists: (p: string) => boolean = fs.existsSync,
): TrayIconResolution {
  return {
    idle: resolveTrayIconPath("tray-idle.png", appPath, scriptDir, fileExists),
    idle2x: resolveTrayIconPath("tray-idle@2x.png", appPath, scriptDir, fileExists),
    attention: resolveTrayIconPath(
      "tray-attention.png",
      appPath,
      scriptDir,
      fileExists,
    ),
    attention2x: resolveTrayIconPath(
      "tray-attention@2x.png",
      appPath,
      scriptDir,
      fileExists,
    ),
  };
}

// `>= 1.5` is the standard Electron HiDPI threshold for `image@2x`.
export function pickIconForState(
  state: TrayIconState,
  scaleFactor: number,
  res: TrayIconResolution,
): string | null {
  const wantHiDpi = scaleFactor >= 1.5;
  if (state === "attention") {
    return (wantHiDpi ? res.attention2x : res.attention) ?? res.attention ?? null;
  }
  return (wantHiDpi ? res.idle2x : res.idle) ?? res.idle ?? null;
}

function loadImage(p: string | null): NativeImage {
  if (p == null) return nativeImage.createEmpty();
  return nativeImage.createFromPath(p);
}

export function createTray(): Tray {
  const appPath = app.getAppPath();
  resolution = resolveTrayIcons(appPath, __dirname);
  if (resolution.idle == null) {
    console.warn(
      "[tray] tray-idle.png not found under resources/tray; falling back to empty icon",
    );
  }
  const initialPath = pickIconForState("idle", getScaleFactorSafe(), resolution);
  const img = loadImage(initialPath);
  if (img.isEmpty() && initialPath != null) {
    console.warn(`[tray] tray icon at ${initialPath} decoded empty; using fallback`);
  }
  trayInstance = new Tray(img.isEmpty() ? nativeImage.createEmpty() : img);
  appliedState = "idle";
  return trayInstance;
}

// Idempotent so the tray-attention debounce can call us on every tick.
export function setTrayIcon(state: TrayIconState): void {
  if (!trayInstance || !resolution) return;
  if (appliedState === state) return;
  const targetPath = pickIconForState(state, getScaleFactorSafe(), resolution);
  if (targetPath == null) {
    appliedState = state;
    return;
  }
  const img = loadImage(targetPath);
  if (img.isEmpty()) {
    console.warn(`[tray] icon at ${targetPath} decoded empty; keeping previous image`);
    return;
  }
  trayInstance.setImage(img);
  appliedState = state;
}

export function resetTrayForTesting(): void {
  trayInstance = null;
  resolution = null;
  appliedState = null;
}

export function getTrayInstance(): Tray | null {
  return trayInstance;
}

export function getAppliedState(): TrayIconState | null {
  return appliedState;
}

function getScaleFactorSafe(): number {
  try {
    return screen.getPrimaryDisplay().scaleFactor || 1;
  } catch {
    // `screen` is unavailable until app.whenReady(); a misordered early caller lands here.
    return 1;
  }
}
