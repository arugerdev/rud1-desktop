/**
 * tray — runtime icon management for the system tray (iter 30).
 *
 * Iter 28 documented the tradeoff: with no real icon assets the tray fell
 * back to `nativeImage.createEmpty()`, which is invisible on Windows /
 * Linux and only worked on macOS (where `setTitle("N")` carries the
 * attention signal). Iter 30 ships two real assets (`tray-idle.png`,
 * `tray-attention.png`) plus their `@2x` HiDPI variants under
 * `resources/tray/` and exposes `setTrayIcon('idle' | 'attention')` so
 * the existing `tray-attention` state machine can swap visuals on rising/
 * falling edges.
 *
 * Resolution policy:
 *   1. `app.getAppPath()` is the canonical install root in both dev and
 *      packaged builds (Electron sets it to the repo for `npm run dev`
 *      and to `resources/app.asar` for packaged builds; either way the
 *      `resources/tray/` directory is sibling to the JS).
 *   2. A dev-mode fallback walks one directory up from `__dirname` when
 *      the appPath candidate is missing — useful when the main script
 *      runs from a watched `dist/` outside the canonical app root (e.g.
 *      a vitest spawn from the repo root).
 *   3. If both candidates are empty / missing the function still returns
 *      a Tray instance backed by `nativeImage.createEmpty()` and emits a
 *      `console.warn` — degrading gracefully rather than crashing main.
 *
 * The Tray instance + the resolved-icon record are kept in module-level
 * state so `setTrayIcon` can swap the image without the caller threading
 * a Tray reference through every call site.
 */

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

/**
 * Search candidate roots for the `resources/tray/<name>` icon file.
 * Returns the first existing absolute path, or null when none match.
 *
 * Exported for unit tests so the resolution rules can be exercised
 * without spinning up a Tray.
 */
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

/**
 * Resolve all four icon variants up-front and emit a single warn log
 * when any are missing. Pure (modulo `fileExists`) so tests can pin the
 * "all-missing" branch.
 */
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

/**
 * Pick the right resolution for the supplied display scale factor.
 * `>= 1.5` is the standard Electron heuristic for "treat as HiDPI" —
 * matches the `image@2x` convention.
 */
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
  const img = nativeImage.createFromPath(p);
  return img;
}

/**
 * Build the tray. Resolves icons, refuses an empty image at startup
 * (warn + fallback), and applies the initial 'idle' state.
 */
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

/**
 * Swap the tray image to the requested state. Idempotent: no-op when
 * the same state is requested twice in a row, so the iter 28 debounce in
 * `computeTrayState` flows through cleanly.
 */
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

/**
 * Test/teardown helper — resets module-level state without destroying
 * a real Tray. The runtime path uses `tray.destroy()` directly via
 * `getTrayInstance` so the lifecycle is unambiguous.
 */
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
    // `screen` is unavailable until app.whenReady(); the tests call
    // through resolveTrayIcons / pickIconForState directly, so this
    // is only hit if a misordered caller invokes setTrayIcon early.
    return 1;
  }
}
