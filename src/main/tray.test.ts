import { describe, expect, it } from "vitest";
import * as path from "path";

import {
  pickIconForState,
  resolveTrayIconPath,
  resolveTrayIcons,
} from "./tray";

const APP_PATH = path.join("/app");
const SCRIPT_DIR = path.join("/app", "dist", "main");
const APP_ICON = (name: string) =>
  path.join(APP_PATH, "resources", "tray", name);
const DEV_ICON_2UP = (name: string) =>
  path.join(SCRIPT_DIR, "..", "..", "resources", "tray", name);
const DEV_ICON_1UP = (name: string) =>
  path.join(SCRIPT_DIR, "..", "resources", "tray", name);

// Pure-helper coverage for the iter-30 tray icon resolver. The runtime
// path (createTray / setTrayIcon) needs an Electron app — we only
// exercise the side-effect-free functions here, which is enough to pin
// the resolution rules and the HiDPI selector.

describe("resolveTrayIconPath", () => {
  it("returns the appPath candidate when present", () => {
    const target = APP_ICON("tray-idle.png");
    const exists = (p: string) => p === target;
    const got = resolveTrayIconPath("tray-idle.png", APP_PATH, SCRIPT_DIR, exists);
    expect(got).toBe(target);
  });

  it("falls back to the dev-mode candidate (../../resources) when appPath misses", () => {
    const target = DEV_ICON_2UP("tray-idle.png");
    const exists = (p: string) => p === target;
    const got = resolveTrayIconPath("tray-idle.png", APP_PATH, SCRIPT_DIR, exists);
    expect(got).toBe(target);
  });

  it("falls back to the second dev-mode candidate (../resources) when both above miss", () => {
    const target = DEV_ICON_1UP("tray-idle.png");
    const exists = (p: string) => p === target;
    const got = resolveTrayIconPath("tray-idle.png", APP_PATH, SCRIPT_DIR, exists);
    expect(got).toBe(target);
  });

  it("returns null when no candidate exists", () => {
    const got = resolveTrayIconPath(
      "tray-idle.png",
      APP_PATH,
      SCRIPT_DIR,
      () => false,
    );
    expect(got).toBeNull();
  });
});

describe("resolveTrayIcons", () => {
  it("resolves all four variants when present", () => {
    const exists = () => true;
    const r = resolveTrayIcons(APP_PATH, SCRIPT_DIR, exists);
    expect(r.idle).toBe(APP_ICON("tray-idle.png"));
    expect(r.idle2x).toBe(APP_ICON("tray-idle@2x.png"));
    expect(r.attention).toBe(APP_ICON("tray-attention.png"));
    expect(r.attention2x).toBe(APP_ICON("tray-attention@2x.png"));
  });

  it("returns nulls for missing variants without throwing", () => {
    const r = resolveTrayIcons(APP_PATH, SCRIPT_DIR, () => false);
    expect(r.idle).toBeNull();
    expect(r.idle2x).toBeNull();
    expect(r.attention).toBeNull();
    expect(r.attention2x).toBeNull();
  });
});

describe("pickIconForState", () => {
  const fullRes = {
    idle: "/idle.png",
    idle2x: "/idle@2x.png",
    attention: "/att.png",
    attention2x: "/att@2x.png",
  } as const;

  it("returns the @2x asset when scaleFactor >= 1.5 (HiDPI)", () => {
    expect(pickIconForState("idle", 2, fullRes)).toBe("/idle@2x.png");
    expect(pickIconForState("attention", 1.5, fullRes)).toBe("/att@2x.png");
  });

  it("returns the 1x asset when scaleFactor < 1.5", () => {
    expect(pickIconForState("idle", 1, fullRes)).toBe("/idle.png");
    expect(pickIconForState("attention", 1.25, fullRes)).toBe("/att.png");
  });

  it("falls back to the 1x asset when only the 1x is resolved", () => {
    const partial = {
      idle: "/idle.png",
      idle2x: null,
      attention: "/att.png",
      attention2x: null,
    } as const;
    expect(pickIconForState("idle", 2, partial)).toBe("/idle.png");
    expect(pickIconForState("attention", 2, partial)).toBe("/att.png");
  });

  it("returns null when the requested variant is fully missing", () => {
    const empty = {
      idle: null,
      idle2x: null,
      attention: null,
      attention2x: null,
    };
    expect(pickIconForState("idle", 1, empty)).toBeNull();
    expect(pickIconForState("attention", 2, empty)).toBeNull();
  });
});
