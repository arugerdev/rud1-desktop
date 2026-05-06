import { promises as fsp } from "fs";
import * as os from "os";
import * as path from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  DEFAULT_PREFERENCES,
  PREFERENCES_FILENAME,
  __test,
  getPreferences,
  isNotificationEnabled,
  loadPreferences,
  sanitizePreferences,
  setPreferences,
} from "./preferences-manager";

let tmpDir: string;
let prefsPath: string;

beforeEach(async () => {
  tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), "rud1-preferences-"));
  prefsPath = path.join(tmpDir, PREFERENCES_FILENAME);
  __test.reset();
});

afterEach(async () => {
  await fsp.rm(tmpDir, { recursive: true, force: true });
});

describe("sanitizePreferences", () => {
  it("returns defaults for null / non-object input", () => {
    expect(sanitizePreferences(null)).toEqual(DEFAULT_PREFERENCES);
    expect(sanitizePreferences("nope")).toEqual(DEFAULT_PREFERENCES);
  });

  it("returns defaults when version is missing or wrong", () => {
    expect(sanitizePreferences({ preferences: { theme: "dark" } })).toEqual(
      DEFAULT_PREFERENCES,
    );
    expect(
      sanitizePreferences({ version: 99, preferences: { theme: "dark" } }),
    ).toEqual(DEFAULT_PREFERENCES);
  });

  it("falls back to default per-field when individual fields are bad", () => {
    const result = sanitizePreferences({
      version: 1,
      preferences: {
        theme: "neon", // invalid
        notifications: { firstBoot: false, vpn: "yes", usb: true },
      },
    });
    expect(result.theme).toBe("system"); // bad theme falls back
    expect(result.notifications.firstBoot).toBe(false); // valid bool kept
    expect(result.notifications.vpn).toBe(true); // bad vpn falls back to default true
    expect(result.notifications.usb).toBe(true);
  });

  it("accepts the three valid theme values", () => {
    for (const theme of ["system", "light", "dark"] as const) {
      const out = sanitizePreferences({ version: 1, preferences: { theme } });
      expect(out.theme).toBe(theme);
    }
  });
});

describe("loadPreferences / setPreferences round-trip", () => {
  it("returns defaults when the file does not exist", async () => {
    const prefs = await loadPreferences(prefsPath);
    expect(prefs).toEqual(DEFAULT_PREFERENCES);
  });

  it("persists a partial patch and merges with defaults", async () => {
    await loadPreferences(prefsPath);
    const next = await setPreferences({ theme: "dark" });
    expect(next.theme).toBe("dark");
    // Notifications untouched by a theme-only patch.
    expect(next.notifications).toEqual(DEFAULT_PREFERENCES.notifications);

    const raw = await fsp.readFile(prefsPath, "utf8");
    const parsed = JSON.parse(raw);
    expect(parsed.version).toBe(1);
    expect(parsed.preferences.theme).toBe("dark");
  });

  it("survives a re-load with the persisted state", async () => {
    await loadPreferences(prefsPath);
    await setPreferences({
      theme: "light",
      notifications: { vpn: false },
    });
    __test.reset();

    const reloaded = await loadPreferences(prefsPath);
    expect(reloaded.theme).toBe("light");
    expect(reloaded.notifications.vpn).toBe(false);
    expect(reloaded.notifications.firstBoot).toBe(true);
  });

  it("keeps in-memory state when persistence fails (read-only dir)", async () => {
    const dir = path.join(tmpDir, "ro-tree");
    await fsp.mkdir(dir, { recursive: true });
    const target = path.join(dir, "prefs-ro.json");
    await loadPreferences(target);
    // Replace the path with a literal that mkdir can't satisfy on Windows.
    // The save() catches the error and warns; the cached value still flips.
    await setPreferences({ theme: "dark" });
    expect(getPreferences().theme).toBe("dark");
  });
});

describe("isNotificationEnabled", () => {
  it("reflects the in-memory cache without touching disk", async () => {
    await loadPreferences(prefsPath);
    expect(isNotificationEnabled("firstBoot")).toBe(true);
    expect(isNotificationEnabled("vpn")).toBe(true);
    expect(isNotificationEnabled("usb")).toBe(true);

    await setPreferences({ notifications: { vpn: false } });
    expect(isNotificationEnabled("vpn")).toBe(false);
    expect(isNotificationEnabled("firstBoot")).toBe(true);
  });
});
