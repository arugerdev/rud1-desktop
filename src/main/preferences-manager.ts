/**
 * Persisted user preferences for the desktop app.
 *
 * Lives in `<userData>/preferences.json` next to `first-boot-notifications.json`.
 * Atomic tmp+rename writes mirror first-boot-dedupe so a power loss can't
 * leave a partially-written file. The Settings window reads + writes via
 * IPC; native code (notifications, theme decisions) reads directly from
 * the in-memory cache populated at boot by `loadPreferences`.
 *
 * Design notes:
 *   - Theme override: "system" (default) honours `prefers-color-scheme`;
 *     "light"/"dark" pin the Settings window regardless of OS appearance.
 *   - Notification toggles: per-category mute. The `show()` helpers in
 *     notifications.ts (and `notifyFirstBootDevice` in index.ts) early-
 *     return when the category is disabled, so the OS toast never fires
 *     even though the underlying lifecycle event still drives state.
 *   - Schema is version-gated; mismatched files are dropped and the
 *     defaults reinstalled. We never throw on a bad payload — the
 *     preferences UI is non-critical and a corrupt JSON shouldn't keep
 *     the app from booting.
 */

import { promises as fsp } from "fs";
import * as path from "path";

export type ThemePreference = "system" | "light" | "dark";

export interface NotificationToggles {
  /** Tray "first-boot device on LAN" toast (firmware-discovery probe). */
  firstBoot: boolean;
  /** VPN connect / disconnect / error / CGNAT-warning toasts. */
  vpn: boolean;
  /** USB attach / detach toasts. */
  usb: boolean;
}

export interface Preferences {
  theme: ThemePreference;
  notifications: NotificationToggles;
  /**
   * Iter 8 — auto-reconnect when the WireGuard handshake goes stale
   * (>3 min without traffic). Default true; the renderer can flip it
   * off from Settings for users who prefer manual control.
   */
  vpnAutoReconnect: boolean;
}

export const PREFERENCES_FILENAME = "preferences.json";
const SCHEMA_VERSION = 1;

export const DEFAULT_PREFERENCES: Preferences = {
  theme: "system",
  notifications: { firstBoot: true, vpn: true, usb: true },
  vpnAutoReconnect: true,
};

interface PersistedFile {
  version: number;
  preferences: Preferences;
}

function isThemePreference(v: unknown): v is ThemePreference {
  return v === "system" || v === "light" || v === "dark";
}

function clonePreferences(p: Preferences): Preferences {
  return {
    theme: p.theme,
    notifications: { ...p.notifications },
    vpnAutoReconnect: p.vpnAutoReconnect,
  };
}

/**
 * Defensive parse: garbage / unknown-version files yield a fresh defaults
 * copy rather than throwing. `clonePreferences` guarantees the caller
 * can mutate the result without affecting the singleton DEFAULT.
 */
export function sanitizePreferences(parsed: unknown): Preferences {
  if (!parsed || typeof parsed !== "object") return clonePreferences(DEFAULT_PREFERENCES);
  const obj = parsed as Record<string, unknown>;
  if (obj.version !== SCHEMA_VERSION) return clonePreferences(DEFAULT_PREFERENCES);
  const raw = obj.preferences as Record<string, unknown> | undefined;
  if (!raw || typeof raw !== "object") return clonePreferences(DEFAULT_PREFERENCES);

  const theme = isThemePreference(raw.theme) ? raw.theme : DEFAULT_PREFERENCES.theme;
  const rawN = (raw.notifications as Record<string, unknown> | undefined) ?? {};
  return {
    theme,
    notifications: {
      firstBoot:
        typeof rawN.firstBoot === "boolean"
          ? rawN.firstBoot
          : DEFAULT_PREFERENCES.notifications.firstBoot,
      vpn:
        typeof rawN.vpn === "boolean" ? rawN.vpn : DEFAULT_PREFERENCES.notifications.vpn,
      usb:
        typeof rawN.usb === "boolean" ? rawN.usb : DEFAULT_PREFERENCES.notifications.usb,
    },
    vpnAutoReconnect:
      typeof raw.vpnAutoReconnect === "boolean"
        ? raw.vpnAutoReconnect
        : DEFAULT_PREFERENCES.vpnAutoReconnect,
  };
}

let cached: Preferences = clonePreferences(DEFAULT_PREFERENCES);
let activePath: string | null = null;

/** Idempotent. Loaded once at app.whenReady() before any notification fires. */
export async function loadPreferences(targetPath: string): Promise<Preferences> {
  activePath = targetPath;
  try {
    const buf = await fsp.readFile(targetPath, "utf8");
    cached = sanitizePreferences(JSON.parse(buf));
  } catch {
    // Missing / unreadable / unparseable — keep defaults. The first set()
    // will materialise the file at `targetPath`.
    cached = clonePreferences(DEFAULT_PREFERENCES);
  }
  return clonePreferences(cached);
}

export function getPreferences(): Preferences {
  return clonePreferences(cached);
}

async function persist(targetPath: string, prefs: Preferences): Promise<void> {
  const data: PersistedFile = { version: SCHEMA_VERSION, preferences: prefs };
  const tmp = targetPath + ".tmp";
  await fsp.mkdir(path.dirname(targetPath), { recursive: true });
  await fsp.writeFile(tmp, JSON.stringify(data, null, 2), { encoding: "utf8" });
  await fsp.rename(tmp, targetPath);
}

export interface PreferencesPatch {
  theme?: ThemePreference;
  notifications?: Partial<NotificationToggles>;
  vpnAutoReconnect?: boolean;
}

/**
 * Merge `patch` into the cached preferences and persist atomically. Returns
 * the resulting Preferences so the renderer can mirror the canonical shape
 * without re-fetching. A persistence failure logs but does NOT roll the
 * in-memory state back — preferences-on-disk drifting from in-memory
 * is acceptable until the next set() reconciles, and the operator-visible
 * change still takes effect immediately.
 */
export async function setPreferences(patch: PreferencesPatch): Promise<Preferences> {
  const current = cached;
  const nextNotifications: NotificationToggles = {
    firstBoot:
      typeof patch.notifications?.firstBoot === "boolean"
        ? patch.notifications.firstBoot
        : current.notifications.firstBoot,
    vpn:
      typeof patch.notifications?.vpn === "boolean"
        ? patch.notifications.vpn
        : current.notifications.vpn,
    usb:
      typeof patch.notifications?.usb === "boolean"
        ? patch.notifications.usb
        : current.notifications.usb,
  };
  const next: Preferences = {
    theme: isThemePreference(patch.theme) ? patch.theme : current.theme,
    notifications: nextNotifications,
    vpnAutoReconnect:
      typeof patch.vpnAutoReconnect === "boolean"
        ? patch.vpnAutoReconnect
        : current.vpnAutoReconnect,
  };
  cached = next;
  if (activePath) {
    try {
      await persist(activePath, next);
    } catch (err) {
      console.warn(
        "[preferences] save failed:",
        err instanceof Error ? err.message : err,
      );
    }
  }
  return clonePreferences(next);
}

/**
 * Convenience predicate for the notification helpers in `notifications.ts`
 * and the `notifyFirstBootDevice` site in `index.ts`. Reads the in-memory
 * cache populated by `loadPreferences` — never hits disk on the hot path.
 */
export function isNotificationEnabled(category: keyof NotificationToggles): boolean {
  return cached.notifications[category];
}

// Test-only hook so the vitest suite can reset state between cases without
// poking at file paths. The export is stable; renaming would be a contract
// break for the test file.
export const __test = {
  sanitizePreferences,
  reset(): void {
    cached = clonePreferences(DEFAULT_PREFERENCES);
    activePath = null;
  },
};
