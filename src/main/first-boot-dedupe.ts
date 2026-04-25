/**
 * first-boot-dedupe — persisted rising-edge dedupe for the first-boot OS
 * notification (iter 27).
 *
 * The iter 26 rising-edge logic in `firmware-discovery.shouldNotifyFirstBoot`
 * is in-memory only (it consults the previous probe). That's enough to
 * suppress re-notification while the app stays running, but every Electron
 * restart drops the in-memory state — so a Pi that's still in first-boot
 * mode the next morning will re-notify the operator who already saw and
 * dismissed yesterday's notification. This module backs the dedupe set with
 * a JSON file in `app.getPath("userData")` so the suppression survives
 * restarts.
 *
 * Falling edge matters: when a host transitions back to NOT-first-boot
 * (the operator finished the wizard, or the Pi got reflashed and is now
 * paired), we drop it from the persisted set. If the same host re-enters
 * first-boot mode some weeks later — say the operator factory-resets the
 * device — we want to notify again.
 *
 * TTL: a 30-day window prunes entries on load. Two reasons:
 *   1. Without it the set grows unbounded as operators rotate through
 *      devices over months.
 *   2. A Pi that's been stuck in first-boot mode for a month is genuinely
 *      worth re-flagging — that's "something is wrong" territory.
 *
 * FIFO cap at 50 entries by `notifiedAt` keeps file size bounded even in
 * the pathological case where someone configures 200 devices in 30 days.
 *
 * Pure helpers (`pruneExpiredHosts`, `enforceCap`, `addHost`, `removeHost`)
 * are exported separately from the I/O wrappers (`loadNotifiedHosts`,
 * `saveNotifiedHosts`) so the dedupe semantics are trivially testable
 * without touching disk.
 */

import { promises as fsp } from "fs";
import * as path from "path";

export interface NotifiedHost {
  host: string;
  notifiedAt: string; // ISO 8601
}

export interface PersistedDedupeFile {
  version: 1;
  notifiedHosts: NotifiedHost[];
}

export const DEDUPE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
export const DEDUPE_CAP = 50;
export const DEDUPE_FILENAME = "first-boot-notifications.json";

/**
 * Drop entries whose `notifiedAt` is older than `ttlMs`. Pure on the
 * input array (returns a new array).
 */
export function pruneExpiredHosts(
  hosts: readonly NotifiedHost[],
  now: Date,
  ttlMs: number = DEDUPE_TTL_MS,
): NotifiedHost[] {
  const cutoff = now.getTime() - ttlMs;
  return hosts.filter((h) => {
    const t = Date.parse(h.notifiedAt);
    if (Number.isNaN(t)) return false; // garbage entries are silently dropped
    return t >= cutoff;
  });
}

/**
 * Cap the list at `cap` entries, evicting the oldest by `notifiedAt`. Pure.
 */
export function enforceCap(
  hosts: readonly NotifiedHost[],
  cap: number = DEDUPE_CAP,
): NotifiedHost[] {
  if (hosts.length <= cap) return [...hosts];
  // Sort ascending by notifiedAt and keep the newest `cap`. Date.parse on
  // a malformed value returns NaN; treat NaN as oldest so it gets evicted
  // first.
  const sorted = [...hosts].sort((a, b) => {
    const ta = Date.parse(a.notifiedAt);
    const tb = Date.parse(b.notifiedAt);
    const av = Number.isNaN(ta) ? -Infinity : ta;
    const bv = Number.isNaN(tb) ? -Infinity : tb;
    return av - bv;
  });
  return sorted.slice(sorted.length - cap);
}

/**
 * Add a host to the dedupe list. If the host is already present, its
 * `notifiedAt` is refreshed to `now`. Pure.
 */
export function addHost(
  hosts: readonly NotifiedHost[],
  host: string,
  now: Date,
): NotifiedHost[] {
  const without = hosts.filter((h) => h.host !== host);
  without.push({ host, notifiedAt: now.toISOString() });
  return enforceCap(without);
}

/**
 * Remove a host from the dedupe list (no-op if not present). Pure.
 */
export function removeHost(
  hosts: readonly NotifiedHost[],
  host: string,
): NotifiedHost[] {
  return hosts.filter((h) => h.host !== host);
}

/**
 * Best-effort schema validation on a parsed-JSON blob. Anything that
 * doesn't conform returns an empty list rather than throwing — telemetry
 * is non-critical and we'd rather notify-once-too-often than crash main
 * on a bad file.
 */
function sanitize(parsed: unknown): NotifiedHost[] {
  if (!parsed || typeof parsed !== "object") return [];
  const obj = parsed as Record<string, unknown>;
  if (obj.version !== 1) return [];
  if (!Array.isArray(obj.notifiedHosts)) return [];
  const out: NotifiedHost[] = [];
  for (const item of obj.notifiedHosts) {
    if (!item || typeof item !== "object") continue;
    const e = item as Record<string, unknown>;
    if (typeof e.host !== "string" || typeof e.notifiedAt !== "string") continue;
    if (e.host.length === 0) continue;
    out.push({ host: e.host, notifiedAt: e.notifiedAt });
  }
  return out;
}

/**
 * Load the persisted dedupe set, prune expired entries against `now`,
 * and return the surviving list. A missing file returns `[]`. A corrupt
 * file (bad JSON, wrong shape, unreadable) ALSO returns `[]` — we never
 * propagate I/O errors out of this function because the dedupe is a
 * UX nicety, not load-bearing.
 */
export async function loadNotifiedHosts(
  filepath: string,
  now: Date,
  ttlMs: number = DEDUPE_TTL_MS,
): Promise<NotifiedHost[]> {
  let raw: string;
  try {
    raw = await fsp.readFile(filepath, "utf8");
  } catch (err: unknown) {
    const e = err as NodeJS.ErrnoException;
    if (e?.code !== "ENOENT") {
      console.warn(
        `[first-boot-dedupe] read failed (${e?.code ?? "unknown"}): ${e?.message ?? err}`,
      );
    }
    return [];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    console.warn(
      `[first-boot-dedupe] parse failed: ${err instanceof Error ? err.message : err}`,
    );
    return [];
  }
  return pruneExpiredHosts(sanitize(parsed), now, ttlMs);
}

/**
 * Persist the dedupe list atomically. Writes to `<filepath>.tmp` and
 * renames into place so a process kill mid-write doesn't leave a
 * truncated file. Errors are logged-and-swallowed for the same reason
 * loadNotifiedHosts swallows them: dedupe is non-critical telemetry,
 * not state we'd rather crash than corrupt.
 */
export async function saveNotifiedHosts(
  filepath: string,
  hosts: readonly NotifiedHost[],
): Promise<void> {
  const payload: PersistedDedupeFile = {
    version: 1,
    notifiedHosts: enforceCap([...hosts]),
  };
  const body = JSON.stringify(payload, null, 2) + "\n";
  const tmp = `${filepath}.tmp`;
  try {
    await fsp.mkdir(path.dirname(filepath), { recursive: true });
    await fsp.writeFile(tmp, body, "utf8");
    await fsp.rename(tmp, filepath);
  } catch (err) {
    console.warn(
      `[first-boot-dedupe] write failed: ${err instanceof Error ? err.message : err}`,
    );
    // Best-effort cleanup of a stale tmp file. Ignore secondary failures.
    try {
      await fsp.unlink(tmp);
    } catch {
      /* ignore */
    }
  }
}

/**
 * Convenience: returns true if `host` has a non-expired entry in the list.
 * Pure.
 */
export function isHostNotified(
  hosts: readonly NotifiedHost[],
  host: string,
  now: Date,
  ttlMs: number = DEDUPE_TTL_MS,
): boolean {
  const cutoff = now.getTime() - ttlMs;
  for (const h of hosts) {
    if (h.host !== host) continue;
    const t = Date.parse(h.notifiedAt);
    if (Number.isNaN(t)) continue;
    if (t >= cutoff) return true;
  }
  return false;
}
