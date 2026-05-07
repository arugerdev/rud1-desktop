/**
 * Persisted USB/IP attach state for the auto-reattach flow.
 *
 * Each successful `usb:attach` records `(host, busId, label?, port?)`
 * to `<userData>/usb-session-state.json`; each successful detach drops
 * the matching entry. When the WireGuard tunnel reconnects, the main
 * process replays every persisted entry — so the user doesn't have to
 * click "Attach" again after every accidental disconnect.
 *
 * Pure helpers are exported alongside the disk wrappers so the dedupe
 * semantics are testable without touching the filesystem. Mirrors the
 * shape of `first-boot-dedupe.ts` so the two files stay readable side
 * by side (same atomic write, same FIFO cap, same TTL prune).
 */

import { promises as fsp } from "fs";
import * as path from "path";

export interface AttachedUsbSession {
  /** Hostname or IP we passed to `usbip attach -r host`. */
  host: string;
  /** Linux-style bus id, e.g. "1-1.4". Stable across reconnects. */
  busId: string;
  /** Optional human-readable label captured at attach time so the
   *  reattach toast doesn't fall back to "USB <busId>". */
  label?: string;
  /** Last vhci port the kernel assigned. Recorded for diagnostics —
   *  ports are reassigned freely by `usbip attach`, so reattach uses
   *  bus id, not port. */
  port?: number;
  /** ISO 8601 of the last successful attach. */
  attachedAt: string;
}

export interface PersistedUsbSessionFile {
  version: 1;
  sessions: AttachedUsbSession[];
}

export const USB_SESSION_FILENAME = "usb-session-state.json";

/** 30-day TTL keeps the file from growing forever when a user attaches
 *  many short-lived devices. Anything older drops on load. */
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** Cap on persisted sessions — well above realistic concurrent attach
 *  counts (hand-counted < 10 in operator testing). FIFO-evicts oldest
 *  by `attachedAt` when exceeded. */
export const SESSION_CAP = 50;

export function pruneExpiredSessions(
  sessions: readonly AttachedUsbSession[],
  now: Date,
  ttlMs: number = SESSION_TTL_MS,
): AttachedUsbSession[] {
  const cutoff = now.getTime() - ttlMs;
  return sessions.filter((s) => {
    const t = Date.parse(s.attachedAt);
    if (Number.isNaN(t)) return false;
    return t >= cutoff;
  });
}

export function enforceCap(
  sessions: readonly AttachedUsbSession[],
  cap: number = SESSION_CAP,
): AttachedUsbSession[] {
  if (sessions.length <= cap) return [...sessions];
  const sorted = [...sessions].sort((a, b) => {
    const ta = Date.parse(a.attachedAt);
    const tb = Date.parse(b.attachedAt);
    const av = Number.isNaN(ta) ? -Infinity : ta;
    const bv = Number.isNaN(tb) ? -Infinity : tb;
    return av - bv;
  });
  return sorted.slice(sorted.length - cap);
}

/** Add or update a session by `(host, busId)`. Re-attaching the same
 *  device refreshes its `attachedAt`/`label`/`port`. */
export function addSession(
  sessions: readonly AttachedUsbSession[],
  entry: AttachedUsbSession,
): AttachedUsbSession[] {
  const without = sessions.filter(
    (s) => !(s.host === entry.host && s.busId === entry.busId),
  );
  without.push(entry);
  return enforceCap(without);
}

export function removeSessionByBusId(
  sessions: readonly AttachedUsbSession[],
  busId: string,
): AttachedUsbSession[] {
  return sessions.filter((s) => s.busId !== busId);
}

export function removeSessionByPort(
  sessions: readonly AttachedUsbSession[],
  port: number,
): AttachedUsbSession[] {
  return sessions.filter((s) => s.port !== port);
}

function sanitize(parsed: unknown): AttachedUsbSession[] {
  if (!parsed || typeof parsed !== "object") return [];
  const obj = parsed as Record<string, unknown>;
  if (obj.version !== 1) return [];
  if (!Array.isArray(obj.sessions)) return [];
  const out: AttachedUsbSession[] = [];
  for (const item of obj.sessions) {
    if (!item || typeof item !== "object") continue;
    const e = item as Record<string, unknown>;
    if (
      typeof e.host !== "string" ||
      e.host.length === 0 ||
      typeof e.busId !== "string" ||
      e.busId.length === 0 ||
      typeof e.attachedAt !== "string"
    ) {
      continue;
    }
    const entry: AttachedUsbSession = {
      host: e.host,
      busId: e.busId,
      attachedAt: e.attachedAt,
    };
    if (typeof e.label === "string" && e.label.length > 0) entry.label = e.label;
    if (typeof e.port === "number" && Number.isFinite(e.port)) {
      entry.port = e.port;
    }
    out.push(entry);
  }
  return out;
}

/**
 * Load + sanitise + prune the persisted set. Missing file returns an
 * empty array; a malformed file is silently treated as empty so a
 * single bad write can never block the auto-reattach feature.
 */
export async function loadSessions(
  filepath: string,
  now: Date,
): Promise<AttachedUsbSession[]> {
  let raw: string;
  try {
    raw = await fsp.readFile(filepath, "utf8");
  } catch {
    return [];
  }
  try {
    const parsed = JSON.parse(raw);
    return enforceCap(pruneExpiredSessions(sanitize(parsed), now));
  } catch {
    return [];
  }
}

/**
 * Atomic write — tmp + rename so a crash mid-write can't leave a
 * partial JSON file. Mirrors first-boot-dedupe's strategy.
 */
export async function saveSessions(
  filepath: string,
  sessions: readonly AttachedUsbSession[],
): Promise<void> {
  const dir = path.dirname(filepath);
  try {
    await fsp.mkdir(dir, { recursive: true });
  } catch {
    // mkdir failure is logged at the caller; we still try the write.
  }
  const payload: PersistedUsbSessionFile = {
    version: 1,
    sessions: [...sessions],
  };
  const tmp = filepath + ".tmp";
  try {
    await fsp.writeFile(tmp, JSON.stringify(payload, null, 2), "utf8");
    await fsp.rename(tmp, filepath);
  } catch (err) {
    console.warn("[usb-session-state] write failed:", err);
    try {
      await fsp.unlink(tmp);
    } catch {
      // ignore cleanup failures
    }
  }
}
