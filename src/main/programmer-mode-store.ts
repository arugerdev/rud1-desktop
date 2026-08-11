/**
 * Per-USB choice of which programmer runs an upload: the rud1 shim (flash next
 * to the hardware, latency-immune) or the IDE's original flasher.
 *
 * Exists because "auto" can't always be right: it only routes a port whose COM
 * the desktop managed to capture, and some toolchains invoke a flasher we never
 * wrapped. The operator needs to be able to force either side per device.
 *
 *   never  → the port stays out of the shim's map, so it passes through.
 *   auto   → routed when the attach captured its COM (default).
 *   always → routed whenever the COM is known, even if the session went stale.
 *
 * Keyed by (host, busId): bus ids are only unique within one device, so the
 * same bus id on two machines must not share a setting. Pure helpers are
 * exported next to the disk wrappers so the semantics are testable without
 * touching the filesystem — same shape as usb-session-state.ts.
 */

import { promises as fsp } from "fs";
import * as path from "path";

export type ProgrammerMode = "auto" | "always" | "never";

export const PROGRAMMER_MODE_FILENAME = "usb-programmer-modes.json";
export const DEFAULT_PROGRAMMER_MODE: ProgrammerMode = "auto";

/** Map of `${host}|${busId}` → mode. Only non-default entries are stored. */
export type ProgrammerModeMap = Record<string, ProgrammerMode>;

export interface PersistedProgrammerModeFile {
  version: 1;
  modes: ProgrammerModeMap;
}

const VALID: ReadonlySet<string> = new Set<ProgrammerMode>(["auto", "always", "never"]);

export function modeKey(host: string, busId: string): string {
  return `${host}|${busId}`;
}

export function modeFor(
  modes: ProgrammerModeMap,
  host: string,
  busId: string,
): ProgrammerMode {
  return modes[modeKey(host, busId)] ?? DEFAULT_PROGRAMMER_MODE;
}

/** Returns a new map. Setting the default drops the entry — the file only ever
 *  holds deliberate choices, so changing the default later takes effect. */
export function setMode(
  modes: ProgrammerModeMap,
  host: string,
  busId: string,
  mode: ProgrammerMode,
): ProgrammerModeMap {
  const next = { ...modes };
  const key = modeKey(host, busId);
  if (mode === DEFAULT_PROGRAMMER_MODE) delete next[key];
  else next[key] = mode;
  return next;
}

function sanitize(parsed: unknown): ProgrammerModeMap {
  const modes = (parsed as PersistedProgrammerModeFile | null)?.modes;
  if (!modes || typeof modes !== "object") return {};
  const out: ProgrammerModeMap = {};
  for (const [k, v] of Object.entries(modes)) {
    if (typeof k === "string" && typeof v === "string" && VALID.has(v)) {
      if (v !== DEFAULT_PROGRAMMER_MODE) out[k] = v as ProgrammerMode;
    }
  }
  return out;
}

/** Missing or malformed file → no overrides, so a bad write can never leave a
 *  device unable to program. */
export async function loadProgrammerModes(filepath: string): Promise<ProgrammerModeMap> {
  try {
    return sanitize(JSON.parse(await fsp.readFile(filepath, "utf8")));
  } catch {
    return {};
  }
}

/** Atomic write — tmp + rename, as in usb-session-state. */
export async function saveProgrammerModes(
  filepath: string,
  modes: ProgrammerModeMap,
): Promise<void> {
  try {
    await fsp.mkdir(path.dirname(filepath), { recursive: true });
  } catch {
    // still try the write; the caller logs a hard failure
  }
  const payload: PersistedProgrammerModeFile = { version: 1, modes };
  const tmp = filepath + ".tmp";
  try {
    await fsp.writeFile(tmp, JSON.stringify(payload, null, 2), "utf8");
    await fsp.rename(tmp, filepath);
  } catch (err) {
    console.warn("[programmer-mode] write failed:", err);
    try {
      await fsp.unlink(tmp);
    } catch {
      // ignore cleanup failures
    }
  }
}
