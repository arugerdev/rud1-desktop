/**
 * Opt-in periodic diagnosis snapshotter.
 *
 * Runs `exportReport()` on a user-configured interval so operators can build
 * a longitudinal record of a link's health without clicking "Run diagnosis"
 * every time something feels off. State lives in
 * `~/.rud1/diag/autosnapshot.json` so the timer resumes across app restarts.
 *
 * Design notes:
 *   • Only one timer is ever active; calls to `configure()` cancel the
 *     previous one before starting a new one.
 *   • Bounds are clamped server-side: minimum 5 minutes, maximum 24 hours.
 *     Out-of-range intervals from the renderer are silently coerced (with a
 *     `console.warn`) rather than rejected — never trust the client.
 *   • Snapshots run sequentially via a `running` flag; if the previous tick
 *     is still in flight we skip this one rather than queueing, which
 *     protects against pile-up during a sick/slow probe.
 *   • Failures are recorded into the persisted state (`lastError`) but do
 *     NOT disable the timer — a single transient probe error shouldn't stop
 *     an operator's audit trail. Only an explicit `configure({enabled:false})`
 *     stops it.
 *   • A rolling 20-entry `history` ring buffer captures every run (success
 *     or failure) so the renderer can render a timeline without re-reading
 *     report files.
 *   • Manual `triggerAutoSnapshotNow()` runs share the run logic with the
 *     scheduled tick but DO NOT touch the timer state — a button press
 *     mid-cycle no longer pushes the next scheduled run further out.
 */

import { promises as fsp } from "fs";
import * as os from "os";
import * as path from "path";
import { exportReport, type ExportReportResult } from "./tunnel-diag-manager";

export interface AutoSnapshotOpts {
  wgInterface?: string;
  wgHost?: string;
  publicHost?: string;
  publicPort?: number;
  autoMtuProbe?: boolean;
  mtuProbeTimeoutMs?: number;
}

export interface AutoSnapshotHistoryEntry {
  startedAt: string;
  finishedAt: string;
  status: "success" | "error";
  durationMs: number;
  path?: string;
  error?: string;
}

export interface AutoSnapshotConfig {
  enabled: boolean;
  intervalMs: number;
  opts?: AutoSnapshotOpts;
  lastRunAt?: string; // ISO
  lastStatus?: "ok" | "error";
  lastError?: string;
  lastPath?: string;
  history?: AutoSnapshotHistoryEntry[];
}

export interface AutoSnapshotStatus extends AutoSnapshotConfig {
  nextRunAt: string | null;
  running: boolean;
}

const MIN_INTERVAL_MS = 5 * 60 * 1000;
const MAX_INTERVAL_MS = 24 * 60 * 60 * 1000;
const HISTORY_CAP = 20;
const CONFIG_FILENAME = "autosnapshot.json";

function resolveConfigPath(): string {
  return path.join(os.homedir(), ".rud1", "diag", CONFIG_FILENAME);
}

/**
 * Coerce an arbitrary `intervalMs` candidate into the allowed range.
 * Out-of-range values are clamped (with a warning) rather than rejected —
 * the renderer should never be able to crash the schedule with bad input.
 */
function clampInterval(candidate: unknown, fallback: number): number {
  const n = typeof candidate === "number" && Number.isFinite(candidate) ? candidate : fallback;
  if (n < MIN_INTERVAL_MS) {
    console.warn(
      `[auto-snapshot] intervalMs ${n} below minimum ${MIN_INTERVAL_MS}, clamping up`,
    );
    return MIN_INTERVAL_MS;
  }
  if (n > MAX_INTERVAL_MS) {
    console.warn(
      `[auto-snapshot] intervalMs ${n} above maximum ${MAX_INTERVAL_MS}, clamping down`,
    );
    return MAX_INTERVAL_MS;
  }
  return n;
}

function sanitizeHistory(raw: unknown): AutoSnapshotHistoryEntry[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const out: AutoSnapshotHistoryEntry[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const e = item as Record<string, unknown>;
    if (
      typeof e.startedAt !== "string" ||
      typeof e.finishedAt !== "string" ||
      (e.status !== "success" && e.status !== "error") ||
      typeof e.durationMs !== "number"
    ) {
      continue;
    }
    const entry: AutoSnapshotHistoryEntry = {
      startedAt: e.startedAt,
      finishedAt: e.finishedAt,
      status: e.status,
      durationMs: e.durationMs,
    };
    if (typeof e.path === "string") entry.path = e.path;
    if (typeof e.error === "string") entry.error = e.error;
    out.push(entry);
  }
  // Keep only the most recent HISTORY_CAP entries in case a previous run
  // wrote a longer list.
  return out.slice(-HISTORY_CAP);
}

// In-memory state. `timer` is the handle returned by setTimeout (we use a
// self-rescheduling setTimeout rather than setInterval so each tick can wait
// for the previous export to finish before scheduling the next one).
let timer: NodeJS.Timeout | null = null;
let running = false;
let currentConfig: AutoSnapshotConfig = { enabled: false, intervalMs: MIN_INTERVAL_MS };
let nextRunAt: Date | null = null;

async function readConfigFromDisk(): Promise<AutoSnapshotConfig | null> {
  try {
    const raw = await fsp.readFile(resolveConfigPath(), "utf8");
    const parsed = JSON.parse(raw) as Partial<AutoSnapshotConfig> & { history?: unknown };
    if (typeof parsed !== "object" || parsed == null) return null;
    const intervalMs = clampInterval(parsed.intervalMs, MIN_INTERVAL_MS);
    return {
      enabled: parsed.enabled === true,
      intervalMs,
      opts: parsed.opts && typeof parsed.opts === "object" ? parsed.opts : undefined,
      lastRunAt: typeof parsed.lastRunAt === "string" ? parsed.lastRunAt : undefined,
      lastStatus:
        parsed.lastStatus === "ok" || parsed.lastStatus === "error"
          ? parsed.lastStatus
          : undefined,
      lastError: typeof parsed.lastError === "string" ? parsed.lastError : undefined,
      lastPath: typeof parsed.lastPath === "string" ? parsed.lastPath : undefined,
      history: sanitizeHistory(parsed.history),
    };
  } catch (err: unknown) {
    const e = err as NodeJS.ErrnoException;
    if (e?.code === "ENOENT") return null;
    throw err;
  }
}

async function writeConfigToDisk(cfg: AutoSnapshotConfig): Promise<void> {
  const p = resolveConfigPath();
  await fsp.mkdir(path.dirname(p), { recursive: true });
  const tmp = `${p}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(cfg, null, 2) + "\n", "utf8");
  await fsp.rename(tmp, p);
}

function clearTimer(): void {
  if (timer) {
    clearTimeout(timer);
    timer = null;
  }
  nextRunAt = null;
}

function scheduleNext(delayMs: number): void {
  clearTimer();
  nextRunAt = new Date(Date.now() + delayMs);
  timer = setTimeout(() => {
    void runScheduledTick();
  }, delayMs);
  // Allow the Node event loop to exit even if the timer is pending — the
  // Electron main process stays alive on its own accord.
  if (timer && typeof timer.unref === "function") timer.unref();
}

function appendHistory(entry: AutoSnapshotHistoryEntry): void {
  const prev = Array.isArray(currentConfig.history) ? currentConfig.history : [];
  const next = [...prev, entry];
  if (next.length > HISTORY_CAP) next.splice(0, next.length - HISTORY_CAP);
  currentConfig = { ...currentConfig, history: next };
}

/**
 * Core run logic shared by scheduled ticks and manual triggers. Does NOT
 * touch the timer — callers decide whether to reschedule.
 *
 * Returns `false` if a run was already in flight (skipped) so callers can
 * surface "already running" without inspecting state directly.
 */
async function performRun(): Promise<boolean> {
  if (running) return false;
  running = true;
  const startedAt = new Date();
  let entry: AutoSnapshotHistoryEntry;
  try {
    const result: ExportReportResult = await exportReport(currentConfig.opts ?? {});
    const finishedAt = new Date();
    currentConfig = {
      ...currentConfig,
      lastRunAt: startedAt.toISOString(),
      lastStatus: "ok",
      lastPath: result.path,
      lastError: undefined,
    };
    entry = {
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      status: "success",
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      path: result.path,
    };
  } catch (err) {
    const finishedAt = new Date();
    const message = err instanceof Error ? err.message : String(err);
    currentConfig = {
      ...currentConfig,
      lastRunAt: startedAt.toISOString(),
      lastStatus: "error",
      lastError: message,
    };
    entry = {
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      status: "error",
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      error: message,
    };
  } finally {
    running = false;
  }
  appendHistory(entry);
  try {
    await writeConfigToDisk(currentConfig);
  } catch {
    // Persistence failures shouldn't break the loop — next success will
    // overwrite the file anyway.
  }
  return true;
}

/**
 * Scheduled tick: run + reschedule. The reschedule is owned by the timer
 * lifecycle and only fires on scheduled ticks (manual runs do NOT call this).
 */
async function runScheduledTick(): Promise<void> {
  if (!currentConfig.enabled) return;
  const ran = await performRun();
  if (!ran) {
    // Previous export still in flight — skip this slot and reschedule for
    // one full interval from now to avoid tail-end stacking.
    if (currentConfig.enabled) scheduleNext(currentConfig.intervalMs);
    return;
  }
  if (currentConfig.enabled) scheduleNext(currentConfig.intervalMs);
}

/**
 * Read persisted config from disk and start the timer if it was enabled.
 * Called once from the main process after IPC handlers are registered.
 * Safe to call more than once; subsequent calls are no-ops.
 */
export async function resumeAutoSnapshotFromDisk(): Promise<void> {
  if (timer || running) return;
  const cfg = await readConfigFromDisk();
  if (!cfg) return;
  currentConfig = cfg;
  if (cfg.enabled) scheduleNext(cfg.intervalMs);
}

/**
 * Apply a new configuration (persist it to disk and restart the timer).
 * Passing `enabled:false` stops the timer and forgets any pending tick.
 *
 * Interval bounds are enforced server-side via `clampInterval` — never trust
 * what the renderer sent. Out-of-range values get clamped (and warned) rather
 * than rejected so a misbehaving client can't break the schedule.
 */
export async function configureAutoSnapshot(
  next: { enabled: boolean; intervalMs?: number; opts?: AutoSnapshotOpts },
): Promise<AutoSnapshotStatus> {
  const intervalMs = clampInterval(next.intervalMs, currentConfig.intervalMs);
  currentConfig = {
    ...currentConfig,
    enabled: next.enabled,
    intervalMs,
    opts: next.opts ?? currentConfig.opts,
  };
  await writeConfigToDisk(currentConfig);
  if (currentConfig.enabled) {
    scheduleNext(currentConfig.intervalMs);
  } else {
    clearTimer();
  }
  return getAutoSnapshotStatus();
}

export function getAutoSnapshotStatus(): AutoSnapshotStatus {
  return {
    ...currentConfig,
    nextRunAt: nextRunAt ? nextRunAt.toISOString() : null,
    running,
  };
}

/**
 * Trigger a snapshot immediately (outside the timer cadence). Does NOT
 * touch the timer state — `nextRunAt` is preserved exactly as it was, so a
 * "Run now" press never delays the next scheduled tick.
 *
 * Skip-overlap behaviour still applies: if a scheduled (or other manual) run
 * is already in flight the result envelope reports `{ok:false, error:"already running"}`
 * and the in-flight run is allowed to complete on its own.
 */
export async function triggerAutoSnapshotNow(): Promise<
  { ok: true; result: AutoSnapshotStatus } | { ok: false; error: string; result: AutoSnapshotStatus }
> {
  const ran = await performRun();
  if (!ran) {
    return { ok: false, error: "already running", result: getAutoSnapshotStatus() };
  }
  return { ok: true, result: getAutoSnapshotStatus() };
}

// ---- internal exports for tests ---------------------------------------------
// Not part of the public surface; kept underscore-prefixed so the runtime
// shape signals "do not touch from feature code".
export const __test = {
  MIN_INTERVAL_MS,
  MAX_INTERVAL_MS,
  HISTORY_CAP,
  clampInterval,
  resetForTest: (cfg?: Partial<AutoSnapshotConfig>): void => {
    clearTimer();
    running = false;
    currentConfig = {
      enabled: false,
      intervalMs: MIN_INTERVAL_MS,
      ...(cfg ?? {}),
    };
  },
  getNextRunAt: (): Date | null => nextRunAt,
};
