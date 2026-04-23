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
 *   • The minimum interval is clamped to 5 minutes. A tighter cadence would
 *     write to `~/.rud1/diag/` aggressively (each snapshot is ~1 KB but
 *     probe latency alone is multi-second on a healthy link and we want
 *     headroom to avoid overlap).
 *   • Snapshots run sequentially via a `running` flag; if the previous tick
 *     is still in flight we skip this one rather than queueing, which
 *     protects against pile-up during a sick/slow probe.
 *   • Failures are recorded into the persisted state (`lastError`) but do
 *     NOT disable the timer — a single transient probe error shouldn't stop
 *     an operator's audit trail. Only an explicit `configure({enabled:false})`
 *     stops it.
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

export interface AutoSnapshotConfig {
  enabled: boolean;
  intervalMs: number;
  opts?: AutoSnapshotOpts;
  lastRunAt?: string; // ISO
  lastStatus?: "ok" | "error";
  lastError?: string;
  lastPath?: string;
}

export interface AutoSnapshotStatus extends AutoSnapshotConfig {
  nextRunAt: string | null;
  running: boolean;
}

const MIN_INTERVAL_MS = 5 * 60 * 1000;
const CONFIG_FILENAME = "autosnapshot.json";

function resolveConfigPath(): string {
  return path.join(os.homedir(), ".rud1", "diag", CONFIG_FILENAME);
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
    const parsed = JSON.parse(raw) as Partial<AutoSnapshotConfig>;
    if (typeof parsed !== "object" || parsed == null) return null;
    const intervalMs =
      typeof parsed.intervalMs === "number" && parsed.intervalMs >= MIN_INTERVAL_MS
        ? parsed.intervalMs
        : MIN_INTERVAL_MS;
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
    void runTick();
  }, delayMs);
  // Allow the Node event loop to exit even if the timer is pending — the
  // Electron main process stays alive on its own accord.
  if (timer && typeof timer.unref === "function") timer.unref();
}

async function runTick(): Promise<void> {
  if (!currentConfig.enabled) return;
  if (running) {
    // Previous export still in flight — skip this slot and reschedule for
    // one full interval from now to avoid tail-end stacking.
    scheduleNext(currentConfig.intervalMs);
    return;
  }
  running = true;
  const startedAt = new Date();
  try {
    const result: ExportReportResult = await exportReport(currentConfig.opts ?? {});
    currentConfig = {
      ...currentConfig,
      lastRunAt: startedAt.toISOString(),
      lastStatus: "ok",
      lastPath: result.path,
      lastError: undefined,
    };
  } catch (err) {
    currentConfig = {
      ...currentConfig,
      lastRunAt: startedAt.toISOString(),
      lastStatus: "error",
      lastError: err instanceof Error ? err.message : String(err),
    };
  } finally {
    running = false;
    try {
      await writeConfigToDisk(currentConfig);
    } catch {
      // Persistence failures shouldn't break the loop — next success will
      // overwrite the file anyway.
    }
    if (currentConfig.enabled) scheduleNext(currentConfig.intervalMs);
  }
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
 */
export async function configureAutoSnapshot(
  next: { enabled: boolean; intervalMs?: number; opts?: AutoSnapshotOpts },
): Promise<AutoSnapshotStatus> {
  const intervalMs =
    typeof next.intervalMs === "number" && next.intervalMs >= MIN_INTERVAL_MS
      ? next.intervalMs
      : Math.max(currentConfig.intervalMs, MIN_INTERVAL_MS);
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
 * Trigger a snapshot immediately (outside the timer cadence). Does not
 * affect the schedule. Useful for a "Run now" button in the renderer.
 */
export async function triggerAutoSnapshotNow(): Promise<AutoSnapshotStatus> {
  await runTick();
  return getAutoSnapshotStatus();
}
