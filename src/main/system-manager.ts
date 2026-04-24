/**
 * System diagnostics manager.
 *
 * Exposes a read-only snapshot of the operator's machine — hostname,
 * platform, CPU count + load, memory pressure, network interface roll-up
 * — so rud1.es dashboards can sanity-check whether a suspicious VPN issue
 * is caused by the desktop side (CPU saturated, memory pressure, offline
 * adapter) before pointing fingers at the Pi.
 *
 * Everything here is local-only: no shell commands, no external calls,
 * no filesystem writes. It's a thin wrapper around Node's `os` module
 * plus a handful of derived convenience fields.
 */

import os from "os";
import { performance } from "perf_hooks";

export interface SystemStatsCpu {
  model: string;
  speedMhz: number;
  count: number;
  // loadavg is [1m, 5m, 15m] on POSIX; all zeros on Windows (node-native).
  loadavg: [number, number, number];
  // Normalised 0..1 utilisation computed from a pair of samples 250ms apart.
  // `null` when the second sample failed (extremely rare, e.g. permission
  // errors in a sandbox).
  utilisation: number | null;
}

export interface SystemStatsMemory {
  totalBytes: number;
  freeBytes: number;
  usedBytes: number;
  usagePct: number; // 0..100, rounded to 1 decimal
}

export interface SystemStatsInterface {
  name: string;
  mac: string;
  up: boolean;
  internal: boolean;
  addresses: {
    family: "IPv4" | "IPv6";
    address: string;
    cidr: string | null;
  }[];
}

export interface SystemStats {
  hostname: string;
  platform: NodeJS.Platform;
  release: string;
  arch: string;
  uptimeSec: number;
  // `process.uptime()` in seconds — how long the desktop app has been
  // alive. Useful for detecting "the tunnel is flapping because the app
  // keeps being killed" scenarios.
  appUptimeSec: number;
  cpu: SystemStatsCpu;
  memory: SystemStatsMemory;
  interfaces: SystemStatsInterface[];
  capturedAt: string; // RFC3339 UTC — same format the Pi uses for timestamps
}

/**
 * Samples aggregate CPU time from `os.cpus()` twice, `delayMs` apart, and
 * returns utilisation as (busyDelta / totalDelta). Returns null if either
 * sample is unavailable.
 */
async function sampleCpuUtilisation(delayMs = 250): Promise<number | null> {
  const first = totalCpuTimes(os.cpus());
  if (!first) return null;
  await new Promise((r) => setTimeout(r, delayMs));
  const second = totalCpuTimes(os.cpus());
  if (!second) return null;
  const busyDelta =
    second.user + second.sys + second.nice + second.irq
    - (first.user + first.sys + first.nice + first.irq);
  const totalDelta =
    second.user + second.sys + second.nice + second.irq + second.idle
    - (first.user + first.sys + first.nice + first.irq + first.idle);
  if (totalDelta <= 0) return 0;
  const util = busyDelta / totalDelta;
  if (!Number.isFinite(util) || util < 0) return 0;
  if (util > 1) return 1;
  return Number(util.toFixed(3));
}

function totalCpuTimes(cpus: os.CpuInfo[]):
  | { user: number; sys: number; nice: number; idle: number; irq: number }
  | null {
  if (!cpus || cpus.length === 0) return null;
  return cpus.reduce(
    (acc, c) => ({
      user: acc.user + c.times.user,
      sys: acc.sys + c.times.sys,
      nice: acc.nice + c.times.nice,
      idle: acc.idle + c.times.idle,
      irq: acc.irq + c.times.irq,
    }),
    { user: 0, sys: 0, nice: 0, idle: 0, irq: 0 },
  );
}

function collectInterfaces(): SystemStatsInterface[] {
  const raw = os.networkInterfaces();
  const out: SystemStatsInterface[] = [];
  for (const [name, addrs] of Object.entries(raw)) {
    if (!addrs || addrs.length === 0) continue;
    // Node's `internal` flag is per-address — roll up: the interface is
    // treated as internal iff every address on it is internal.
    const internal = addrs.every((a) => a.internal);
    const mac = addrs[0]?.mac ?? "";
    out.push({
      name,
      mac,
      // `os.networkInterfaces()` omits down interfaces entirely on POSIX,
      // so anything we see here is "up" in practice. Keep the field for
      // API symmetry with the Pi's interface listing.
      up: true,
      internal,
      addresses: addrs.map((a) => ({
        family: a.family as "IPv4" | "IPv6",
        address: a.address,
        cidr: a.cidr ?? null,
      })),
    });
  }
  return out;
}

// Test-only hatch: exposes the internal helpers so system-manager.test.ts
// can pin their behaviour (CPU delta math, interface rollup, edge cases)
// without exercising `getStats()` top-to-bottom. Matches the pattern used
// by vpn-manager / net-diag-manager / tunnel-diag-manager.
export const __test = {
  totalCpuTimes,
  collectInterfaces,
  sampleCpuUtilisation,
};

export async function getStats(): Promise<SystemStats> {
  const startedAt = performance.now();
  const util = await sampleCpuUtilisation();
  const cpus = os.cpus();
  const first = cpus[0];
  const total = os.totalmem();
  const free = os.freemem();
  const used = Math.max(0, total - free);
  const usagePct = total > 0 ? Number(((used / total) * 100).toFixed(1)) : 0;
  void startedAt; // reserved for perf logging; avoid unused-var lint

  return {
    hostname: os.hostname(),
    platform: process.platform,
    release: os.release(),
    arch: process.arch,
    uptimeSec: Math.floor(os.uptime()),
    appUptimeSec: Math.floor(process.uptime()),
    cpu: {
      model: first?.model ?? "unknown",
      speedMhz: first?.speed ?? 0,
      count: cpus.length,
      loadavg: os.loadavg() as [number, number, number],
      utilisation: util,
    },
    memory: {
      totalBytes: total,
      freeBytes: free,
      usedBytes: used,
      usagePct,
    },
    interfaces: collectInterfaces(),
    capturedAt: new Date().toISOString(),
  };
}
