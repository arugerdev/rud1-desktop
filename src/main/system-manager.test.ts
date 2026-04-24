/**
 * Unit tests for system-manager (iter 20).
 *
 * Scope:
 *   • totalCpuTimes — aggregates os.cpus() times arrays; rejects
 *     null/empty input so the downstream delta math can't divide by zero.
 *   • collectInterfaces — rolls up os.networkInterfaces() into the
 *     diagnostic shape; marks an interface internal iff every address is
 *     internal; copies mac from the first address.
 *   • sampleCpuUtilisation — clamps util into [0, 1]; returns 0 when the
 *     total delta is non-positive; rounds to 3 decimal places.
 *   • getStats — end-to-end shape check against mocked os APIs: memory
 *     usagePct honours 1-decimal rounding, empty cpus list falls back to
 *     "unknown" / 0, RFC3339 capturedAt, app uptime comes from
 *     process.uptime().
 *
 * Mocking strategy:
 *   • Uses vi.spyOn against the `os` module for each test so the call
 *     under test sees deterministic values. No child_process, no filesystem,
 *     no electron — system-manager is a pure wrapper around `os`.
 */

import { describe, expect, it, vi, afterEach } from "vitest";
import os from "os";

import { getStats, __test } from "./system-manager";

const { totalCpuTimes, collectInterfaces, sampleCpuUtilisation } = __test;

afterEach(() => {
  vi.restoreAllMocks();
});

// ─── 1. totalCpuTimes ──────────────────────────────────────────────────────

describe("totalCpuTimes", () => {
  function cpu(times: {
    user: number;
    nice: number;
    sys: number;
    idle: number;
    irq: number;
  }): os.CpuInfo {
    return { model: "test", speed: 0, times };
  }

  it("sums matching fields across cores", () => {
    const cpus = [
      cpu({ user: 10, nice: 1, sys: 2, idle: 100, irq: 0 }),
      cpu({ user: 20, nice: 2, sys: 3, idle: 200, irq: 1 }),
      cpu({ user: 30, nice: 3, sys: 5, idle: 300, irq: 2 }),
    ];
    expect(totalCpuTimes(cpus)).toEqual({
      user: 60,
      nice: 6,
      sys: 10,
      idle: 600,
      irq: 3,
    });
  });

  it("returns null for an empty array", () => {
    expect(totalCpuTimes([])).toBeNull();
  });

  it("returns null for null/undefined input (defensive against sandbox stubs)", () => {
    // @ts-expect-error — intentional misuse to exercise the guard.
    expect(totalCpuTimes(null)).toBeNull();
    // @ts-expect-error — intentional misuse to exercise the guard.
    expect(totalCpuTimes(undefined)).toBeNull();
  });
});

// ─── 2. collectInterfaces ───────────────────────────────────────────────────

describe("collectInterfaces", () => {
  it("rolls up interfaces; marks internal only if every address is internal", () => {
    vi.spyOn(os, "networkInterfaces").mockReturnValue({
      lo: [
        {
          address: "127.0.0.1",
          netmask: "255.0.0.0",
          family: "IPv4",
          mac: "00:00:00:00:00:00",
          internal: true,
          cidr: "127.0.0.1/8",
        },
      ],
      eth0: [
        {
          address: "192.168.1.10",
          netmask: "255.255.255.0",
          family: "IPv4",
          mac: "aa:bb:cc:dd:ee:ff",
          internal: false,
          cidr: "192.168.1.10/24",
        },
        {
          address: "fe80::1",
          netmask: "ffff:ffff:ffff:ffff::",
          family: "IPv6",
          mac: "aa:bb:cc:dd:ee:ff",
          internal: false,
          scopeid: 0,
          cidr: "fe80::1/64",
        },
      ],
    });

    const result = collectInterfaces();
    const byName = Object.fromEntries(result.map((i) => [i.name, i]));

    expect(byName.lo.internal).toBe(true);
    expect(byName.lo.mac).toBe("00:00:00:00:00:00");
    expect(byName.lo.up).toBe(true);
    expect(byName.lo.addresses).toHaveLength(1);

    expect(byName.eth0.internal).toBe(false);
    expect(byName.eth0.mac).toBe("aa:bb:cc:dd:ee:ff");
    expect(byName.eth0.addresses).toHaveLength(2);
    expect(byName.eth0.addresses[0].family).toBe("IPv4");
    expect(byName.eth0.addresses[1].family).toBe("IPv6");
    expect(byName.eth0.addresses[0].cidr).toBe("192.168.1.10/24");
  });

  it("skips interfaces with no addresses", () => {
    vi.spyOn(os, "networkInterfaces").mockReturnValue({
      empty: undefined,
      also: [],
      eth0: [
        {
          address: "10.0.0.1",
          netmask: "255.0.0.0",
          family: "IPv4",
          mac: "00:11:22:33:44:55",
          internal: false,
          cidr: "10.0.0.1/8",
        },
      ],
    });
    const result = collectInterfaces();
    expect(result.map((i) => i.name)).toEqual(["eth0"]);
  });

  it("marks interface internal when any address is non-internal", () => {
    // Belt-and-braces: if even one address is not internal, the rollup
    // must be non-internal — otherwise a link-local IPv6 could hide a
    // real externally-reachable interface.
    vi.spyOn(os, "networkInterfaces").mockReturnValue({
      mixed: [
        {
          address: "127.0.0.1",
          netmask: "255.0.0.0",
          family: "IPv4",
          mac: "00:00:00:00:00:00",
          internal: true,
          cidr: "127.0.0.1/8",
        },
        {
          address: "10.0.0.1",
          netmask: "255.0.0.0",
          family: "IPv4",
          mac: "00:00:00:00:00:00",
          internal: false,
          cidr: "10.0.0.1/8",
        },
      ],
    });
    const [iface] = collectInterfaces();
    expect(iface.internal).toBe(false);
  });
});

// ─── 3. sampleCpuUtilisation ────────────────────────────────────────────────

describe("sampleCpuUtilisation", () => {
  function cpu(times: {
    user: number;
    nice: number;
    sys: number;
    idle: number;
    irq: number;
  }): os.CpuInfo {
    return { model: "test", speed: 0, times };
  }

  it("computes busy/total delta and rounds to 3 decimals", async () => {
    // First sample: user=100 sys=0 nice=0 irq=0 idle=900 (total=1000, busy=100)
    // Second sample: user=250 sys=0 nice=0 irq=0 idle=1250 (total=1500, busy=250)
    // Delta: busy=150, total=500 => util=0.3
    const spy = vi
      .spyOn(os, "cpus")
      .mockReturnValueOnce([
        cpu({ user: 100, nice: 0, sys: 0, idle: 900, irq: 0 }),
      ])
      .mockReturnValueOnce([
        cpu({ user: 250, nice: 0, sys: 0, idle: 1250, irq: 0 }),
      ]);

    const util = await sampleCpuUtilisation(0);
    expect(util).toBe(0.3);
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it("returns 0 when totalDelta is non-positive (identical samples)", async () => {
    vi.spyOn(os, "cpus").mockReturnValue([
      cpu({ user: 100, nice: 0, sys: 0, idle: 900, irq: 0 }),
    ]);
    expect(await sampleCpuUtilisation(0)).toBe(0);
  });

  it("clamps to 1 when busy somehow exceeds total (counter rollover safety)", async () => {
    // Fabricated rollover: busyDelta > totalDelta. Unlikely in practice,
    // but a 32-bit counter wrap could briefly produce it.
    vi.spyOn(os, "cpus")
      .mockReturnValueOnce([cpu({ user: 0, nice: 0, sys: 0, idle: 1000, irq: 0 })])
      .mockReturnValueOnce([
        cpu({ user: 2000, nice: 0, sys: 0, idle: 500, irq: 0 }),
      ]);
    expect(await sampleCpuUtilisation(0)).toBe(1);
  });

  it("returns null when os.cpus() yields an empty list on either sample", async () => {
    vi.spyOn(os, "cpus")
      .mockReturnValueOnce([])
      .mockReturnValueOnce([
        cpu({ user: 1, nice: 0, sys: 0, idle: 1, irq: 0 }),
      ]);
    expect(await sampleCpuUtilisation(0)).toBeNull();
  });
});

// ─── 4. getStats (end-to-end shape) ─────────────────────────────────────────

describe("getStats", () => {
  it("assembles a full snapshot with 1-decimal usagePct and RFC3339 capturedAt", async () => {
    vi.spyOn(os, "hostname").mockReturnValue("test-host");
    vi.spyOn(os, "release").mockReturnValue("test-release");
    vi.spyOn(os, "uptime").mockReturnValue(1234.9);
    vi.spyOn(os, "loadavg").mockReturnValue([0.1, 0.2, 0.3]);
    vi.spyOn(os, "totalmem").mockReturnValue(16_000_000_000);
    vi.spyOn(os, "freemem").mockReturnValue(4_000_000_000);
    vi.spyOn(os, "networkInterfaces").mockReturnValue({
      eth0: [
        {
          address: "10.0.0.1",
          netmask: "255.0.0.0",
          family: "IPv4",
          mac: "00:11:22:33:44:55",
          internal: false,
          cidr: "10.0.0.1/8",
        },
      ],
    });
    // Two identical samples — util works out to 0 (totalDelta=0 guard).
    vi.spyOn(os, "cpus").mockReturnValue([
      {
        model: "Test CPU",
        speed: 2400,
        times: { user: 100, nice: 0, sys: 0, idle: 900, irq: 0 },
      },
      {
        model: "Test CPU",
        speed: 2400,
        times: { user: 100, nice: 0, sys: 0, idle: 900, irq: 0 },
      },
    ]);

    const stats = await getStats();

    expect(stats.hostname).toBe("test-host");
    expect(stats.release).toBe("test-release");
    expect(stats.uptimeSec).toBe(1234); // floored
    expect(stats.appUptimeSec).toBeGreaterThanOrEqual(0);
    expect(stats.cpu.model).toBe("Test CPU");
    expect(stats.cpu.speedMhz).toBe(2400);
    expect(stats.cpu.count).toBe(2);
    expect(stats.cpu.loadavg).toEqual([0.1, 0.2, 0.3]);
    expect(stats.cpu.utilisation).toBe(0);

    // 4GB free of 16GB total => used=12GB => 75.0%
    expect(stats.memory.totalBytes).toBe(16_000_000_000);
    expect(stats.memory.freeBytes).toBe(4_000_000_000);
    expect(stats.memory.usedBytes).toBe(12_000_000_000);
    expect(stats.memory.usagePct).toBe(75);

    expect(stats.interfaces).toHaveLength(1);
    expect(stats.interfaces[0].name).toBe("eth0");

    // RFC3339: YYYY-MM-DDTHH:mm:ss.sssZ
    expect(stats.capturedAt).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/,
    );
  });

  it("falls back to 'unknown' model and 0 usagePct on degenerate os input", async () => {
    vi.spyOn(os, "hostname").mockReturnValue("h");
    vi.spyOn(os, "release").mockReturnValue("r");
    vi.spyOn(os, "uptime").mockReturnValue(0);
    vi.spyOn(os, "loadavg").mockReturnValue([0, 0, 0]);
    vi.spyOn(os, "totalmem").mockReturnValue(0);
    vi.spyOn(os, "freemem").mockReturnValue(0);
    vi.spyOn(os, "networkInterfaces").mockReturnValue({});
    vi.spyOn(os, "cpus").mockReturnValue([]);

    const stats = await getStats();

    expect(stats.cpu.model).toBe("unknown");
    expect(stats.cpu.speedMhz).toBe(0);
    expect(stats.cpu.count).toBe(0);
    // sampleCpuUtilisation returns null when cpus() is empty on first call
    expect(stats.cpu.utilisation).toBeNull();
    expect(stats.memory.usagePct).toBe(0);
    expect(stats.interfaces).toEqual([]);
  });
});
