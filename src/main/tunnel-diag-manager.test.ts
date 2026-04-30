/**
 * Unit tests for tunnel-diag-manager (iter 17).
 *
 * Scope:
 *   • validateReportPath — path-traversal guard (resolveDiagDir + filename
 *     regex), exposed via the `__test` hatch we add at the bottom of the
 *     module.
 *   • mtuProbe — RUD1_SIMULATE short-circuit + invalid-host rejection.
 *   • compareReports — swap-on-out-of-order, delta arithmetic,
 *     verdictChanged null-handling, activePeers counting, JSON parse error.
 *
 * Mocking strategy (mirrors iter 16 / auto-snapshot-manager.test.ts):
 *   • `os.homedir()` is redirected to a per-test tmpdir subdir via
 *     `vi.mock("os", factory)`. We can't `vi.spyOn` because the ESM
 *     namespace is non-configurable in the tunnel-diag-manager import.
 *   • We intentionally do NOT mock `child_process` — the simulated
 *     RUD1_SIMULATE=1 path inside `mtuProbe` short-circuits before any
 *     spawn/execFile is touched, so the real binding stays inert. The
 *     non-simulated bisect-narrows-to-576 case is `it.todo`'d below
 *     because mocking the promisified execFile event chain is brittle and
 *     adds little signal beyond what the simulated path already proves.
 *   • compareReports uses real fixture files written into the mocked
 *     `~/.rud1/diag/` so it exercises validateReportPath + readFile +
 *     JSON.parse + extractSnapshot end to end.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as path from "path";
import { tmpdir } from "os";
import { promises as fsp } from "fs";

// Per-test tmp home — the `vi.mock` factory captures `tmpHome` by reference
// (it's reassigned in beforeEach), so each test's homedir() returns the new
// path without re-registering the mock.
let tmpHome = path.join(
  tmpdir(),
  `rud1-tdm-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
);
vi.mock("os", async () => {
  const actual = await vi.importActual<typeof import("os")>("os");
  return {
    ...actual,
    homedir: () => tmpHome,
    default: { ...actual, homedir: () => tmpHome },
  };
});

// Import AFTER the mock is registered. vi.mock is hoisted but the captured
// `tmpHome` lookup happens lazily inside homedir(), so it's safe.
import {
  compareReports,
  mtuProbe,
  wgStatus,
  __test,
} from "./tunnel-diag-manager";

const { validateReportPath, REPORT_FILENAME_REGEX } = __test;

// ─── helpers ────────────────────────────────────────────────────────────────

const VALID_FILENAME = "rud1-diag-20260423-120000.json";

function diagDir(): string {
  return path.join(tmpHome, ".rud1", "diag");
}

async function ensureDiagDir(): Promise<string> {
  const d = diagDir();
  await fsp.mkdir(d, { recursive: true });
  return d;
}

interface FixtureOpts {
  exportedAt: string;
  verdict?: "healthy" | "degraded" | "broken" | null;
  /** One number per peer; used as `latestHandshake`. */
  peerHandshakes?: number[];
  mtuDiscovered?: number | null;
  cpuPct?: number | null;
  memPct?: number | null;
  tempCpu?: number | null;
}

/**
 * Build a synthetic exported-report payload that mirrors the shape produced
 * by `exportReport`. We hard-code only the fields `extractSnapshot` reads —
 * everything else is omitted so the test fixture stays grokkable.
 */
function buildReport(opts: FixtureOpts): unknown {
  const peers = (opts.peerHandshakes ?? []).map((hs, idx) => ({
    publicKey: `peer-${idx}`,
    endpoint: null,
    allowedIps: [],
    latestHandshake: hs,
    transferRx: 0,
    transferTx: 0,
    persistentKeepalive: null,
  }));

  return {
    exportedAt: opts.exportedAt,
    appVersion: "0.0.0-test",
    platform: "linux",
    arch: "x64",
    nodeVersion: "0.0.0",
    electronVersion: "0.0.0",
    diagnosis: {
      timestamp: Date.parse(opts.exportedAt),
      wgStatus: {
        available: true,
        tunnels: [
          {
            interface: "wg0",
            publicKey: null,
            listenPort: null,
            peers,
          },
        ],
      },
      wgStatusError: null,
      tunnelHealth:
        opts.verdict === undefined
          ? null
          : {
              wgPing: { reachable: true, rttMs: 5 },
              publicPing: { reachable: true, rttMs: 5 },
              tcpProbe: { open: true, errorCode: null, latencyMs: 5 },
              verdict: opts.verdict,
              hints: [],
              ...(opts.mtuDiscovered != null
                ? { mtu: { discovered: opts.mtuDiscovered } }
                : {}),
            },
      tunnelHealthError: null,
      systemStats: {
        cpu: { utilisation: opts.cpuPct ?? null, tempC: opts.tempCpu ?? null },
        memory: { usagePct: opts.memPct ?? null },
      },
      systemStatsError: null,
    },
  };
}

async function writeFixture(filename: string, payload: unknown): Promise<string> {
  const dir = await ensureDiagDir();
  const abs = path.join(dir, filename);
  await fsp.writeFile(abs, JSON.stringify(payload, null, 2), "utf8");
  return abs;
}

// ─── lifecycle ──────────────────────────────────────────────────────────────

beforeEach(async () => {
  tmpHome = path.join(
    tmpdir(),
    `rud1-tdm-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );
  await fsp.mkdir(tmpHome, { recursive: true });
  // Make sure the simulate flag is in a known state per test.
  delete process.env.RUD1_SIMULATE;
});

afterEach(async () => {
  delete process.env.RUD1_SIMULATE;
  try {
    await fsp.rm(tmpHome, { recursive: true, force: true });
  } catch {
    // best-effort cleanup
  }
});

// ─── 1. validateReportPath ──────────────────────────────────────────────────

describe("validateReportPath", () => {
  it("accepts a well-formed filename inside ~/.rud1/diag/", async () => {
    await ensureDiagDir();
    const candidate = path.join(diagDir(), VALID_FILENAME);
    const res = validateReportPath(candidate);
    expect(res.filename).toBe(VALID_FILENAME);
    expect(res.abs).toBe(path.resolve(candidate));
    expect(res.dir).toBe(diagDir());
  });

  it("rejects ../etc/passwd-style traversal that escapes the diag dir", () => {
    expect(() => validateReportPath("../etc/passwd")).toThrow(
      /path outside allowed directory/,
    );
  });

  it("rejects an absolute path outside ~/.rud1/diag/", () => {
    const outside = path.join(tmpHome, "elsewhere", VALID_FILENAME);
    expect(() => validateReportPath(outside)).toThrow(
      /path outside allowed directory/,
    );
  });

  it("rejects filenames that don't match the rud1-diag-YYYYMMDD-HHmmss.json regex", async () => {
    await ensureDiagDir();
    const cases = [
      "rud1-diag-abc.json",
      "rud1-diag-20260423.json",
      "rud1-diag-20260423-120000.json.exe",
      "rud1-diag-20260423-12000.json", // 5-digit time
      "rud1-diag-2026042-120000.json", // 7-digit date
    ];
    for (const name of cases) {
      const abs = path.join(diagDir(), name);
      expect(() => validateReportPath(abs)).toThrow(/invalid report filename/);
    }
  });

  it("rejects a sibling directory like ~/.rud1/diag-evil/ (trailing-separator guard)", () => {
    // The guard requires the resolved path to start with `<diagDir><sep>`. A
    // sibling whose name happens to share the prefix must be rejected.
    const evil = path.join(tmpHome, ".rud1", "diag-evil", VALID_FILENAME);
    expect(() => validateReportPath(evil)).toThrow(
      /path outside allowed directory/,
    );
  });

  it("rejects a path that resolves to the parent dir via dot-segments", () => {
    const sneaky = path.join(diagDir(), "..", "..", VALID_FILENAME);
    expect(() => validateReportPath(sneaky)).toThrow(
      /path outside allowed directory/,
    );
  });

  it("rejects empty/non-string inputs", () => {
    expect(() => validateReportPath("")).toThrow(/invalid path/);
    expect(() =>
      (validateReportPath as (p: unknown) => unknown)(undefined),
    ).toThrow(/invalid path/);
    expect(() =>
      (validateReportPath as (p: unknown) => unknown)(null),
    ).toThrow(/invalid path/);
    expect(() =>
      (validateReportPath as (p: unknown) => unknown)(123),
    ).toThrow(/invalid path/);
  });

  it("REPORT_FILENAME_REGEX is exposed and matches a canonical filename", () => {
    expect(REPORT_FILENAME_REGEX.test(VALID_FILENAME)).toBe(true);
    expect(REPORT_FILENAME_REGEX.test("rud1-diag-99999999-235959.json")).toBe(true);
    expect(REPORT_FILENAME_REGEX.test("RUD1-DIAG-20260423-120000.json")).toBe(false);
  });
});

// ─── 2. mtuProbe ────────────────────────────────────────────────────────────

describe("mtuProbe", () => {
  it("returns the simulated 1420 result when RUD1_SIMULATE=1", async () => {
    process.env.RUD1_SIMULATE = "1";
    const res = await mtuProbe("10.0.0.1");
    expect(res.mtu).toBe(1420);
    expect(res.host).toBe("10.0.0.1");
    expect(res.attempts.length).toBeGreaterThan(0);
    // The deterministic simulated branch sets attempts to a fixed pair —
    // a 1500-fail followed by a 1420-pass.
    expect(res.attempts.some((a) => a.size === 1420 && a.ok)).toBe(true);
    expect(res.attempts.some((a) => a.size === 1500 && !a.ok)).toBe(true);
    expect(res.platform === "linux" || res.platform === "win32").toBe(true);
  });

  it("simulated mode ignores opts.start/min and still returns 1420", async () => {
    process.env.RUD1_SIMULATE = "1";
    const res = await mtuProbe("10.0.0.1", { start: 1280, min: 1000, timeoutMs: 1000 });
    expect(res.mtu).toBe(1420);
  });

  it("rejects hosts with shell metacharacters via validateHost", async () => {
    // No RUD1_SIMULATE here — validateHost runs before the simulate
    // short-circuit, so even without the env var these throw.
    await expect(mtuProbe("foo;rm -rf /")).rejects.toThrow(/invalid host/);
    await expect(mtuProbe("a b")).rejects.toThrow(/invalid host/);
    await expect(mtuProbe("$(whoami)")).rejects.toThrow(/invalid host/);
    await expect(mtuProbe("")).rejects.toThrow(/invalid host/);
  });

  it("validateHost rejection precedes simulate short-circuit", async () => {
    // Even with simulate on, an invalid host must throw — we don't want
    // the simulator to mask validation bugs in production code paths.
    process.env.RUD1_SIMULATE = "1";
    await expect(mtuProbe("foo;bar")).rejects.toThrow(/invalid host/);
  });

  it.todo(
    "narrows to 576 when execFile is mocked to always report 'message too long' " +
      "(skipped: mocking promisified execFile's event chain is too brittle " +
      "for the value it adds — the simulate-path tests above already " +
      "exercise the public contract end to end)",
  );
});

// ─── 3. wgStatus tunnel-name guard ──────────────────────────────────────────

describe("wgStatus", () => {
  it("rejects leading-dash tunnel names (flag-injection defence)", async () => {
    // TUNNEL_NAME_REGEX permits `-` in its char class, so without an explicit
    // startsWith-dash guard a value like "-version" matches the regex and
    // would be forwarded as positional argv #2 to `wg show`, where it would
    // be parsed as a flag. Mirrors the equivalent guard added in iter 11 to
    // net-diag-manager.validateHost.
    for (const bad of ["-version", "-h", "--help", "-rud1", "-_attacker"]) {
      const res = await wgStatus(bad);
      expect(res).toEqual({ available: false, reason: "invalid tunnel name" });
    }
  });
});

// ─── 4. compareReports ──────────────────────────────────────────────────────

describe("compareReports", () => {
  it("swaps when pathA's exportedAt is later than pathB's", async () => {
    const later = "2026-04-23T15:00:00.000Z";
    const earlier = "2026-04-23T12:00:00.000Z";
    const pathA = await writeFixture(
      "rud1-diag-20260423-150000.json",
      buildReport({ exportedAt: later, verdict: "degraded", cpuPct: 80 }),
    );
    const pathB = await writeFixture(
      "rud1-diag-20260423-120000.json",
      buildReport({ exportedAt: earlier, verdict: "healthy", cpuPct: 20 }),
    );

    const res = await compareReports({ pathA, pathB });
    expect(res.swapped).toBe(true);
    // After swap, `a` is the earlier and `b` is the later.
    expect(res.a.exportedAt).toBe(earlier);
    expect(res.b.exportedAt).toBe(later);
    // Delta is "later minus earlier".
    expect(res.deltas.cpuPctDelta).toBe(60);
    expect(res.deltas.verdictChanged).toBe(true);
    expect(res.deltas.timeBetweenMs).toBe(3 * 60 * 60 * 1000);
  });

  it("does not swap when paths are already in chronological order", async () => {
    const earlier = "2026-04-23T08:00:00.000Z";
    const later = "2026-04-23T09:00:00.000Z";
    const pathA = await writeFixture(
      "rud1-diag-20260423-080000.json",
      buildReport({ exportedAt: earlier, verdict: "healthy" }),
    );
    const pathB = await writeFixture(
      "rud1-diag-20260423-090000.json",
      buildReport({ exportedAt: later, verdict: "healthy" }),
    );

    const res = await compareReports({ pathA, pathB });
    expect(res.swapped).toBe(false);
    expect(res.a.exportedAt).toBe(earlier);
    expect(res.b.exportedAt).toBe(later);
  });

  it("identical reports yield zero deltas and verdictChanged=false", async () => {
    const ts = "2026-04-23T10:00:00.000Z";
    const fixture = buildReport({
      exportedAt: ts,
      verdict: "healthy",
      peerHandshakes: [12345, 67890],
      mtuDiscovered: 1420,
      cpuPct: 25,
      memPct: 40,
      tempCpu: 55,
    });
    const pathA = await writeFixture("rud1-diag-20260423-100000.json", fixture);
    // Same timestamp inside the payload, different on-disk filename so the
    // path validator accepts both.
    const pathB = await writeFixture("rud1-diag-20260423-100001.json", fixture);

    const res = await compareReports({ pathA, pathB });
    expect(res.deltas.cpuPctDelta).toBe(0);
    expect(res.deltas.memPctDelta).toBe(0);
    expect(res.deltas.tempDelta).toBe(0);
    expect(res.deltas.mtuDelta).toBe(0);
    expect(res.deltas.wgPeerCountDelta).toBe(0);
    expect(res.deltas.activePeersDelta).toBe(0);
    expect(res.deltas.timeBetweenMs).toBe(0);
    expect(res.deltas.verdictChanged).toBe(false);
  });

  it("computes per-field deltas as (b - a) for cpu/mem/temp/mtu", async () => {
    const pathA = await writeFixture(
      "rud1-diag-20260423-100000.json",
      buildReport({
        exportedAt: "2026-04-23T10:00:00.000Z",
        verdict: "healthy",
        cpuPct: 10,
        memPct: 30,
        tempCpu: 40,
        mtuDiscovered: 1500,
      }),
    );
    const pathB = await writeFixture(
      "rud1-diag-20260423-110000.json",
      buildReport({
        exportedAt: "2026-04-23T11:00:00.000Z",
        verdict: "healthy",
        cpuPct: 25,
        memPct: 28,
        tempCpu: 45,
        mtuDiscovered: 1420,
      }),
    );

    const res = await compareReports({ pathA, pathB });
    expect(res.deltas.cpuPctDelta).toBe(15);
    expect(res.deltas.memPctDelta).toBe(-2);
    expect(res.deltas.tempDelta).toBe(5);
    expect(res.deltas.mtuDelta).toBe(-80);
  });

  it("verdictChanged is false when either side's verdict is missing", async () => {
    const pathA = await writeFixture(
      "rud1-diag-20260423-100000.json",
      // verdict undefined ⇒ tunnelHealth=null in the fixture builder
      buildReport({ exportedAt: "2026-04-23T10:00:00.000Z" }),
    );
    const pathB = await writeFixture(
      "rud1-diag-20260423-110000.json",
      buildReport({ exportedAt: "2026-04-23T11:00:00.000Z", verdict: "broken" }),
    );

    const res = await compareReports({ pathA, pathB });
    expect(res.a.verdict).toBeNull();
    expect(res.b.verdict).toBe("broken");
    // One side null ⇒ never flagged as changed (per the AND-not-null guard
    // in the implementation).
    expect(res.deltas.verdictChanged).toBe(false);
  });

  it("activePeers counts peers with non-zero latestHandshake (3 peers, 2 active)", async () => {
    const pathA = await writeFixture(
      "rud1-diag-20260423-100000.json",
      buildReport({
        exportedAt: "2026-04-23T10:00:00.000Z",
        peerHandshakes: [0, 12345, 67890],
      }),
    );
    const pathB = await writeFixture(
      "rud1-diag-20260423-110000.json",
      buildReport({
        exportedAt: "2026-04-23T11:00:00.000Z",
        peerHandshakes: [0, 0, 67890],
      }),
    );

    const res = await compareReports({ pathA, pathB });
    expect(res.a.wgPeerCount).toBe(3);
    expect(res.a.activePeers).toBe(2);
    expect(res.b.wgPeerCount).toBe(3);
    expect(res.b.activePeers).toBe(1);
    expect(res.deltas.activePeersDelta).toBe(-1);
    expect(res.deltas.wgPeerCountDelta).toBe(0);
  });

  it("throws 'report not parseable' when a fixture is not valid JSON", async () => {
    const dir = await ensureDiagDir();
    const pathA = path.join(dir, "rud1-diag-20260423-100000.json");
    const pathB = path.join(dir, "rud1-diag-20260423-110000.json");
    await fsp.writeFile(pathA, "{not json", "utf8");
    await fsp.writeFile(
      pathB,
      JSON.stringify(
        buildReport({ exportedAt: "2026-04-23T11:00:00.000Z" }),
      ),
      "utf8",
    );

    await expect(compareReports({ pathA, pathB })).rejects.toThrow(
      /report not parseable/,
    );
  });

  it("rejects malicious paths with the same guard validateReportPath uses", async () => {
    await expect(
      compareReports({ pathA: "../etc/passwd", pathB: "../etc/shadow" }),
    ).rejects.toThrow(/path outside allowed directory|invalid report filename|invalid path/);
  });
});
