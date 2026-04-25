/**
 * Unit tests for the persisted first-boot notification dedupe (iter 27).
 *
 * Tests use real temp directories (`os.tmpdir()` + `mkdtempSync`) rather
 * than mocking `fs` — the iter 25 firmware-discovery tests boot a real
 * http server for the same reason: filesystem behaviour (atomic rename,
 * mkdir -p, ENOENT on missing files) is too easy to get wrong against
 * a mock and works fine against a real tmp dir.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { promises as fsp } from "fs";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import {
  DEDUPE_CAP,
  DEDUPE_TTL_MS,
  addHost,
  enforceCap,
  isHostNotified,
  loadNotifiedHosts,
  pruneExpiredHosts,
  removeHost,
  saveNotifiedHosts,
  type NotifiedHost,
} from "./first-boot-dedupe";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rud1-dedupe-"));
});

afterEach(async () => {
  await fsp.rm(tmpDir, { recursive: true, force: true });
});

function tmpFile(): string {
  return path.join(tmpDir, "first-boot-notifications.json");
}

function iso(offsetMs: number, base = Date.now()): string {
  return new Date(base + offsetMs).toISOString();
}

// ─── pure helpers ─────────────────────────────────────────────────────────

describe("pruneExpiredHosts", () => {
  it("drops entries older than the TTL", () => {
    const now = new Date("2026-04-25T12:00:00Z");
    const hosts: NotifiedHost[] = [
      { host: "old.local", notifiedAt: iso(-(DEDUPE_TTL_MS + 1000), now.getTime()) },
      { host: "fresh.local", notifiedAt: iso(-1000, now.getTime()) },
    ];
    const out = pruneExpiredHosts(hosts, now);
    expect(out.map((h) => h.host)).toEqual(["fresh.local"]);
  });

  it("keeps entries exactly at the TTL boundary", () => {
    const now = new Date("2026-04-25T12:00:00Z");
    const hosts: NotifiedHost[] = [
      { host: "edge.local", notifiedAt: iso(-DEDUPE_TTL_MS, now.getTime()) },
    ];
    expect(pruneExpiredHosts(hosts, now).map((h) => h.host)).toEqual(["edge.local"]);
  });

  it("drops entries with malformed notifiedAt", () => {
    const hosts: NotifiedHost[] = [{ host: "bad.local", notifiedAt: "not-a-date" }];
    expect(pruneExpiredHosts(hosts, new Date())).toEqual([]);
  });
});

describe("enforceCap", () => {
  it("is a no-op below the cap", () => {
    const hosts: NotifiedHost[] = [
      { host: "a", notifiedAt: iso(-100) },
      { host: "b", notifiedAt: iso(-50) },
    ];
    expect(enforceCap(hosts, 5)).toHaveLength(2);
  });

  it("evicts oldest entries by notifiedAt (FIFO)", () => {
    const base = Date.parse("2026-04-25T12:00:00Z");
    const hosts: NotifiedHost[] = [];
    for (let i = 0; i < DEDUPE_CAP + 5; i++) {
      hosts.push({ host: `host-${i}`, notifiedAt: new Date(base + i * 1000).toISOString() });
    }
    const out = enforceCap(hosts);
    expect(out).toHaveLength(DEDUPE_CAP);
    // The 5 oldest (host-0..host-4) should have been evicted; the newest
    // (host-{CAP+4}) should be present.
    expect(out.find((h) => h.host === "host-0")).toBeUndefined();
    expect(out.find((h) => h.host === "host-4")).toBeUndefined();
    expect(out.find((h) => h.host === `host-${DEDUPE_CAP + 4}`)).toBeDefined();
  });
});

describe("addHost", () => {
  it("appends a new host with the current timestamp", () => {
    const now = new Date("2026-04-25T12:00:00Z");
    const out = addHost([], "rud1.local", now);
    expect(out).toEqual([{ host: "rud1.local", notifiedAt: now.toISOString() }]);
  });

  it("refreshes notifiedAt when the host is already present", () => {
    const earlier = new Date("2026-04-01T12:00:00Z");
    const later = new Date("2026-04-25T12:00:00Z");
    const start = addHost([], "rud1.local", earlier);
    const refreshed = addHost(start, "rud1.local", later);
    expect(refreshed).toHaveLength(1);
    expect(refreshed[0].notifiedAt).toBe(later.toISOString());
  });

  it("respects the cap when adding past CAP", () => {
    const base = Date.parse("2026-04-25T12:00:00Z");
    let hosts: NotifiedHost[] = [];
    for (let i = 0; i < DEDUPE_CAP + 10; i++) {
      hosts = addHost(hosts, `h-${i}`, new Date(base + i * 1000));
    }
    expect(hosts).toHaveLength(DEDUPE_CAP);
  });
});

describe("removeHost", () => {
  it("removes the named host", () => {
    const hosts: NotifiedHost[] = [
      { host: "a", notifiedAt: iso(-100) },
      { host: "b", notifiedAt: iso(-100) },
    ];
    expect(removeHost(hosts, "a").map((h) => h.host)).toEqual(["b"]);
  });

  it("is a no-op when the host is absent", () => {
    const hosts: NotifiedHost[] = [{ host: "a", notifiedAt: iso(-100) }];
    expect(removeHost(hosts, "missing")).toHaveLength(1);
  });
});

describe("isHostNotified", () => {
  it("returns true for a host within TTL", () => {
    const now = new Date("2026-04-25T12:00:00Z");
    const hosts: NotifiedHost[] = [
      { host: "rud1.local", notifiedAt: iso(-1000, now.getTime()) },
    ];
    expect(isHostNotified(hosts, "rud1.local", now)).toBe(true);
  });

  it("returns false for a host past TTL", () => {
    const now = new Date("2026-04-25T12:00:00Z");
    const hosts: NotifiedHost[] = [
      { host: "rud1.local", notifiedAt: iso(-(DEDUPE_TTL_MS + 1000), now.getTime()) },
    ];
    expect(isHostNotified(hosts, "rud1.local", now)).toBe(false);
  });

  it("returns false for an unknown host", () => {
    expect(isHostNotified([], "rud1.local", new Date())).toBe(false);
  });
});

// ─── loadNotifiedHosts (real fs) ──────────────────────────────────────────

describe("loadNotifiedHosts", () => {
  it("returns [] when the file is missing (ENOENT)", async () => {
    const out = await loadNotifiedHosts(tmpFile(), new Date());
    expect(out).toEqual([]);
  });

  it("parses a valid file", async () => {
    const now = new Date("2026-04-25T12:00:00Z");
    const data = {
      version: 1,
      notifiedHosts: [{ host: "rud1.local", notifiedAt: iso(-1000, now.getTime()) }],
    };
    await fsp.writeFile(tmpFile(), JSON.stringify(data), "utf8");
    const out = await loadNotifiedHosts(tmpFile(), now);
    expect(out).toHaveLength(1);
    expect(out[0].host).toBe("rud1.local");
  });

  it("returns [] on corrupt JSON without throwing", async () => {
    await fsp.writeFile(tmpFile(), "{not-json", "utf8");
    const out = await loadNotifiedHosts(tmpFile(), new Date());
    expect(out).toEqual([]);
  });

  it("returns [] on wrong version (forward-incompat)", async () => {
    await fsp.writeFile(
      tmpFile(),
      JSON.stringify({ version: 99, notifiedHosts: [] }),
      "utf8",
    );
    expect(await loadNotifiedHosts(tmpFile(), new Date())).toEqual([]);
  });

  it("prunes expired entries on load", async () => {
    const now = new Date("2026-04-25T12:00:00Z");
    const data = {
      version: 1,
      notifiedHosts: [
        { host: "old.local", notifiedAt: iso(-(DEDUPE_TTL_MS + 1000), now.getTime()) },
        { host: "fresh.local", notifiedAt: iso(-1000, now.getTime()) },
      ],
    };
    await fsp.writeFile(tmpFile(), JSON.stringify(data), "utf8");
    const out = await loadNotifiedHosts(tmpFile(), now);
    expect(out.map((h) => h.host)).toEqual(["fresh.local"]);
  });

  it("filters out entries with bad shape", async () => {
    await fsp.writeFile(
      tmpFile(),
      JSON.stringify({
        version: 1,
        notifiedHosts: [
          { host: "ok.local", notifiedAt: new Date().toISOString() },
          { host: 123, notifiedAt: "x" }, // wrong type
          { notifiedAt: "x" },             // missing host
          null,                             // null entry
          { host: "", notifiedAt: "x" },   // empty host
        ],
      }),
      "utf8",
    );
    const out = await loadNotifiedHosts(tmpFile(), new Date());
    expect(out.map((h) => h.host)).toEqual(["ok.local"]);
  });
});

// ─── saveNotifiedHosts (real fs) ──────────────────────────────────────────

describe("saveNotifiedHosts", () => {
  it("writes a valid round-trippable file", async () => {
    const now = new Date("2026-04-25T12:00:00Z");
    const hosts: NotifiedHost[] = [
      { host: "rud1.local", notifiedAt: now.toISOString() },
    ];
    await saveNotifiedHosts(tmpFile(), hosts);
    const reloaded = await loadNotifiedHosts(tmpFile(), now);
    expect(reloaded).toEqual(hosts);
  });

  it("creates the parent directory if missing", async () => {
    const nested = path.join(tmpDir, "deeply", "nested", "first-boot.json");
    const hosts: NotifiedHost[] = [
      { host: "x", notifiedAt: new Date().toISOString() },
    ];
    await saveNotifiedHosts(nested, hosts);
    const stat = await fsp.stat(nested);
    expect(stat.isFile()).toBe(true);
  });

  it("uses atomic tmp+rename (no .tmp file lingering on success)", async () => {
    const target = tmpFile();
    await saveNotifiedHosts(target, [
      { host: "a", notifiedAt: new Date().toISOString() },
    ]);
    // The .tmp must not exist after the rename completes.
    await expect(fsp.access(`${target}.tmp`)).rejects.toThrow();
    await expect(fsp.access(target)).resolves.toBeUndefined();
  });

  it("enforces the cap when persisting", async () => {
    const base = Date.parse("2026-04-25T12:00:00Z");
    const hosts: NotifiedHost[] = [];
    for (let i = 0; i < DEDUPE_CAP + 7; i++) {
      hosts.push({ host: `h-${i}`, notifiedAt: new Date(base + i * 1000).toISOString() });
    }
    await saveNotifiedHosts(tmpFile(), hosts);
    const raw = await fsp.readFile(tmpFile(), "utf8");
    const parsed = JSON.parse(raw) as { notifiedHosts: NotifiedHost[] };
    expect(parsed.notifiedHosts).toHaveLength(DEDUPE_CAP);
    // Newest (h-{CAP+6}) must be present, oldest (h-0) must not.
    expect(parsed.notifiedHosts.find((h) => h.host === "h-0")).toBeUndefined();
    expect(parsed.notifiedHosts.find((h) => h.host === `h-${DEDUPE_CAP + 6}`)).toBeDefined();
  });

  it("does not throw when the destination path is unwritable", async () => {
    // Aim at a path under a non-existent drive letter on Windows or a
    // path with a NUL byte on POSIX — both reliably fail mkdir+write.
    // On Windows, using a path with reserved characters (`*`, `<`) under
    // a tmpdir reliably triggers EINVAL on writeFile.
    const bogus =
      process.platform === "win32"
        ? path.join(tmpDir, "bad<*name", "file.json")
        : path.join(tmpDir, "bad\0name", "file.json");
    await expect(
      saveNotifiedHosts(bogus, [
        { host: "x", notifiedAt: new Date().toISOString() },
      ]),
    ).resolves.toBeUndefined();
  });
});

// ─── falling-edge round trip ──────────────────────────────────────────────

describe("falling-edge persistence round trip", () => {
  it("removes a host from disk when it transitions out of first-boot", async () => {
    const now = new Date("2026-04-25T12:00:00Z");
    const initial: NotifiedHost[] = [
      { host: "rud1.local", notifiedAt: now.toISOString() },
      { host: "192.168.50.1", notifiedAt: now.toISOString() },
    ];
    await saveNotifiedHosts(tmpFile(), initial);

    // Simulate a falling edge for rud1.local — operator finished setup.
    const after = removeHost(
      await loadNotifiedHosts(tmpFile(), now),
      "rud1.local",
    );
    await saveNotifiedHosts(tmpFile(), after);

    const reloaded = await loadNotifiedHosts(tmpFile(), now);
    expect(reloaded.map((h) => h.host)).toEqual(["192.168.50.1"]);
  });

  it("re-notifies the same host after a falling edge + re-rising edge", async () => {
    const now = new Date("2026-04-25T12:00:00Z");
    let hosts = await loadNotifiedHosts(tmpFile(), now);
    expect(isHostNotified(hosts, "rud1.local", now)).toBe(false);

    // Rising edge: notify + persist.
    hosts = addHost(hosts, "rud1.local", now);
    await saveNotifiedHosts(tmpFile(), hosts);

    // Falling edge: remove + persist.
    hosts = removeHost(hosts, "rud1.local");
    await saveNotifiedHosts(tmpFile(), hosts);

    // Same host re-enters first-boot — predicate must say "notify again".
    const reloaded = await loadNotifiedHosts(tmpFile(), now);
    expect(isHostNotified(reloaded, "rud1.local", now)).toBe(false);
  });
});
