import { describe, it, expect } from "vitest";

import {
  VersionCheckManager,
  parseManifest,
  classifyManifest,
  buildVersionCheckMenuItems,
  __test as versionCheckInternals,
  type VersionManifest,
  type VersionCheckState,
} from "./version-check-manager";

const { computeDeviceBucket } = versionCheckInternals;

// Pure-helper unit tests for the iter-29 desktop version check.
// We exercise:
//   • parseManifest      — accepts well-formed JSON, rejects everything
//                          else (no version, garbage version, bad URL).
//   • classifyManifest   — pin newer / equal / older outcomes plus the
//                          "current isn't semver" guard.
//   • VersionCheckManager — single-shot checkOnce against a stub fetch
//                          that returns various manifest shapes; we
//                          assert the state transitions + the listener
//                          contract (including the swallowed throw).
//
// We deliberately do NOT exercise `start()` — its only job is to wire
// `setInterval` around `checkOnce`, which is covered by an integration
// test in the runtime path. Keeping the unit suite synchronous keeps it
// fast and free of fake-timer plumbing.

function jsonResponse(body: unknown, init: ResponseInit = { status: 200 }): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "Content-Type": "application/json" },
  });
}

describe("parseManifest", () => {
  it("accepts a minimal valid manifest (legacy v1, no manifestVersion field)", () => {
    const m = parseManifest({ version: "1.2.3" });
    expect(m).toEqual({
      version: "1.2.3",
      downloadUrl: null,
      manifestVersion: 1,
      sha256: null,
      releaseNotesUrl: null,
      rolloutBucket: null,
    });
  });

  it("preserves a https downloadUrl", () => {
    const m = parseManifest({
      version: "1.2.3",
      downloadUrl: "https://rud1.es/desktop/download",
    });
    expect(m).toEqual({
      version: "1.2.3",
      downloadUrl: "https://rud1.es/desktop/download",
      manifestVersion: 1,
      sha256: null,
      releaseNotesUrl: null,
      rolloutBucket: null,
    });
  });

  it("drops a downloadUrl that fails the feed-url allowlist", () => {
    const m = parseManifest({
      version: "1.2.3",
      downloadUrl: "javascript:alert(1)",
    });
    expect(m).toEqual({
      version: "1.2.3",
      downloadUrl: null,
      manifestVersion: 1,
      sha256: null,
      releaseNotesUrl: null,
      rolloutBucket: null,
    });
  });

  it("rejects when version is missing", () => {
    expect(parseManifest({ downloadUrl: "https://example.test" })).toBeNull();
  });

  it("rejects when version isn't semver", () => {
    expect(parseManifest({ version: "not-a-version" })).toBeNull();
  });

  it("rejects null / non-object input", () => {
    expect(parseManifest(null)).toBeNull();
    expect(parseManifest("a string")).toBeNull();
    expect(parseManifest(42)).toBeNull();
  });
});

// ─── Iter 32 — manifest v2 schema gate ──────────────────────────────────────

describe("parseManifest — manifestVersion + sha256 (iter 32)", () => {
  const VALID_SHA = "a".repeat(64); // 64 lowercase-hex chars, valid shape
  const VALID_SHA_MIXED =
    "ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789";

  it("v2 manifest with valid sha256 → parsed and sha256 lowercased", () => {
    const m = parseManifest({
      version: "1.2.3",
      manifestVersion: 2,
      sha256: VALID_SHA_MIXED,
    });
    expect(m).toEqual({
      version: "1.2.3",
      downloadUrl: null,
      manifestVersion: 2,
      sha256: VALID_SHA_MIXED.toLowerCase(),
      releaseNotesUrl: null,
      rolloutBucket: null,
    });
  });

  it("v2 manifest with downloadUrl + sha256 → both preserved", () => {
    const m = parseManifest({
      version: "1.2.3",
      manifestVersion: 2,
      sha256: VALID_SHA,
      downloadUrl: "https://rud1.es/desktop/download",
    });
    expect(m).toEqual({
      version: "1.2.3",
      downloadUrl: "https://rud1.es/desktop/download",
      manifestVersion: 2,
      sha256: VALID_SHA,
      releaseNotesUrl: null,
      rolloutBucket: null,
    });
  });

  it("v2 manifest missing sha256 → rejected (the whole point of the v2 bump)", () => {
    expect(
      parseManifest({ version: "1.2.3", manifestVersion: 2 }),
    ).toBeNull();
  });

  it("v2 manifest with sha256:null → rejected", () => {
    expect(
      parseManifest({ version: "1.2.3", manifestVersion: 2, sha256: null }),
    ).toBeNull();
  });

  it("v2 manifest with sha256 of wrong length → rejected", () => {
    expect(
      parseManifest({
        version: "1.2.3",
        manifestVersion: 2,
        sha256: "deadbeef", // too short
      }),
    ).toBeNull();
    expect(
      parseManifest({
        version: "1.2.3",
        manifestVersion: 2,
        sha256: "a".repeat(63), // off-by-one short
      }),
    ).toBeNull();
    expect(
      parseManifest({
        version: "1.2.3",
        manifestVersion: 2,
        sha256: "a".repeat(65), // off-by-one long
      }),
    ).toBeNull();
  });

  it("v2 manifest with non-hex sha256 → rejected", () => {
    expect(
      parseManifest({
        version: "1.2.3",
        manifestVersion: 2,
        sha256: "z".repeat(64), // 64 chars but z is non-hex
      }),
    ).toBeNull();
    expect(
      parseManifest({
        version: "1.2.3",
        manifestVersion: 2,
        sha256: "g" + "a".repeat(63), // first char is non-hex
      }),
    ).toBeNull();
  });

  it("v2 manifest with non-string sha256 → rejected", () => {
    expect(
      parseManifest({
        version: "1.2.3",
        manifestVersion: 2,
        sha256: 1234567890,
      }),
    ).toBeNull();
    expect(
      parseManifest({
        version: "1.2.3",
        manifestVersion: 2,
        sha256: { hex: VALID_SHA },
      }),
    ).toBeNull();
  });

  it("v1 explicit manifest without sha256 → parsed (backward compat)", () => {
    const m = parseManifest({ version: "1.2.3", manifestVersion: 1 });
    expect(m).toEqual({
      version: "1.2.3",
      downloadUrl: null,
      manifestVersion: 1,
      sha256: null,
      releaseNotesUrl: null,
      rolloutBucket: null,
    });
  });

  it("v1 explicit manifest WITH sha256 → parsed and sha256 preserved (lowercased)", () => {
    const m = parseManifest({
      version: "1.2.3",
      manifestVersion: 1,
      sha256: VALID_SHA_MIXED,
    });
    expect(m).toEqual({
      version: "1.2.3",
      downloadUrl: null,
      manifestVersion: 1,
      sha256: VALID_SHA_MIXED.toLowerCase(),
      releaseNotesUrl: null,
      rolloutBucket: null,
    });
  });

  it("v1 manifest with malformed sha256 → rejected (we don't silently drop)", () => {
    // Even in v1 a malformed sha256 is a server-side bug we'd rather
    // surface than mask: the operator advertised an integrity claim and
    // the shape is wrong, so refuse to promote to update-available.
    expect(
      parseManifest({ version: "1.2.3", manifestVersion: 1, sha256: "deadbeef" }),
    ).toBeNull();
  });

  it("manifest without manifestVersion field → parsed as v1 (backward compat)", () => {
    const m = parseManifest({ version: "1.2.3" });
    expect(m?.manifestVersion).toBe(1);
    expect(m?.sha256).toBeNull();
  });

  it("manifestVersion as string '2' → rejected (number-only, no coercion)", () => {
    // Documented decision in the iter-32 commit: JSON.parse produces
    // numbers from JSON numbers, so a string-typed manifestVersion is
    // almost always a server-side typo we'd rather fail loudly on.
    expect(
      parseManifest({
        version: "1.2.3",
        manifestVersion: "2",
        sha256: VALID_SHA,
      }),
    ).toBeNull();
  });

  it("manifestVersion as float (e.g. 2.5) → rejected (integer-only)", () => {
    expect(
      parseManifest({
        version: "1.2.3",
        manifestVersion: 2.5,
        sha256: VALID_SHA,
      }),
    ).toBeNull();
  });

  it("manifestVersion as 0 or negative → rejected", () => {
    expect(
      parseManifest({ version: "1.2.3", manifestVersion: 0 }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.2.3", manifestVersion: -1 }),
    ).toBeNull();
  });

  it("manifestVersion as 999 (future) → rejected as unsupported (fail-closed)", () => {
    // We pick "rejected as unsupported" over "treat as latest known"
    // because v3+ may add NEW required fields whose absence from this
    // code path would otherwise be silently ignored.
    expect(
      parseManifest({
        version: "1.2.3",
        manifestVersion: 999,
        sha256: VALID_SHA,
      }),
    ).toBeNull();
    expect(
      parseManifest({
        version: "1.2.3",
        manifestVersion: 3, // first unsupported value above the cap
        sha256: VALID_SHA,
      }),
    ).toBeNull();
  });

  it("releaseNotesUrl https → preserved (iter 33)", () => {
    const m = parseManifest({
      version: "1.2.3",
      releaseNotesUrl: "https://rud1.es/changelog/v1.2.3",
    });
    expect(m?.releaseNotesUrl).toBe("https://rud1.es/changelog/v1.2.3");
  });

  it("releaseNotesUrl with javascript: scheme → silently dropped (iter 33)", () => {
    // Same allowlist as downloadUrl; the changelog URL is a convenience
    // so a malformed one shouldn't reject the whole manifest.
    const m = parseManifest({
      version: "1.2.3",
      downloadUrl: "https://rud1.es/dl",
      releaseNotesUrl: "javascript:alert(1)",
    });
    expect(m).not.toBeNull();
    expect(m?.releaseNotesUrl).toBeNull();
    expect(m?.downloadUrl).toBe("https://rud1.es/dl");
  });

  it("releaseNotesUrl missing or null → null (iter 33)", () => {
    expect(parseManifest({ version: "1.2.3" })?.releaseNotesUrl).toBeNull();
    expect(
      parseManifest({ version: "1.2.3", releaseNotesUrl: null })?.releaseNotesUrl,
    ).toBeNull();
  });

  it("releaseNotesUrl empty string → null (iter 33, silent drop)", () => {
    // Empty string is treated like a missing field — server probably
    // emitted "" as a placeholder; surfacing a "What's new" row that
    // tries to open "" would be worse than hiding the row.
    const m = parseManifest({ version: "1.2.3", releaseNotesUrl: "" });
    expect(m).not.toBeNull();
    expect(m?.releaseNotesUrl).toBeNull();
  });

  it("releaseNotesUrl with non-string type → rejects whole manifest (iter 33)", () => {
    // Wrong-type rejects the whole manifest, mirroring the strictness
    // applied to every other typed field — a server-side bug here is
    // louder than a missing convenience link.
    expect(
      parseManifest({ version: "1.2.3", releaseNotesUrl: 42 }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.2.3", releaseNotesUrl: { url: "x" } }),
    ).toBeNull();
  });

  it("v2 manifest with sha256 + releaseNotesUrl → both preserved (iter 33)", () => {
    const m = parseManifest({
      version: "1.2.3",
      manifestVersion: 2,
      sha256: VALID_SHA,
      downloadUrl: "https://rud1.es/dl",
      releaseNotesUrl: "https://rud1.es/changelog",
    });
    expect(m).toEqual({
      version: "1.2.3",
      downloadUrl: "https://rud1.es/dl",
      manifestVersion: 2,
      sha256: VALID_SHA,
      releaseNotesUrl: "https://rud1.es/changelog",
      rolloutBucket: null,
    });
  });

  it("manifestVersion as NaN / Infinity → rejected", () => {
    expect(
      parseManifest({
        version: "1.2.3",
        manifestVersion: Number.NaN,
        sha256: VALID_SHA,
      }),
    ).toBeNull();
    expect(
      parseManifest({
        version: "1.2.3",
        manifestVersion: Number.POSITIVE_INFINITY,
        sha256: VALID_SHA,
      }),
    ).toBeNull();
  });
});

describe("classifyManifest", () => {
  const NOW = 1_700_000_000_000;
  const m = (version: string, downloadUrl: string | null = null): VersionManifest => ({
    version,
    downloadUrl,
    manifestVersion: 1,
    sha256: null,
    releaseNotesUrl: null,
    rolloutBucket: null,
  });

  it("flags an update when remote > current", () => {
    const out = classifyManifest("1.2.0", m("1.3.0"), NOW);
    expect(out).toEqual({
      kind: "update-available",
      current: "1.2.0",
      latest: "1.3.0",
      downloadUrl: null,
      releaseNotesUrl: null,
      checkedAt: NOW,
    });
  });

  it("preserves the downloadUrl when promoting to update-available", () => {
    const out = classifyManifest(
      "1.2.0",
      m("1.3.0", "https://rud1.es/desktop/download"),
      NOW,
    );
    expect(out.kind).toBe("update-available");
    if (out.kind === "update-available") {
      expect(out.downloadUrl).toBe("https://rud1.es/desktop/download");
    }
  });

  it("returns up-to-date when remote == current", () => {
    const out = classifyManifest("1.2.3", m("1.2.3"), NOW);
    expect(out).toEqual({
      kind: "up-to-date",
      current: "1.2.3",
      latest: "1.2.3",
      checkedAt: NOW,
    });
  });

  it("returns up-to-date when remote < current (downgrade-block)", () => {
    const out = classifyManifest("2.0.0", m("1.9.9"), NOW);
    expect(out.kind).toBe("up-to-date");
  });

  it("errors when the current version is malformed", () => {
    const out = classifyManifest("not-semver", m("1.2.3"), NOW);
    expect(out).toEqual({
      kind: "error",
      message: "current version is not valid semver",
      checkedAt: NOW,
    });
  });
});

describe("VersionCheckManager", () => {
  it("transitions checking → up-to-date on a successful equal-version fetch", async () => {
    const states: string[] = [];
    const mgr = new VersionCheckManager({
      manifestUrl: "https://example.test/manifest.json",
      currentVersion: "1.2.3",
      fetch: async () => jsonResponse({ version: "1.2.3" }),
      onStateChange: (s) => states.push(s.kind),
    });
    const final = await mgr.checkOnce();
    expect(states).toEqual(["checking", "up-to-date"]);
    expect(final.kind).toBe("up-to-date");
  });

  it("flags update-available when remote is newer", async () => {
    const mgr = new VersionCheckManager({
      manifestUrl: "https://example.test/manifest.json",
      currentVersion: "1.2.3",
      fetch: async () =>
        jsonResponse({ version: "1.4.0", downloadUrl: "https://rud1.es/dl" }),
    });
    const final = await mgr.checkOnce();
    expect(final.kind).toBe("update-available");
    if (final.kind === "update-available") {
      expect(final.latest).toBe("1.4.0");
      expect(final.downloadUrl).toBe("https://rud1.es/dl");
    }
  });

  it("transitions to error on a non-2xx response", async () => {
    const mgr = new VersionCheckManager({
      manifestUrl: "https://example.test/manifest.json",
      currentVersion: "1.2.3",
      fetch: async () =>
        new Response("nope", { status: 503, statusText: "Service Unavailable" }),
    });
    const final = await mgr.checkOnce();
    expect(final.kind).toBe("error");
    if (final.kind === "error") {
      expect(final.message).toMatch(/HTTP 503/);
    }
  });

  it("transitions to error on malformed JSON", async () => {
    const mgr = new VersionCheckManager({
      manifestUrl: "https://example.test/manifest.json",
      currentVersion: "1.2.3",
      fetch: async () =>
        new Response("{not json", { status: 200, headers: { "Content-Type": "application/json" } }),
    });
    const final = await mgr.checkOnce();
    expect(final.kind).toBe("error");
    if (final.kind === "error") {
      expect(final.message).toBe("manifest is not valid JSON");
    }
  });

  it("transitions to error on rejected manifest shape (missing version)", async () => {
    const mgr = new VersionCheckManager({
      manifestUrl: "https://example.test/manifest.json",
      currentVersion: "1.2.3",
      fetch: async () => jsonResponse({ note: "no version here" }),
    });
    const final = await mgr.checkOnce();
    expect(final.kind).toBe("error");
    if (final.kind === "error") {
      expect(final.message).toBe("manifest shape rejected");
    }
  });

  it("starts in error when manifestUrl fails the allowlist", async () => {
    const mgr = new VersionCheckManager({
      manifestUrl: "http://insecure.example/manifest.json",
      currentVersion: "1.2.3",
      fetch: async () => jsonResponse({ version: "9.9.9" }),
    });
    const final = await mgr.checkOnce();
    // Critically: we never invoke fetch, so the manager doesn't promote
    // to "checking" — the error stands.
    expect(final.kind).toBe("error");
    if (final.kind === "error") {
      expect(final.message).toBe("invalid manifest URL");
    }
  });

  it("starts in error when currentVersion isn't valid semver", () => {
    const mgr = new VersionCheckManager({
      manifestUrl: "https://example.test/manifest.json",
      currentVersion: "not-semver",
      fetch: async () => jsonResponse({ version: "1.0.0" }),
    });
    expect(mgr.getState().kind).toBe("error");
  });

  it("swallows listener errors so the polling loop survives", async () => {
    const mgr = new VersionCheckManager({
      manifestUrl: "https://example.test/manifest.json",
      currentVersion: "1.2.3",
      fetch: async () => jsonResponse({ version: "1.2.3" }),
      onStateChange: () => {
        throw new Error("listener boom");
      },
    });
    // If the throw weren't swallowed, this would reject and fail the test.
    const final = await mgr.checkOnce();
    expect(final.kind).toBe("up-to-date");
  });
});

// ─── Iter 33 — release notes URL in tray menu ─────────────────────────────────

describe("buildVersionCheckMenuItems — releaseNotesUrl (iter 33)", () => {
  const updateAvailableState = (
    releaseNotesUrl: string | null,
  ): VersionCheckState => ({
    kind: "update-available",
    current: "1.2.3",
    latest: "1.4.0",
    downloadUrl: "https://rud1.es/dl",
    releaseNotesUrl,
    checkedAt: 1_700_000_000_000,
  });

  it("inserts a 'What's new' row above 'Check for updates now' when releaseNotesUrl is set", () => {
    const opens: string[] = [];
    const items = buildVersionCheckMenuItems(
      updateAvailableState("https://rud1.es/changelog/v1.4.0"),
      { openExternal: (u) => opens.push(u) },
    );
    // Expected order: Update available, Currently installed, What's new, Recheck.
    expect(items.map((i) => i.label)).toEqual([
      "▲ Update available — v1.4.0",
      "Currently installed: v1.2.3",
      "What's new — view release notes",
      "Check for updates now",
    ]);

    items[2].click?.();
    expect(opens).toEqual(["https://rud1.es/changelog/v1.4.0"]);
  });

  it("omits the 'What's new' row when releaseNotesUrl is null", () => {
    const items = buildVersionCheckMenuItems(updateAvailableState(null));
    // Same labels as iter-29 baseline — no extra row.
    expect(items.map((i) => i.label)).toEqual([
      "▲ Update available — v1.4.0",
      "Currently installed: v1.2.3",
      "Check for updates now",
    ]);
  });

  it("release notes click opens in the system browser even when auto-update is engaged", () => {
    // Whether or not the operator opted into auto-update, the changelog
    // link is read-only content and must always go through openExternal.
    // (Auto-update only swaps the *Download* row's behaviour.)
    const opens: string[] = [];
    const items = buildVersionCheckMenuItems(
      updateAvailableState("https://rud1.es/changelog/v1.4.0"),
      {
        openExternal: (u) => opens.push(u),
        startDownload: () => {
          throw new Error("releaseNotes click must NOT trigger startDownload");
        },
      },
      // auto-update state engaged but idle
      { kind: "idle" },
    );
    const releaseNotesItem = items.find(
      (i) => i.label === "What's new — view release notes",
    );
    expect(releaseNotesItem).toBeDefined();
    releaseNotesItem?.click?.();
    expect(opens).toEqual(["https://rud1.es/changelog/v1.4.0"]);
  });

  it("up-to-date state does not produce a 'What's new' row", () => {
    // Defensive: changelog URLs are only relevant when an update IS
    // available; the up-to-date state never carries one in our schema.
    const items = buildVersionCheckMenuItems({
      kind: "up-to-date",
      current: "1.2.3",
      latest: "1.2.3",
      checkedAt: 1_700_000_000_000,
    });
    expect(
      items.find((i) => i.label === "What's new — view release notes"),
    ).toBeUndefined();
  });
});

// ─── Iter 34 — staged rollout via rolloutBucket ───────────────────────────────

describe("parseManifest — rolloutBucket (iter 34)", () => {
  it("rolloutBucket integer in [1, 100] → preserved", () => {
    const m = parseManifest({ version: "1.2.3", rolloutBucket: 50 });
    expect(m?.rolloutBucket).toBe(50);
    const lo = parseManifest({ version: "1.2.3", rolloutBucket: 1 });
    expect(lo?.rolloutBucket).toBe(1);
    const hi = parseManifest({ version: "1.2.3", rolloutBucket: 100 });
    expect(hi?.rolloutBucket).toBe(100);
  });

  it("rolloutBucket missing or null → null", () => {
    expect(parseManifest({ version: "1.2.3" })?.rolloutBucket).toBeNull();
    expect(
      parseManifest({ version: "1.2.3", rolloutBucket: null })?.rolloutBucket,
    ).toBeNull();
  });

  it("rolloutBucket of wrong type → rejects whole manifest", () => {
    // String / boolean / object — server-side bug we'd rather surface
    // than mask, mirroring the strictness on every other typed field.
    expect(
      parseManifest({ version: "1.2.3", rolloutBucket: "50" }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.2.3", rolloutBucket: true }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.2.3", rolloutBucket: { pct: 50 } }),
    ).toBeNull();
  });

  it("rolloutBucket out of [1, 100] or non-integer → rejects whole manifest", () => {
    // 0 would silence the entire fleet; 101+ is meaningless. Floats are
    // ambiguous (50.5 → ?). All four reject.
    expect(parseManifest({ version: "1.2.3", rolloutBucket: 0 })).toBeNull();
    expect(parseManifest({ version: "1.2.3", rolloutBucket: 101 })).toBeNull();
    expect(parseManifest({ version: "1.2.3", rolloutBucket: -5 })).toBeNull();
    expect(parseManifest({ version: "1.2.3", rolloutBucket: 50.5 })).toBeNull();
    expect(
      parseManifest({ version: "1.2.3", rolloutBucket: Number.NaN }),
    ).toBeNull();
    expect(
      parseManifest({
        version: "1.2.3",
        rolloutBucket: Number.POSITIVE_INFINITY,
      }),
    ).toBeNull();
  });
});

describe("computeDeviceBucket (iter 34)", () => {
  it("is stable across calls for the same installation ID", () => {
    const id = "rud1-desktop:host-fixture";
    const a = computeDeviceBucket(id);
    const b = computeDeviceBucket(id);
    const c = computeDeviceBucket(id);
    expect(a).toBe(b);
    expect(b).toBe(c);
    expect(a).toBeGreaterThanOrEqual(1);
    expect(a).toBeLessThanOrEqual(100);
  });

  it("distributes roughly uniformly across [1, 100] for varied IDs", () => {
    // 1000 distinct installation IDs should cover most of the bucket
    // space. We don't pin exact counts (sha256 mod 100 isn't perfectly
    // uniform on a finite sample); we just confirm the spread covers
    // the full range, sits inside [1, 100], and isn't clumped into a
    // single bucket.
    const buckets = new Set<number>();
    let min = 101;
    let max = 0;
    for (let i = 0; i < 1000; i++) {
      const b = computeDeviceBucket(`fixture-${i}`);
      expect(b).toBeGreaterThanOrEqual(1);
      expect(b).toBeLessThanOrEqual(100);
      buckets.add(b);
      if (b < min) min = b;
      if (b > max) max = b;
    }
    // Reasonable diversity: at least 80 of the 100 buckets hit out of
    // 1000 trials, and the range spans at least 1..100 within a few
    // buckets at each end.
    expect(buckets.size).toBeGreaterThanOrEqual(80);
    expect(min).toBeLessThanOrEqual(5);
    expect(max).toBeGreaterThanOrEqual(96);
  });

  it("wraps with mod 100 + 1 so output is always in [1, 100], never 0 or 101", () => {
    // Probe a deterministic spread of inputs and confirm the +1 offset
    // is applied (we never hit 0) and the modulo cap holds (we never
    // hit 101). Edge inputs include the empty string, very long
    // strings, and high-entropy hex strings.
    const probes = [
      "",
      "a",
      "abcdefghijklmnopqrstuvwxyz",
      "0".repeat(1024),
      "ff".repeat(64),
      "rud1-desktop:" + "x".repeat(10_000),
    ];
    for (const p of probes) {
      const b = computeDeviceBucket(p);
      expect(b).toBeGreaterThanOrEqual(1);
      expect(b).toBeLessThanOrEqual(100);
      expect(Number.isInteger(b)).toBe(true);
    }
  });
});

describe("classifyManifest — rolloutBucket suppression (iter 34)", () => {
  const NOW = 1_700_000_000_000;
  const m = (version: string, rolloutBucket: number | null = null): VersionManifest => ({
    version,
    downloadUrl: "https://rud1.es/dl",
    manifestVersion: 2,
    sha256: "a".repeat(64),
    releaseNotesUrl: null,
    rolloutBucket,
  });

  it("eligible bucket (deviceBucket <= rolloutBucket) → update-available", () => {
    const out = classifyManifest("1.2.0", m("1.3.0", 50), NOW, 25);
    expect(out.kind).toBe("update-available");
    if (out.kind === "update-available") {
      expect(out.latest).toBe("1.3.0");
    }
  });

  it("ineligible bucket (deviceBucket > rolloutBucket) → up-to-date despite newer version", () => {
    // The whole point of staged rollouts: a newer manifest exists, but
    // this device hasn't been picked yet, so we silently report up-to-date.
    const out = classifyManifest("1.2.0", m("1.3.0", 50), NOW, 75);
    expect(out.kind).toBe("up-to-date");
    if (out.kind === "up-to-date") {
      expect(out.latest).toBe("1.3.0");
      expect(out.current).toBe("1.2.0");
    }
  });

  it("no rolloutBucket → newer version always classified as update-available", () => {
    // Even an unlikely deviceBucket=100 still gets the update when the
    // manifest doesn't gate the rollout.
    const out = classifyManifest("1.2.0", m("1.3.0", null), NOW, 100);
    expect(out.kind).toBe("update-available");
  });

  it("boundary: deviceBucket == rolloutBucket → eligible (inclusive lower edge)", () => {
    const out = classifyManifest("1.2.0", m("1.3.0", 42), NOW, 42);
    expect(out.kind).toBe("update-available");
  });
});
