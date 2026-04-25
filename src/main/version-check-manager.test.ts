import { describe, it, expect } from "vitest";

import {
  VersionCheckManager,
  parseManifest,
  classifyManifest,
  buildVersionCheckMenuItems,
  formatBlockedStateMessage,
  formatVersionCheckSummary,
  pickDownloadUrl,
  isBridgeDownloadUrlAllowed,
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
      minBootstrapVersion: null,
      bridgeDownloadUrl: null,
      bridgeSha256: null,
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
      minBootstrapVersion: null,
      bridgeDownloadUrl: null,
      bridgeSha256: null,
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
      minBootstrapVersion: null,
      bridgeDownloadUrl: null,
      bridgeSha256: null,
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
      minBootstrapVersion: null,
      bridgeDownloadUrl: null,
      bridgeSha256: null,
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
      minBootstrapVersion: null,
      bridgeDownloadUrl: null,
      bridgeSha256: null,
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
      minBootstrapVersion: null,
      bridgeDownloadUrl: null,
      bridgeSha256: null,
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
      minBootstrapVersion: null,
      bridgeDownloadUrl: null,
      bridgeSha256: null,
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
      minBootstrapVersion: null,
      bridgeDownloadUrl: null,
      bridgeSha256: null,
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
    minBootstrapVersion: null,
    bridgeDownloadUrl: null,
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
    minBootstrapVersion: null,
    bridgeDownloadUrl: null,
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

// ─── classifyManifest — forceRollout override (iter 35) ───────────────────
//
// `forceRollout=true` bypasses the iter-34 bucket comparison so a tester
// running with `RUD1_DESKTOP_ROLLOUT_FORCE=1` (or persisted-config
// `rolloutForce: true`) sees `update-available` regardless of bucket.
// Default (false) preserves iter-34 behaviour exactly.

describe("classifyManifest — forceRollout override (iter 35)", () => {
  const NOW = 1_700_000_000_000;
  const m = (version: string, rolloutBucket: number | null = null): VersionManifest => ({
    version,
    downloadUrl: "https://rud1.es/dl",
    manifestVersion: 2,
    sha256: "a".repeat(64),
    releaseNotesUrl: null,
    rolloutBucket,
    minBootstrapVersion: null,
    bridgeDownloadUrl: null,
  });

  it("ineligible bucket BUT forceRollout=true → update-available", () => {
    // Same fixture as the iter-34 "ineligible bucket → up-to-date" test
    // but with the iter-35 force flag set. Without the flag this would
    // be `up-to-date`; with it we see the update.
    const out = classifyManifest("1.2.0", m("1.3.0", 50), NOW, 75, true);
    expect(out.kind).toBe("update-available");
    if (out.kind === "update-available") {
      expect(out.latest).toBe("1.3.0");
      expect(out.downloadUrl).toBe("https://rud1.es/dl");
    }
  });

  it("forceRollout=true is a no-op when the bucket would have allowed the update", () => {
    // No state change for in-bucket devices — the override is purely
    // additive and never demotes an eligible device to up-to-date.
    const out = classifyManifest("1.2.0", m("1.3.0", 50), NOW, 25, true);
    expect(out.kind).toBe("update-available");
  });

  it("forceRollout=true does NOT promote an older/equal version", () => {
    // The version-comparison gate runs before the bucket gate; the
    // override only bypasses bucket suppression. A same-version
    // manifest still resolves to up-to-date.
    const sameVer = classifyManifest("1.3.0", m("1.3.0", 50), NOW, 75, true);
    expect(sameVer.kind).toBe("up-to-date");
    const olderVer = classifyManifest("1.4.0", m("1.3.0", 50), NOW, 75, true);
    expect(olderVer.kind).toBe("up-to-date");
  });

  it("forceRollout=false (the default) preserves iter-34 suppression behaviour", () => {
    // Explicit-default + omitted-default both suppress the update for
    // an out-of-bucket device, so the iter-34 contract is unchanged.
    const explicit = classifyManifest("1.2.0", m("1.3.0", 50), NOW, 75, false);
    expect(explicit.kind).toBe("up-to-date");
    const omitted = classifyManifest("1.2.0", m("1.3.0", 50), NOW, 75);
    expect(omitted.kind).toBe("up-to-date");
  });

  it("forceRollout=true with a missing rolloutBucket is identical to no-bucket behaviour", () => {
    // Manifest without a bucket already ships to everyone; the override
    // shouldn't change the outcome.
    const out = classifyManifest("1.2.0", m("1.3.0", null), NOW, 100, true);
    expect(out.kind).toBe("update-available");
  });

  it("forceRollout=true with no deviceBucket → update-available (override still applies)", () => {
    // Defensive: if installId was omitted (deviceBucket undefined), the
    // bucket check was already disabled; the override should remain a
    // no-op rather than introduce surprising new behaviour.
    const out = classifyManifest("1.2.0", m("1.3.0", 50), NOW, undefined, true);
    expect(out.kind).toBe("update-available");
  });
});

// ─── VersionCheckManager — forceRollout predicate wiring (iter 35) ─────────

describe("VersionCheckManager forceRollout predicate (iter 35)", () => {
  function manifest(rolloutBucket: number | null): unknown {
    return {
      version: "9.9.9",
      downloadUrl: "https://rud1.es/dl",
      manifestVersion: 2,
      sha256: "a".repeat(64),
      releaseNotesUrl: null,
      rolloutBucket,
    };
  }

  it("re-evaluates the predicate on every checkOnce (no caching)", async () => {
    const calls: boolean[] = [];
    let force = false;
    const fakeFetch: typeof globalThis.fetch = async () => jsonResponse(manifest(50));
    const states: VersionCheckState[] = [];
    const mgr = new VersionCheckManager({
      manifestUrl: "https://example.com/m.json",
      currentVersion: "1.0.0",
      // installId chosen so deviceBucket is > 50 (suppressed without force).
      installId: "rud1-fixture-out-of-bucket",
      fetch: fakeFetch,
      forceRollout: () => {
        calls.push(force);
        return force;
      },
      onStateChange: (s) => states.push(s),
    });

    // Find an installId whose bucket is > 50 so the suppression actually fires.
    // (We hop to a fixture in the existing computeDeviceBucket-stable suite if
    //  needed, but the default `rud1-fixture-out-of-bucket` is checked first.)
    const bucket = computeDeviceBucket("rud1-fixture-out-of-bucket");
    if (bucket <= 50) {
      // Fall through: pick any other deterministic ID that maps high.
      // We try a few until we find one >50. Test stays deterministic
      // because computeDeviceBucket is sha256-based.
      let id = "x-0";
      for (let i = 0; i < 200; i++) {
        if (computeDeviceBucket(`x-${i}`) > 50) { id = `x-${i}`; break; }
      }
      // Rebuild the manager with the high-bucket id.
      const mgr2 = new VersionCheckManager({
        manifestUrl: "https://example.com/m.json",
        currentVersion: "1.0.0",
        installId: id,
        fetch: fakeFetch,
        forceRollout: () => {
          calls.push(force);
          return force;
        },
        onStateChange: (s) => states.push(s),
      });
      await mgr2.checkOnce();
      const last = states.at(-1);
      expect(last?.kind).toBe("up-to-date"); // suppressed
      // Now flip the override and re-check; the same fetch result should now
      // resolve to update-available.
      force = true;
      await mgr2.checkOnce();
      const after = states.at(-1);
      expect(after?.kind).toBe("update-available");
      // Predicate consulted on every fetch.
      expect(calls.length).toBeGreaterThanOrEqual(2);
      return;
    }

    // The default ID happened to land out-of-bucket — use the original mgr.
    await mgr.checkOnce();
    expect(states.at(-1)?.kind).toBe("up-to-date");
    force = true;
    await mgr.checkOnce();
    expect(states.at(-1)?.kind).toBe("update-available");
    expect(calls.length).toBeGreaterThanOrEqual(2);
  });

  it("a throwing predicate degrades to forceRollout=false (does not break the loop)", async () => {
    const fakeFetch: typeof globalThis.fetch = async () => jsonResponse(manifest(50));
    // Pick a deterministic out-of-bucket id.
    let id = "y-0";
    for (let i = 0; i < 200; i++) {
      if (computeDeviceBucket(`y-${i}`) > 50) { id = `y-${i}`; break; }
    }
    const states: VersionCheckState[] = [];
    const mgr = new VersionCheckManager({
      manifestUrl: "https://example.com/m.json",
      currentVersion: "1.0.0",
      installId: id,
      fetch: fakeFetch,
      forceRollout: () => { throw new Error("fs read failed"); },
      onStateChange: (s) => states.push(s),
    });
    await mgr.checkOnce();
    // Suppression still fires because the throw collapses to false.
    expect(states.at(-1)?.kind).toBe("up-to-date");
  });
});

// ─── Iter 36 — minBootstrapVersion staged-migration gate ─────────────────────
//
// The manifest may now advertise a `minBootstrapVersion` indicating the
// lowest currently-installed desktop release that may auto-update directly
// to `version`. Devices below the anchor are blocked: the operator must
// install an intermediate bridge build by hand. The blocked state is a
// distinct VersionCheckState variant (not just an "error") so the tray
// menu can render an actionable label and still surface the changelog.
//
// Scope:
//   • parseManifest — accept-valid / missing→null / null→null /
//                     empty-string→reject / non-string→reject /
//                     malformed-shape→reject; v1 + v2 both accept the field.
//   • compareSemver — identity / simple ordering / shorter-prefix.
//   • classifyManifest — blocks when current < min, allows when current ≥
//     min, allows when min absent, composes with sha256+rolloutBucket+strict.
//   • buildVersionCheckMenuItems — blocked-state row labels.

const { compareSemver: compareSemverInternal, MIN_BOOTSTRAP_VERSION_SHAPE } =
  versionCheckInternals;

describe("parseManifest — minBootstrapVersion (iter 36)", () => {
  const VALID_SHA = "a".repeat(64);

  it("v1 manifest with valid minBootstrapVersion → preserved", () => {
    const m = parseManifest({
      version: "1.5.0",
      minBootstrapVersion: "1.2.0",
    });
    expect(m).toEqual({
      version: "1.5.0",
      downloadUrl: null,
      manifestVersion: 1,
      sha256: null,
      releaseNotesUrl: null,
      rolloutBucket: null,
      minBootstrapVersion: "1.2.0",
      bridgeDownloadUrl: null,
      bridgeSha256: null,
    });
  });

  it("v2 manifest with valid minBootstrapVersion → preserved", () => {
    const m = parseManifest({
      version: "1.5.0",
      manifestVersion: 2,
      sha256: VALID_SHA,
      minBootstrapVersion: "1.2.0",
    });
    expect(m).toEqual({
      version: "1.5.0",
      downloadUrl: null,
      manifestVersion: 2,
      sha256: VALID_SHA,
      releaseNotesUrl: null,
      rolloutBucket: null,
      minBootstrapVersion: "1.2.0",
      bridgeDownloadUrl: null,
      bridgeSha256: null,
    });
  });

  it("manifest with prerelease-shaped minBootstrapVersion → preserved", () => {
    // The shape regex is anchored on the MAJOR.MINOR.PATCH triplet so
    // prerelease/build suffixes pass through to parseSemver, which
    // accepts them per the iter-21 RFC implementation.
    const m = parseManifest({
      version: "2.0.0",
      minBootstrapVersion: "1.2.0-rc.1",
    });
    expect(m?.minBootstrapVersion).toBe("1.2.0-rc.1");
  });

  it("missing field → null (behaviour unchanged)", () => {
    const m = parseManifest({ version: "1.5.0" });
    expect(m?.minBootstrapVersion).toBeNull();
  });

  it("explicit null → null (behaviour unchanged)", () => {
    const m = parseManifest({ version: "1.5.0", minBootstrapVersion: null });
    expect(m?.minBootstrapVersion).toBeNull();
  });

  it("explicit undefined → null (behaviour unchanged)", () => {
    const m = parseManifest({
      version: "1.5.0",
      minBootstrapVersion: undefined,
    });
    expect(m?.minBootstrapVersion).toBeNull();
  });

  it("empty string → rejects whole manifest", () => {
    expect(
      parseManifest({ version: "1.5.0", minBootstrapVersion: "" }),
    ).toBeNull();
  });

  it("non-string types → rejects whole manifest", () => {
    expect(
      parseManifest({ version: "1.5.0", minBootstrapVersion: 1 }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.5.0", minBootstrapVersion: 1.2 }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.5.0", minBootstrapVersion: true }),
    ).toBeNull();
    expect(
      parseManifest({
        version: "1.5.0",
        minBootstrapVersion: { major: 1, minor: 2, patch: 0 },
      }),
    ).toBeNull();
    expect(
      parseManifest({
        version: "1.5.0",
        minBootstrapVersion: ["1", "2", "0"],
      }),
    ).toBeNull();
  });

  it("malformed shape (`not-semver` / `1.2` / `1.2.3.4-`) → rejects whole manifest", () => {
    expect(
      parseManifest({
        version: "1.5.0",
        minBootstrapVersion: "not-semver",
      }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.5.0", minBootstrapVersion: "1.2" }),
    ).toBeNull();
    expect(
      parseManifest({
        version: "1.5.0",
        minBootstrapVersion: "1.2.3.4-",
      }),
    ).toBeNull();
    // Leading whitespace breaks the anchored shape regex.
    expect(
      parseManifest({ version: "1.5.0", minBootstrapVersion: " 1.2.3" }),
    ).toBeNull();
  });

  it("malformed minBootstrapVersion in v2 manifest → rejects whole manifest", () => {
    // Compose with the v2 sha256 requirement: the shape failure is
    // hit BEFORE we'd get to surface a sha256 issue, but the rejection
    // is the same — the whole manifest goes away.
    expect(
      parseManifest({
        version: "1.5.0",
        manifestVersion: 2,
        sha256: VALID_SHA,
        minBootstrapVersion: "1.2",
      }),
    ).toBeNull();
  });

  it("MIN_BOOTSTRAP_VERSION_SHAPE matches anchored MAJOR.MINOR.PATCH only", () => {
    // Pin the regex so a future refactor that loosens the shape (e.g.
    // permits `v` prefix or trailing whitespace) trips a test rather
    // than silently changing the gate.
    expect(MIN_BOOTSTRAP_VERSION_SHAPE.test("1.2.3")).toBe(true);
    expect(MIN_BOOTSTRAP_VERSION_SHAPE.test("1.2.3-rc.1")).toBe(true);
    expect(MIN_BOOTSTRAP_VERSION_SHAPE.test("0.0.0")).toBe(true);
    expect(MIN_BOOTSTRAP_VERSION_SHAPE.test("1.2")).toBe(false);
    expect(MIN_BOOTSTRAP_VERSION_SHAPE.test("v1.2.3")).toBe(false);
    expect(MIN_BOOTSTRAP_VERSION_SHAPE.test("not-semver")).toBe(false);
    expect(MIN_BOOTSTRAP_VERSION_SHAPE.test(" 1.2.3")).toBe(false);
    expect(MIN_BOOTSTRAP_VERSION_SHAPE.test("")).toBe(false);
  });
});

describe("compareSemver (iter 36)", () => {
  // The helper lives in auto-updater.ts and is re-exported through the
  // version-check-manager __test hatch so the staged-migration suite can
  // pin its semantics without reaching across files.

  it("identity: equal versions return 0", () => {
    const a = { major: 1, minor: 2, patch: 3, prerelease: "" };
    const b = { major: 1, minor: 2, patch: 3, prerelease: "" };
    expect(compareSemverInternal(a, b)).toBe(0);
  });

  it("simple ordering: lower < higher per axis", () => {
    const lower = { major: 1, minor: 2, patch: 3, prerelease: "" };
    const higherMajor = { major: 2, minor: 0, patch: 0, prerelease: "" };
    const higherMinor = { major: 1, minor: 3, patch: 0, prerelease: "" };
    const higherPatch = { major: 1, minor: 2, patch: 4, prerelease: "" };
    expect(compareSemverInternal(lower, higherMajor)).toBeLessThan(0);
    expect(compareSemverInternal(lower, higherMinor)).toBeLessThan(0);
    expect(compareSemverInternal(lower, higherPatch)).toBeLessThan(0);
    expect(compareSemverInternal(higherMajor, lower)).toBeGreaterThan(0);
    expect(compareSemverInternal(higherMinor, lower)).toBeGreaterThan(0);
    expect(compareSemverInternal(higherPatch, lower)).toBeGreaterThan(0);
  });

  it("length differences: 1.0 vs 1.0.0 — short form rejected by parseManifest", () => {
    // The iter-21 parser refuses `1.0` outright (parseManifest returns
    // null for any version that doesn't match MAJOR.MINOR.PATCH), so
    // the gate's behaviour on a "shorter" semver string is "reject the
    // whole manifest" — exercised here via parseManifest to pin the
    // contract that a length mismatch never silently coerces.
    expect(parseManifest({ version: "1.0" })).toBeNull();
    // A canonical `1.0.0` round-trips equal under the helper.
    const eq = compareSemverInternal(
      { major: 1, minor: 0, patch: 0, prerelease: "" },
      { major: 1, minor: 0, patch: 0, prerelease: "" },
    );
    expect(eq).toBe(0);
  });

  it("prerelease ranks below the matching release", () => {
    const release = { major: 1, minor: 2, patch: 0, prerelease: "" };
    const pre = { major: 1, minor: 2, patch: 0, prerelease: "rc.1" };
    expect(compareSemverInternal(pre, release)).toBeLessThan(0);
    expect(compareSemverInternal(release, pre)).toBeGreaterThan(0);
  });
});

describe("classifyManifest — minBootstrapVersion gate (iter 36)", () => {
  const NOW = 1_700_000_000_000;
  const m = (
    overrides: Partial<VersionManifest> & { version: string },
  ): VersionManifest => ({
    downloadUrl: "https://rud1.es/dl",
    manifestVersion: 1,
    sha256: null,
    releaseNotesUrl: null,
    rolloutBucket: null,
    minBootstrapVersion: null,
    bridgeDownloadUrl: null,
    ...overrides,
  });

  it("blocks when current < minBootstrapVersion (current=1.0.0, min=1.2.0, target=1.5.0)", () => {
    const out = classifyManifest(
      "1.0.0",
      m({ version: "1.5.0", minBootstrapVersion: "1.2.0" }),
      NOW,
    );
    expect(out.kind).toBe("update-blocked-by-min-bootstrap");
    if (out.kind === "update-blocked-by-min-bootstrap") {
      expect(out.requiredMinVersion).toBe("1.2.0");
      expect(out.currentVersion).toBe("1.0.0");
      expect(out.targetVersion).toBe("1.5.0");
      expect(out.checkedAt).toBe(NOW);
    }
  });

  it("allows when current == minBootstrapVersion (boundary, inclusive)", () => {
    // current >= min is allowed — only strictly less is blocked.
    const out = classifyManifest(
      "1.2.0",
      m({ version: "1.5.0", minBootstrapVersion: "1.2.0" }),
      NOW,
    );
    expect(out.kind).toBe("update-available");
  });

  it("allows when current > minBootstrapVersion", () => {
    const out = classifyManifest(
      "1.3.0",
      m({ version: "1.5.0", minBootstrapVersion: "1.2.0" }),
      NOW,
    );
    expect(out.kind).toBe("update-available");
  });

  it("allows when minBootstrapVersion is absent (null)", () => {
    const out = classifyManifest(
      "1.0.0",
      m({ version: "1.5.0", minBootstrapVersion: null }),
      NOW,
    );
    expect(out.kind).toBe("update-available");
  });

  it("blocked state preserves releaseNotesUrl so 'What's new' still works", () => {
    const out = classifyManifest(
      "1.0.0",
      m({
        version: "1.5.0",
        minBootstrapVersion: "1.2.0",
        releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
      }),
      NOW,
    );
    expect(out.kind).toBe("update-blocked-by-min-bootstrap");
    if (out.kind === "update-blocked-by-min-bootstrap") {
      expect(out.releaseNotesUrl).toBe(
        "https://rud1.es/changelog/v1.5.0",
      );
    }
  });

  it("never blocks an up-to-date device (remote == current)", () => {
    // The version-comparison gate runs FIRST; min-bootstrap is only
    // consulted on the path that would have promoted to update-available.
    const out = classifyManifest(
      "1.5.0",
      m({ version: "1.5.0", minBootstrapVersion: "9.9.9" }),
      NOW,
    );
    expect(out.kind).toBe("up-to-date");
  });

  it("composes with sha256 (v2): blocked even when sha256 is valid", () => {
    // The block fires at classify time; the artifact's sha256 is only
    // checked at apply time. So a v2 manifest with a perfectly valid
    // sha256 still blocks an out-of-bootstrap device — the operator
    // never even gets to download.
    const out = classifyManifest(
      "1.0.0",
      m({
        version: "1.5.0",
        manifestVersion: 2,
        sha256: "b".repeat(64),
        minBootstrapVersion: "1.2.0",
      }),
      NOW,
    );
    expect(out.kind).toBe("update-blocked-by-min-bootstrap");
  });

  it("composes with rolloutBucket: out-of-bucket suppression wins (silent up-to-date)", () => {
    // Iter-34 contract: an out-of-bucket device classifies silently as
    // up-to-date. The min-bootstrap gate runs AFTER that suppression so
    // the operator never sees a "blocked" row for a manifest they were
    // never going to receive anyway.
    const out = classifyManifest(
      "1.0.0",
      m({
        version: "1.5.0",
        rolloutBucket: 50,
        minBootstrapVersion: "1.2.0",
      }),
      NOW,
      75, // deviceBucket > 50 → suppressed
    );
    expect(out.kind).toBe("up-to-date");
  });

  it("composes with rolloutBucket: in-bucket device still hits the block", () => {
    const out = classifyManifest(
      "1.0.0",
      m({
        version: "1.5.0",
        rolloutBucket: 50,
        minBootstrapVersion: "1.2.0",
      }),
      NOW,
      25, // deviceBucket <= 50 → eligible
    );
    expect(out.kind).toBe("update-blocked-by-min-bootstrap");
  });

  it("composes with forceRollout (iter 35): override unblocks bucket but block still fires", () => {
    // forceRollout=true bypasses the bucket gate; the min-bootstrap
    // gate is independent and still trips for an out-of-bootstrap
    // device. A tester who flipped the rollout-force flag still can't
    // jump a staged-migration anchor.
    const out = classifyManifest(
      "1.0.0",
      m({
        version: "1.5.0",
        rolloutBucket: 50,
        minBootstrapVersion: "1.2.0",
      }),
      NOW,
      75,
      true,
    );
    expect(out.kind).toBe("update-blocked-by-min-bootstrap");
  });

  it("composes with sha256 + rolloutBucket + min-bootstrap: in-bucket v2 still blocks", () => {
    // The kitchen-sink case the spec asks for explicitly: every gate
    // would otherwise pass except the staged-migration anchor.
    const out = classifyManifest(
      "1.0.0",
      m({
        version: "1.5.0",
        manifestVersion: 2,
        sha256: "c".repeat(64),
        rolloutBucket: 50,
        minBootstrapVersion: "1.2.0",
      }),
      NOW,
      25, // in-bucket
    );
    expect(out.kind).toBe("update-blocked-by-min-bootstrap");
    if (out.kind === "update-blocked-by-min-bootstrap") {
      expect(out.requiredMinVersion).toBe("1.2.0");
      expect(out.targetVersion).toBe("1.5.0");
    }
  });
});

describe("buildVersionCheckMenuItems — blocked-by-min-bootstrap (iter 36)", () => {
  const blockedState = (
    releaseNotesUrl: string | null = null,
  ): VersionCheckState => ({
    kind: "update-blocked-by-min-bootstrap",
    requiredMinVersion: "1.2.0",
    currentVersion: "1.0.0",
    targetVersion: "1.5.0",
    releaseNotesUrl,
    bridgeDownloadUrl: null,
    checkedAt: 1_700_000_000_000,
  });

  it("renders a clear blocked-state row label calling for a manual install", () => {
    const items = buildVersionCheckMenuItems(blockedState());
    expect(items[0].label).toBe(
      "Update requires manual install: download v1.2.0 first",
    );
    expect(items[0].enabled).toBe(false);
  });

  it("includes Currently installed + Target version informational rows", () => {
    const items = buildVersionCheckMenuItems(blockedState());
    expect(items.map((i) => i.label)).toEqual([
      "Update requires manual install: download v1.2.0 first",
      "Currently installed: v1.0.0",
      "Target version: v1.5.0",
      "Check for updates now",
    ]);
  });

  it("renders the 'What's new' row when releaseNotesUrl is set", () => {
    const opens: string[] = [];
    const items = buildVersionCheckMenuItems(
      blockedState("https://rud1.es/changelog/v1.5.0"),
      { openExternal: (u) => opens.push(u) },
    );
    expect(items.map((i) => i.label)).toEqual([
      "Update requires manual install: download v1.2.0 first",
      "Currently installed: v1.0.0",
      "Target version: v1.5.0",
      "What's new — view release notes",
      "Check for updates now",
    ]);
    // Click on "What's new" opens the changelog in the system browser.
    items[3].click?.();
    expect(opens).toEqual(["https://rud1.es/changelog/v1.5.0"]);
  });

  it("the recheck row triggers handlers.recheck", () => {
    let rechecks = 0;
    const items = buildVersionCheckMenuItems(blockedState(), {
      recheck: () => {
        rechecks += 1;
      },
    });
    items.at(-1)?.click?.();
    expect(rechecks).toBe(1);
  });

  it("does NOT trigger startDownload even when auto-update flow is engaged", () => {
    // The whole point of the blocked state: no auto-update download is
    // attempted. The download row is replaced with a disabled label,
    // and there's no clickable update-available entry to mis-route.
    const items = buildVersionCheckMenuItems(
      blockedState("https://rud1.es/changelog/v1.5.0"),
      {
        startDownload: () => {
          throw new Error("startDownload must NOT fire in blocked state");
        },
      },
      { kind: "idle" }, // auto-update engaged but idle
    );
    // None of the items should attempt a download click. We just
    // exercise every click target to confirm.
    for (const it of items) {
      it.click?.();
    }
    // (No exception thrown ⇒ test passes.)
    expect(items[0].enabled).toBe(false);
  });
});

// ─── Iter 37 — Settings/About panel formatters ──────────────────────────────
//
// `formatBlockedStateMessage` is the headline addition: it renders the iter-36
// `update-blocked-by-min-bootstrap` verdict into structured copy that the
// data-URL Settings panel consumes. Pinning the operator-facing strings here
// catches regressions ("Update blocked" vs "Download v… first") that would
// otherwise only surface on a manual smoke test of the panel.
//
// `formatVersionCheckSummary` is the corresponding one-liner for the four
// non-blocked verdicts; tested via a single each-branch sweep.

describe("formatBlockedStateMessage (iter 37)", () => {
  const mkBlocked = (
    overrides: Partial<{
      requiredMinVersion: string;
      currentVersion: string;
      targetVersion: string;
      releaseNotesUrl: string | null;
    }> = {},
  ): VersionCheckState & { kind: "update-blocked-by-min-bootstrap" } => ({
    kind: "update-blocked-by-min-bootstrap",
    requiredMinVersion: overrides.requiredMinVersion ?? "1.2.0",
    currentVersion: overrides.currentVersion ?? "1.0.0",
    targetVersion: overrides.targetVersion ?? "1.5.0",
    releaseNotesUrl: overrides.releaseNotesUrl ?? null,
    bridgeDownloadUrl: null,
    checkedAt: 1_700_000_000_000,
  });

  it("formats the call-to-action banner with the required min version", () => {
    const msg = formatBlockedStateMessage(mkBlocked());
    expect(msg.banner).toBe(
      "Download v1.2.0 manually first to continue receiving updates",
    );
  });

  it("preserves the install/target version pair as caption rows", () => {
    const msg = formatBlockedStateMessage(mkBlocked());
    expect(msg.currentLine).toBe("Currently installed: v1.0.0");
    expect(msg.targetLine).toBe("Target: v1.5.0");
  });

  it("passes through the optional releaseNotesUrl when present", () => {
    const msg = formatBlockedStateMessage(
      mkBlocked({ releaseNotesUrl: "https://rud1.es/changelog/v1.5.0" }),
    );
    expect(msg.releaseNotesUrl).toBe("https://rud1.es/changelog/v1.5.0");
  });

  it("returns null releaseNotesUrl when absent (no fallback fabrication)", () => {
    const msg = formatBlockedStateMessage(mkBlocked({ releaseNotesUrl: null }));
    expect(msg.releaseNotesUrl).toBeNull();
  });

  it("the download-hint is anchored to the requiredMinVersion (used for the clipboard button hover)", () => {
    const msg = formatBlockedStateMessage(
      mkBlocked({ requiredMinVersion: "2.0.0-rc.1" }),
    );
    expect(msg.downloadHint).toContain("v2.0.0-rc.1");
  });

  it("escapes nothing — pure string concatenation, the renderer handles HTML escaping", () => {
    // Defensive: confirms the formatter does NOT pre-escape. If a future
    // edit accidentally adds HTML escaping here, the renderer's own
    // escape() would double-encode and the operator would see literal
    // `&lt;` in the banner. Pinning the raw shape avoids that drift.
    const msg = formatBlockedStateMessage(
      mkBlocked({ requiredMinVersion: "1.2.0<script>" }),
    );
    expect(msg.banner).toContain("<script>");
  });
});

describe("formatVersionCheckSummary (iter 37)", () => {
  it("idle → 'Update check has not run yet.'", () => {
    expect(formatVersionCheckSummary({ kind: "idle" })).toBe(
      "Update check has not run yet.",
    );
  });

  it("checking → 'Checking for updates…'", () => {
    expect(formatVersionCheckSummary({ kind: "checking" })).toBe(
      "Checking for updates…",
    );
  });

  it("up-to-date → 'Up to date (vN.N.N).'", () => {
    expect(
      formatVersionCheckSummary({
        kind: "up-to-date",
        current: "1.4.2",
        latest: "1.4.2",
        checkedAt: 0,
      }),
    ).toBe("Up to date (v1.4.2).");
  });

  it("update-available → carries both current and latest", () => {
    expect(
      formatVersionCheckSummary({
        kind: "update-available",
        current: "1.0.0",
        latest: "1.5.0",
        downloadUrl: null,
        releaseNotesUrl: null,
        checkedAt: 0,
      }),
    ).toBe("Update available — v1.5.0 (currently v1.0.0).");
  });

  it("update-blocked-by-min-bootstrap → leads with the required intermediate", () => {
    expect(
      formatVersionCheckSummary({
        kind: "update-blocked-by-min-bootstrap",
        requiredMinVersion: "1.2.0",
        currentVersion: "1.0.0",
        targetVersion: "1.5.0",
        releaseNotesUrl: null,
        bridgeDownloadUrl: null,
        checkedAt: 0,
      }),
    ).toBe("Update blocked: install v1.2.0 manually first.");
  });

  it("error → carries the upstream message verbatim", () => {
    expect(
      formatVersionCheckSummary({
        kind: "error",
        message: "manifest HTTP 502",
        checkedAt: 0,
      }),
    ).toBe("Couldn't check for updates: manifest HTTP 502");
  });
});

// ─── Iter 37 — VersionCheckManager.getState() snapshot ──────────────────────
//
// The iter-37 IPC channel `versionCheck:state` reads the live state via
// the manager's `getState()` method. The method existed pre-iter-37 (added
// in iter 29) but its contract — "always returns the latest transition,
// including the iter-36 blocked variant" — is now load-bearing for the
// Settings/About panel. Pinning the round-trip here guards against a
// regression that would silently downgrade the panel to a stale view.

describe("VersionCheckManager.getState() — iter 37 snapshot contract", () => {
  function jsonRes(body: unknown, init: ResponseInit = { status: 200 }): Response {
    return new Response(JSON.stringify(body), {
      ...init,
      headers: { "Content-Type": "application/json" },
    });
  }

  it("returns idle before checkOnce runs", () => {
    const mgr = new VersionCheckManager({
      manifestUrl: "https://rud1.es/manifest.json",
      currentVersion: "1.0.0",
      fetch: async () => new Response("{}"),
    });
    expect(mgr.getState()).toEqual({ kind: "idle" });
  });

  it("returns the live update-blocked-by-min-bootstrap verdict after a successful check", async () => {
    const mgr = new VersionCheckManager({
      manifestUrl: "https://rud1.es/manifest.json",
      currentVersion: "1.0.0",
      fetch: async () =>
        jsonRes({
          version: "1.5.0",
          minBootstrapVersion: "1.2.0",
          downloadUrl: "https://rud1.es/desktop/download",
        }),
    });
    await mgr.checkOnce();
    const s = mgr.getState();
    expect(s.kind).toBe("update-blocked-by-min-bootstrap");
    if (s.kind === "update-blocked-by-min-bootstrap") {
      expect(s.requiredMinVersion).toBe("1.2.0");
      expect(s.currentVersion).toBe("1.0.0");
      expect(s.targetVersion).toBe("1.5.0");
    }
  });

  it("getState() and the onStateChange callback observe the same state object", async () => {
    let observed: VersionCheckState | null = null;
    const mgr = new VersionCheckManager({
      manifestUrl: "https://rud1.es/manifest.json",
      currentVersion: "1.0.0",
      fetch: async () =>
        jsonRes({
          version: "1.5.0",
          minBootstrapVersion: "1.2.0",
        }),
      onStateChange: (s) => {
        // Capture only the final transition (we expect 'checking' then
        // the verdict). The contract under test is that the `getState()`
        // snapshot at end-of-await matches what the listener saw.
        if (s.kind === "update-blocked-by-min-bootstrap") observed = s;
      },
    });
    await mgr.checkOnce();
    expect(observed).not.toBeNull();
    expect(mgr.getState()).toEqual(observed);
  });
});

// ─── Iter 38 — bridgeDownloadUrl optional v2 extension ──────────────────────
//
// The Settings/About panel's "Copy download URL" button now prefers a
// manifest-supplied bridge build URL over the iter-37 fallbacks. This
// section pins:
//   • parseManifest accepts and preserves bridgeDownloadUrl when present
//     and valid; missing field still parses; allowlist failures silently
//     drop the field; wrong-type values reject the whole manifest.
//   • isBridgeDownloadUrlAllowed rejects javascript:/data:/file: schemes,
//     URLs with userinfo, and CRLF-injected URLs.
//   • pickDownloadUrl returns the bridge URL first, releaseNotesUrl
//     second, synthesized fallback third — matching the documented
//     precedence chain.

describe("parseManifest — bridgeDownloadUrl (iter 38)", () => {
  const VALID_SHA = "a".repeat(64);

  it("v1 manifest with valid bridgeDownloadUrl → preserved", () => {
    const m = parseManifest({
      version: "1.5.0",
      minBootstrapVersion: "1.2.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/v1.2.0",
    });
    expect(m?.bridgeDownloadUrl).toBe(
      "https://rud1.es/desktop/bridge/v1.2.0",
    );
  });

  it("v2 manifest with valid bridgeDownloadUrl → preserved", () => {
    const m = parseManifest({
      version: "1.5.0",
      manifestVersion: 2,
      sha256: VALID_SHA,
      minBootstrapVersion: "1.2.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/v1.2.0",
    });
    expect(m?.bridgeDownloadUrl).toBe(
      "https://rud1.es/desktop/bridge/v1.2.0",
    );
  });

  it("missing field → null (optional, behaviour unchanged)", () => {
    const m = parseManifest({ version: "1.5.0" });
    expect(m?.bridgeDownloadUrl).toBeNull();
  });

  it("explicit null → null", () => {
    const m = parseManifest({ version: "1.5.0", bridgeDownloadUrl: null });
    expect(m?.bridgeDownloadUrl).toBeNull();
  });

  it("javascript: URL → silently dropped (manifest still parses)", () => {
    const m = parseManifest({
      version: "1.5.0",
      bridgeDownloadUrl: "javascript:alert(1)",
    });
    expect(m).not.toBeNull();
    expect(m?.bridgeDownloadUrl).toBeNull();
  });

  it("data: / file: URLs → silently dropped", () => {
    expect(
      parseManifest({
        version: "1.5.0",
        bridgeDownloadUrl: "data:text/plain,hello",
      })?.bridgeDownloadUrl,
    ).toBeNull();
    expect(
      parseManifest({
        version: "1.5.0",
        bridgeDownloadUrl: "file:///etc/passwd",
      })?.bridgeDownloadUrl,
    ).toBeNull();
  });

  it("http:// URL → silently dropped (https-only allowlist)", () => {
    expect(
      parseManifest({
        version: "1.5.0",
        bridgeDownloadUrl: "http://rud1.es/dl",
      })?.bridgeDownloadUrl,
    ).toBeNull();
  });

  it("URL with userinfo → silently dropped", () => {
    expect(
      parseManifest({
        version: "1.5.0",
        bridgeDownloadUrl: "https://user:pass@rud1.es/dl",
      })?.bridgeDownloadUrl,
    ).toBeNull();
  });

  it("URL with CRLF / control chars → silently dropped", () => {
    expect(
      parseManifest({
        version: "1.5.0",
        bridgeDownloadUrl: "https://rud1.es/dl\r\nSet-Cookie:evil",
      })?.bridgeDownloadUrl,
    ).toBeNull();
  });

  it("non-string types → rejects whole manifest", () => {
    expect(
      parseManifest({ version: "1.5.0", bridgeDownloadUrl: 42 }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.5.0", bridgeDownloadUrl: true }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.5.0", bridgeDownloadUrl: { url: "x" } }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.5.0", bridgeDownloadUrl: ["x"] }),
    ).toBeNull();
  });

  it("classifyManifest threads bridgeDownloadUrl into the blocked state", () => {
    const out = classifyManifest(
      "1.0.0",
      {
        version: "1.5.0",
        downloadUrl: "https://rud1.es/dl",
        manifestVersion: 1,
        sha256: null,
        releaseNotesUrl: null,
        rolloutBucket: null,
        minBootstrapVersion: "1.2.0",
        bridgeDownloadUrl: "https://rud1.es/desktop/bridge/v1.2.0",
      },
      1_700_000_000_000,
    );
    expect(out.kind).toBe("update-blocked-by-min-bootstrap");
    if (out.kind === "update-blocked-by-min-bootstrap") {
      expect(out.bridgeDownloadUrl).toBe(
        "https://rud1.es/desktop/bridge/v1.2.0",
      );
    }
  });
});

describe("isBridgeDownloadUrlAllowed (iter 38)", () => {
  it("accepts a plain https URL", () => {
    expect(
      isBridgeDownloadUrlAllowed("https://rud1.es/desktop/bridge/v1.2.0"),
    ).toBe(true);
  });

  it("rejects http:// (https-only)", () => {
    expect(isBridgeDownloadUrlAllowed("http://rud1.es/dl")).toBe(false);
  });

  it("rejects javascript: / data: / file:", () => {
    expect(isBridgeDownloadUrlAllowed("javascript:alert(1)")).toBe(false);
    expect(isBridgeDownloadUrlAllowed("data:text/plain,hello")).toBe(false);
    expect(isBridgeDownloadUrlAllowed("file:///etc/passwd")).toBe(false);
  });

  it("rejects userinfo components", () => {
    expect(
      isBridgeDownloadUrlAllowed("https://user@rud1.es/dl"),
    ).toBe(false);
    expect(
      isBridgeDownloadUrlAllowed("https://user:pw@rud1.es/dl"),
    ).toBe(false);
  });

  it("rejects CRLF / control chars in the raw URL", () => {
    expect(
      isBridgeDownloadUrlAllowed("https://rud1.es/dl\r\nSet-Cookie:x"),
    ).toBe(false);
    expect(
      isBridgeDownloadUrlAllowed("https://rud1.es/ dl"),
    ).toBe(false);
  });

  it("rejects non-string / empty / over-cap inputs", () => {
    expect(isBridgeDownloadUrlAllowed(undefined)).toBe(false);
    expect(isBridgeDownloadUrlAllowed(null)).toBe(false);
    expect(isBridgeDownloadUrlAllowed(42)).toBe(false);
    expect(isBridgeDownloadUrlAllowed("")).toBe(false);
    expect(
      isBridgeDownloadUrlAllowed("https://rud1.es/" + "x".repeat(2050)),
    ).toBe(false);
  });
});

describe("pickDownloadUrl (iter 38)", () => {
  it("returns bridgeDownloadUrl when valid (precedence #1)", () => {
    const url = pickDownloadUrl({
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/v1.2.0",
      releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
      requiredMinVersion: "1.2.0",
    });
    expect(url).toBe("https://rud1.es/desktop/bridge/v1.2.0");
  });

  it("falls back to releaseNotesUrl when bridge URL fails the allowlist", () => {
    const url = pickDownloadUrl({
      bridgeDownloadUrl: "javascript:alert(1)",
      releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
      requiredMinVersion: "1.2.0",
    });
    expect(url).toBe("https://rud1.es/changelog/v1.5.0");
  });

  it("falls back to releaseNotesUrl when bridgeDownloadUrl is absent", () => {
    const url = pickDownloadUrl({
      bridgeDownloadUrl: null,
      releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
      requiredMinVersion: "1.2.0",
    });
    expect(url).toBe("https://rud1.es/changelog/v1.5.0");
  });

  it("falls back to synthesized URL when both bridge and releaseNotes are absent", () => {
    const url = pickDownloadUrl({
      bridgeDownloadUrl: null,
      releaseNotesUrl: null,
      requiredMinVersion: "1.2.0",
    });
    expect(url).toBe("https://rud1.es/desktop/download?version=1.2.0");
  });

  it("synthesized URL percent-encodes the requiredMinVersion query value", () => {
    // Defensive: a prerelease tag that includes `+` (build metadata) must
    // round-trip through encodeURIComponent so the query is parseable.
    const url = pickDownloadUrl({
      bridgeDownloadUrl: null,
      releaseNotesUrl: null,
      requiredMinVersion: "2.0.0-rc.1+sha.abc",
    });
    expect(url).toBe(
      "https://rud1.es/desktop/download?version=2.0.0-rc.1%2Bsha.abc",
    );
  });

  it("rejects userinfo bridge URL → falls through (does NOT leak credentials to clipboard)", () => {
    const url = pickDownloadUrl({
      bridgeDownloadUrl: "https://attacker@rud1.es/dl",
      releaseNotesUrl: null,
      requiredMinVersion: "1.2.0",
    });
    expect(url).toBe("https://rud1.es/desktop/download?version=1.2.0");
  });
});

// ─── Iter 38 — Settings panel pin: state.bridgeDownloadUrl is the copied URL ─
//
// The renderer in `index.ts` mirrors `pickDownloadUrl` inline (the panel
// loads from a data: URL and can't import the helper). This pin tests the
// shared contract via `pickDownloadUrl` itself, which is the source of
// truth — a regression there flips the renderer's behaviour too.

describe("Settings panel — Copy download URL precedence (iter 38)", () => {
  it("when state has a valid bridgeDownloadUrl, that is what gets copied", () => {
    const state: VersionCheckState = {
      kind: "update-blocked-by-min-bootstrap",
      requiredMinVersion: "1.2.0",
      currentVersion: "1.0.0",
      targetVersion: "1.5.0",
      releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/v1.2.0",
      checkedAt: 0,
    };
    expect(pickDownloadUrl(state)).toBe(
      "https://rud1.es/desktop/bridge/v1.2.0",
    );
  });
});

// ─── Iter 39 — bridgeDownloadUrls map (per-minBootstrapVersion) ──────────────
//
// Promotes the iter-38 scalar bridgeDownloadUrl to a keyed map so a
// fleet manifest can ship one document and still route every device to
// the right bootstrap installer. The scalar stays as a fallback for
// unkeyed manifests; the keyed lookup wins ONLY when an exact match
// exists for the device's `requiredMinVersion`.

describe("parseManifest — bridgeDownloadUrls map (iter 39)", () => {
  it("preserves a fully valid 3-key map", () => {
    const m = parseManifest({
      version: "1.5.0",
      bridgeDownloadUrls: {
        "1.0.0": "https://rud1.es/desktop/bridge/v1.0.0",
        "1.2.0": "https://rud1.es/desktop/bridge/v1.2.0",
        "1.4.1": "https://rud1.es/desktop/bridge/v1.4.1",
      },
    });
    expect(m).not.toBeNull();
    expect(m?.bridgeDownloadUrls).toEqual({
      "1.0.0": "https://rud1.es/desktop/bridge/v1.0.0",
      "1.2.0": "https://rud1.es/desktop/bridge/v1.2.0",
      "1.4.1": "https://rud1.es/desktop/bridge/v1.4.1",
    });
  });

  it("drops only the entry with an invalid URL value, retains the others", () => {
    const m = parseManifest({
      version: "1.5.0",
      bridgeDownloadUrls: {
        "1.0.0": "https://rud1.es/desktop/bridge/v1.0.0",
        "1.2.0": "javascript:alert(1)", // bad — silently dropped
        "1.4.1": "https://rud1.es/desktop/bridge/v1.4.1",
      },
    });
    expect(m).not.toBeNull();
    expect(m?.bridgeDownloadUrls).toEqual({
      "1.0.0": "https://rud1.es/desktop/bridge/v1.0.0",
      "1.4.1": "https://rud1.es/desktop/bridge/v1.4.1",
    });
  });

  it("drops only the entry whose key is not semver-shaped, retains the others", () => {
    const m = parseManifest({
      version: "1.5.0",
      bridgeDownloadUrls: {
        "1.0.0": "https://rud1.es/desktop/bridge/v1.0.0",
        "not-a-version": "https://rud1.es/desktop/bridge/x", // bad key — dropped
        "1.4.1": "https://rud1.es/desktop/bridge/v1.4.1",
      },
    });
    expect(m).not.toBeNull();
    expect(m?.bridgeDownloadUrls).toEqual({
      "1.0.0": "https://rud1.es/desktop/bridge/v1.0.0",
      "1.4.1": "https://rud1.es/desktop/bridge/v1.4.1",
    });
  });

  it("rejects the whole manifest when bridgeDownloadUrls is the wrong TYPE (string)", () => {
    expect(
      parseManifest({
        version: "1.5.0",
        bridgeDownloadUrls: "https://rud1.es/desktop/bridge/v1.2.0",
      }),
    ).toBeNull();
  });

  it("rejects the whole manifest when bridgeDownloadUrls is an array", () => {
    // Arrays are typeof 'object' but semantically the wrong shape — a
    // server-side typo we'd rather surface than silently mask.
    expect(
      parseManifest({
        version: "1.5.0",
        bridgeDownloadUrls: ["1.0.0", "https://rud1.es/desktop/bridge/v1.0.0"],
      }),
    ).toBeNull();
  });

  it("empty map → coerced to undefined (not an empty {} on the parsed shape)", () => {
    const m = parseManifest({
      version: "1.5.0",
      bridgeDownloadUrls: {},
    });
    expect(m).not.toBeNull();
    expect(m?.bridgeDownloadUrls).toBeUndefined();
  });

  it("map where every entry fails validation → coerced to undefined (post-filter empty)", () => {
    const m = parseManifest({
      version: "1.5.0",
      bridgeDownloadUrls: {
        "1.2.0": "javascript:alert(1)",       // bad URL
        "not-a-version": "https://rud1.es/x", // bad key
        "1.0.0": 42,                          // bad value type
      },
    });
    expect(m).not.toBeNull();
    expect(m?.bridgeDownloadUrls).toBeUndefined();
  });

  it("missing field → undefined (back-compat with iter-38 scalar-only manifests)", () => {
    const m = parseManifest({
      version: "1.5.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/v1.2.0",
    });
    expect(m?.bridgeDownloadUrls).toBeUndefined();
    expect(m?.bridgeDownloadUrl).toBe("https://rud1.es/desktop/bridge/v1.2.0");
  });

  it("classifyManifest threads bridgeDownloadUrls into the blocked state", () => {
    const out = classifyManifest(
      "1.0.0",
      {
        version: "1.5.0",
        downloadUrl: null,
        manifestVersion: 1,
        sha256: null,
        releaseNotesUrl: null,
        rolloutBucket: null,
        minBootstrapVersion: "1.2.0",
        bridgeDownloadUrl: null,
        bridgeDownloadUrls: {
          "1.2.0": "https://rud1.es/desktop/bridge/v1.2.0",
        },
      },
      1_700_000_000_000,
    );
    expect(out.kind).toBe("update-blocked-by-min-bootstrap");
    if (out.kind === "update-blocked-by-min-bootstrap") {
      expect(out.bridgeDownloadUrls).toEqual({
        "1.2.0": "https://rud1.es/desktop/bridge/v1.2.0",
      });
    }
  });
});

describe("pickDownloadUrl — keyed precedence (iter 39)", () => {
  it("keyed map match wins over the iter-38 scalar bridgeDownloadUrl", () => {
    const url = pickDownloadUrl({
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/scalar",
      bridgeDownloadUrls: {
        "1.2.0": "https://rud1.es/desktop/bridge/keyed-1.2.0",
        "1.0.0": "https://rud1.es/desktop/bridge/keyed-1.0.0",
      },
      releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
      requiredMinVersion: "1.2.0",
    });
    expect(url).toBe("https://rud1.es/desktop/bridge/keyed-1.2.0");
  });

  it("no keyed match → falls through to the iter-38 scalar bridgeDownloadUrl", () => {
    // Map is present but no entry matches `requiredMinVersion`; the
    // scalar must still win over releaseNotes/synthesized.
    const url = pickDownloadUrl({
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/scalar",
      bridgeDownloadUrls: {
        "1.0.0": "https://rud1.es/desktop/bridge/keyed-1.0.0",
        "1.4.1": "https://rud1.es/desktop/bridge/keyed-1.4.1",
      },
      releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
      requiredMinVersion: "1.2.0",
    });
    expect(url).toBe("https://rud1.es/desktop/bridge/scalar");
  });

  it("keyed match present but no scalar → keyed still wins", () => {
    const url = pickDownloadUrl({
      bridgeDownloadUrl: null,
      bridgeDownloadUrls: {
        "1.2.0": "https://rud1.es/desktop/bridge/keyed-1.2.0",
      },
      releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
      requiredMinVersion: "1.2.0",
    });
    expect(url).toBe("https://rud1.es/desktop/bridge/keyed-1.2.0");
  });

  it("no keyed match AND no scalar → falls through to releaseNotesUrl", () => {
    const url = pickDownloadUrl({
      bridgeDownloadUrl: null,
      bridgeDownloadUrls: {
        "1.4.1": "https://rud1.es/desktop/bridge/keyed-1.4.1",
      },
      releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
      requiredMinVersion: "1.2.0",
    });
    expect(url).toBe("https://rud1.es/changelog/v1.5.0");
  });

  it("keyed value that fails the allowlist → defensive fall-through to scalar", () => {
    // Defensive: a hand-constructed state object that bypasses
    // parse-time validation should not leak an unsafe URL through the
    // keyed branch. The scalar wins instead.
    const url = pickDownloadUrl({
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/scalar",
      bridgeDownloadUrls: {
        "1.2.0": "javascript:alert(1)",
      },
      releaseNotesUrl: null,
      requiredMinVersion: "1.2.0",
    });
    expect(url).toBe("https://rud1.es/desktop/bridge/scalar");
  });

  it("undefined map (iter-38 scalar-only manifest) → behaves exactly like iter 38", () => {
    const url = pickDownloadUrl({
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/scalar",
      releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
      requiredMinVersion: "1.2.0",
    });
    expect(url).toBe("https://rud1.es/desktop/bridge/scalar");
  });
});

describe("Settings panel — Copy download URL precedence (iter 39)", () => {
  it("keyed manifest copies the keyed URL, NOT the scalar", () => {
    const state: VersionCheckState = {
      kind: "update-blocked-by-min-bootstrap",
      requiredMinVersion: "1.2.0",
      currentVersion: "1.0.0",
      targetVersion: "1.5.0",
      releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/scalar",
      bridgeDownloadUrls: {
        "1.2.0": "https://rud1.es/desktop/bridge/keyed-1.2.0",
      },
      checkedAt: 0,
    };
    expect(pickDownloadUrl(state)).toBe(
      "https://rud1.es/desktop/bridge/keyed-1.2.0",
    );
  });

  it("regression: iter-38 scalar-only state still copies the scalar URL", () => {
    // Backwards-compat pin: a manifest written before iter-39 (no map
    // at all) must still flow through the precedence chain unchanged.
    const state: VersionCheckState = {
      kind: "update-blocked-by-min-bootstrap",
      requiredMinVersion: "1.2.0",
      currentVersion: "1.0.0",
      targetVersion: "1.5.0",
      releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/scalar",
      checkedAt: 0,
    };
    expect(pickDownloadUrl(state)).toBe(
      "https://rud1.es/desktop/bridge/scalar",
    );
  });
});

// ─── Iter 40 — manifest bridgeSha256 integrity field ───────────────────────

describe("parseManifest — bridgeSha256 (iter 40)", () => {
  const VALID_SHA = "a".repeat(64);
  const VALID_BRIDGE_SHA = "b".repeat(64);
  const VALID_BRIDGE_SHA_MIXED =
    "ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789";

  it("v1 manifest with valid bridgeSha256 → preserved (lowercased)", () => {
    const m = parseManifest({
      version: "1.5.0",
      minBootstrapVersion: "1.2.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge",
      bridgeSha256: VALID_BRIDGE_SHA_MIXED,
    });
    expect(m).not.toBeNull();
    expect(m?.bridgeSha256).toBe(VALID_BRIDGE_SHA_MIXED.toLowerCase());
  });

  it("v2 manifest with valid bridgeSha256 → preserved (lowercased)", () => {
    const m = parseManifest({
      version: "1.5.0",
      manifestVersion: 2,
      sha256: VALID_SHA,
      minBootstrapVersion: "1.2.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge",
      bridgeSha256: VALID_BRIDGE_SHA,
    });
    expect(m?.bridgeSha256).toBe(VALID_BRIDGE_SHA);
  });

  it("missing field → null (optional, default behaviour preserved)", () => {
    const m = parseManifest({ version: "1.5.0" });
    expect(m?.bridgeSha256).toBeNull();
  });

  it("explicit null → null (no integrity claim, current default)", () => {
    const m = parseManifest({ version: "1.5.0", bridgeSha256: null });
    expect(m?.bridgeSha256).toBeNull();
  });

  it("non-string bridgeSha256 → REJECT whole manifest (loud-fail)", () => {
    expect(
      parseManifest({ version: "1.5.0", bridgeSha256: 1234567890 }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.5.0", bridgeSha256: { hex: VALID_BRIDGE_SHA } }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.5.0", bridgeSha256: [VALID_BRIDGE_SHA] }),
    ).toBeNull();
  });

  it("wrong-length bridgeSha256 → REJECT whole manifest", () => {
    expect(
      parseManifest({ version: "1.5.0", bridgeSha256: "deadbeef" }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.5.0", bridgeSha256: "a".repeat(63) }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.5.0", bridgeSha256: "a".repeat(65) }),
    ).toBeNull();
  });

  it("non-hex bridgeSha256 → REJECT whole manifest", () => {
    expect(
      parseManifest({ version: "1.5.0", bridgeSha256: "z".repeat(64) }),
    ).toBeNull();
    expect(
      parseManifest({ version: "1.5.0", bridgeSha256: "g" + "a".repeat(63) }),
    ).toBeNull();
  });

  it("bridgeSha256 + bridgeDownloadUrl + minBootstrapVersion all coexist", () => {
    const m = parseManifest({
      version: "1.5.0",
      manifestVersion: 2,
      sha256: VALID_SHA,
      minBootstrapVersion: "1.2.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/v1.2.0",
      bridgeSha256: VALID_BRIDGE_SHA,
    });
    expect(m).not.toBeNull();
    expect(m?.bridgeDownloadUrl).toBe(
      "https://rud1.es/desktop/bridge/v1.2.0",
    );
    expect(m?.bridgeSha256).toBe(VALID_BRIDGE_SHA);
    expect(m?.minBootstrapVersion).toBe("1.2.0");
  });

  it("bridgeSha256 without bridgeDownloadUrl → still preserved (forward-compat)", () => {
    // The hash is independent of the URL: a manifest may carry a hash
    // even if the URL ships in a sibling map (bridgeDownloadUrls) or
    // arrives via a different channel entirely. We don't try to
    // cross-validate at parse time.
    const m = parseManifest({
      version: "1.5.0",
      bridgeSha256: VALID_BRIDGE_SHA,
    });
    expect(m?.bridgeSha256).toBe(VALID_BRIDGE_SHA);
    expect(m?.bridgeDownloadUrl).toBeNull();
  });
});

// ─── Iter 40 — classifyManifest threads bridgeSha256 into blocked state ────

describe("classifyManifest — bridgeSha256 in blocked state (iter 40)", () => {
  const VALID_BRIDGE_SHA = "c".repeat(64);

  it("update-blocked state surfaces bridgeSha256 from the manifest", () => {
    const manifest = parseManifest({
      version: "1.5.0",
      minBootstrapVersion: "1.2.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/v1.2.0",
      bridgeSha256: VALID_BRIDGE_SHA,
    });
    expect(manifest).not.toBeNull();
    const state = classifyManifest("1.0.0", manifest!, 1700000000);
    if (state.kind !== "update-blocked-by-min-bootstrap") {
      throw new Error(`expected blocked state, got ${state.kind}`);
    }
    expect(state.bridgeSha256).toBe(VALID_BRIDGE_SHA);
    expect(state.bridgeDownloadUrl).toBe(
      "https://rud1.es/desktop/bridge/v1.2.0",
    );
  });

  it("update-blocked state has bridgeSha256=null when manifest omits it", () => {
    const manifest = parseManifest({
      version: "1.5.0",
      minBootstrapVersion: "1.2.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/v1.2.0",
    });
    expect(manifest).not.toBeNull();
    const state = classifyManifest("1.0.0", manifest!, 1700000000);
    if (state.kind !== "update-blocked-by-min-bootstrap") {
      throw new Error(`expected blocked state, got ${state.kind}`);
    }
    expect(state.bridgeSha256).toBeNull();
  });
});

// ─── Iter 41 — bridgeSha256 surfacing in Settings panel ─────────────────────
//
// `formatBlockedHashHint` is the pure helper the iter-41 panel JS mirrors
// when surfacing the optional integrity claim from `bridgeSha256`. We pin
// three behaviours:
//   1. valid hex preserved (lowercased), with the matching shell-recipe
//      strings the panel renders into the verification tooltip;
//   2. absent / null state.bridgeSha256 → null, no recipe suggested;
//   3. wrong-shape state.bridgeSha256 (non-hex, wrong length, non-string)
//      → null. Defensive: even though parseManifest already gates on
//      SHA256_HEX_REGEX, a hand-built state object (test fixture, IPC
//      round-trip) cannot smuggle a malformed hex into the panel.
//
// The HTML fragment builder `buildBlockedPanelHashFragment` is then pinned
// against the markup the renderer concatenates inline; tests assert the
// presence of `<code class="hash">` + "Copy expected sha256" when sha256
// is set, and confirm all three pieces are empty strings when absent.

const { formatBlockedHashHint, buildBlockedPanelHashFragment } = versionCheckInternals;

describe("formatBlockedHashHint (iter 41)", () => {
  const VALID_BRIDGE_SHA = "b".repeat(64);
  const VALID_BRIDGE_SHA_MIXED =
    "ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789";

  it("present: preserves the hex (lowercased) and exposes the verification recipes", () => {
    const hint = formatBlockedHashHint({ bridgeSha256: VALID_BRIDGE_SHA_MIXED });
    expect(hint).not.toBeNull();
    expect(hint?.hex).toBe(VALID_BRIDGE_SHA_MIXED.toLowerCase());
    // The recipes use a `<file>` placeholder rather than hardcoding an
    // installer path — operator substitutes their actual download path.
    expect(hint?.getFileHashCmd).toBe("Get-FileHash -Algorithm SHA256 <file>");
    expect(hint?.shasumCmd).toBe("shasum -a 256 <file>");
  });

  it("absent: returns null when bridgeSha256 is null / undefined / empty", () => {
    expect(formatBlockedHashHint({ bridgeSha256: null })).toBeNull();
    expect(formatBlockedHashHint({})).toBeNull();
    expect(formatBlockedHashHint({ bridgeSha256: undefined })).toBeNull();
  });

  it("wrong-shape: rejects non-string / wrong-length / non-hex inputs (defensive even though parse gates)", () => {
    // Defensive re-validation — a future caller that bypassed
    // parseManifest (hand-built fixture, IPC round-trip from a
    // misbehaving renderer) cannot leak a malformed hex into the panel.
    expect(formatBlockedHashHint({ bridgeSha256: 1234 as unknown as string })).toBeNull();
    expect(formatBlockedHashHint({ bridgeSha256: "deadbeef" })).toBeNull(); // too short
    expect(formatBlockedHashHint({ bridgeSha256: "a".repeat(63) })).toBeNull();
    expect(formatBlockedHashHint({ bridgeSha256: "a".repeat(65) })).toBeNull();
    expect(formatBlockedHashHint({ bridgeSha256: "z".repeat(64) })).toBeNull();
    expect(formatBlockedHashHint({ bridgeSha256: "g" + "a".repeat(63) })).toBeNull();
  });
});

describe("buildBlockedPanelHashFragment HTML pin (iter 41)", () => {
  const VALID_BRIDGE_SHA = "c".repeat(64);

  it("with sha256 → row with <code class=\"hash\"> visible + 'Copy expected sha256' button", () => {
    const frag = buildBlockedPanelHashFragment({ bridgeSha256: VALID_BRIDGE_SHA });
    // Row contains the code.hash element with the lowercased hex.
    expect(frag.row).toContain('<code class="hash" id="bridge-hash">');
    expect(frag.row).toContain(VALID_BRIDGE_SHA);
    expect(frag.row).toContain('Expected SHA-256');
    // Button copy + aria-describedby anchor for the verification tooltip.
    expect(frag.button).toContain('id="copy-hash"');
    expect(frag.button).toContain('aria-describedby="bridge-hash-help"');
    expect(frag.button).toContain('Copy expected sha256');
    // Verification recipe help line — both PowerShell and POSIX recipes
    // appear inline so the operator can copy whichever matches their OS.
    expect(frag.help).toContain('Verify hash before running installer');
    expect(frag.help).toContain('Get-FileHash -Algorithm SHA256');
    expect(frag.help).toContain('shasum -a 256');
  });

  it("without sha256 → row, help, and button all absent (empty strings)", () => {
    expect(buildBlockedPanelHashFragment({ bridgeSha256: null })).toEqual({
      row: "",
      help: "",
      button: "",
    });
    expect(buildBlockedPanelHashFragment({})).toEqual({
      row: "",
      help: "",
      button: "",
    });
    // Wrong-shape defensive case: the fragment is empty so the panel
    // does not advertise an integrity claim it cannot trust.
    expect(buildBlockedPanelHashFragment({ bridgeSha256: "not-a-real-hex" })).toEqual({
      row: "",
      help: "",
      button: "",
    });
  });
});

// Iter 41 regression — adding the iter-41 panel helpers must NOT change the
// iter-40 parse behaviour. We pin the canonical iter-40 fixture (a v2
// manifest with bridgeSha256) and confirm every typed field round-trips
// byte-for-byte through parseManifest after the iter-41 additions.
describe("parseManifest — iter 40 regression after iter 41 additions", () => {
  it("v2 manifest with bridgeSha256 parses to the same shape as before iter 41", () => {
    const VALID_SHA = "a".repeat(64);
    const VALID_BRIDGE_SHA = "b".repeat(64);
    const m = parseManifest({
      version: "1.5.0",
      manifestVersion: 2,
      sha256: VALID_SHA,
      releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
      minBootstrapVersion: "1.2.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/v1.2.0",
      bridgeSha256: VALID_BRIDGE_SHA,
    });
    expect(m).toEqual({
      version: "1.5.0",
      downloadUrl: null,
      manifestVersion: 2,
      sha256: VALID_SHA,
      releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
      rolloutBucket: null,
      minBootstrapVersion: "1.2.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/bridge/v1.2.0",
      bridgeSha256: VALID_BRIDGE_SHA,
    });
  });
});

// ─── Iter 42 — `buildBlockedDiagnosticsBlob` envelope contract ─────────────
//
// The blob is the only stable wire-out from the Settings/About blocked
// panel — once an operator pastes it into a support ticket, support
// readers parse it back as JSON. We pin the envelope shape, key
// ordering, and the precedence-resolved downloadUrl so a future
// refactor can't silently shuffle fields and invalidate past-ticket
// scrapers. Mirrors the rud1-app iter-42 contract on
// AuditForwardStatusCard's buildDiagnosticsBlob.

describe("buildBlockedDiagnosticsBlob (iter 42)", () => {
  const { buildBlockedDiagnosticsBlob } = versionCheckInternals;
  const FIXED_AT = Date.UTC(2026, 3, 25, 12, 0, 0); // 2026-04-25T12:00:00.000Z
  const VALID_BRIDGE_SHA = "c".repeat(64);

  function baseState() {
    return {
      currentVersion: "1.4.0",
      targetVersion: "2.1.0",
      requiredMinVersion: "1.7.0",
      manifestVersion: 2,
    };
  }

  it("capturedAt is wall-clock at copy time, formatted as ISO-8601 UTC", () => {
    const out = JSON.parse(buildBlockedDiagnosticsBlob(baseState(), FIXED_AT));
    expect(out.capturedAt).toBe("2026-04-25T12:00:00.000Z");
  });

  it("kind is the iter-42 stable string literal", () => {
    const out = JSON.parse(buildBlockedDiagnosticsBlob(baseState(), FIXED_AT));
    expect(out.kind).toBe("update-blocked-by-min-bootstrap");
  });

  it("versions echo verbatim from the input state", () => {
    const out = JSON.parse(buildBlockedDiagnosticsBlob(baseState(), FIXED_AT));
    expect(out.currentVersion).toBe("1.4.0");
    expect(out.targetVersion).toBe("2.1.0");
    expect(out.requiredMinVersion).toBe("1.7.0");
  });

  it("downloadUrl reflects pickDownloadUrl precedence — keyed map wins", () => {
    const out = JSON.parse(
      buildBlockedDiagnosticsBlob(
        {
          ...baseState(),
          bridgeDownloadUrls: {
            "1.7.0": "https://rud1.es/desktop/bridge/v1.7.0",
            "1.6.0": "https://rud1.es/desktop/bridge/v1.6.0",
          },
          bridgeDownloadUrl: "https://rud1.es/desktop/bridge/scalar",
          releaseNotesUrl: "https://rud1.es/changelog/v1.7.0",
        },
        FIXED_AT,
      ),
    );
    expect(out.downloadUrl).toBe("https://rud1.es/desktop/bridge/v1.7.0");
  });

  it("downloadUrl falls back to scalar bridgeDownloadUrl when keyed map is absent", () => {
    const out = JSON.parse(
      buildBlockedDiagnosticsBlob(
        {
          ...baseState(),
          bridgeDownloadUrl: "https://rud1.es/desktop/bridge/scalar",
        },
        FIXED_AT,
      ),
    );
    expect(out.downloadUrl).toBe("https://rud1.es/desktop/bridge/scalar");
  });

  it("downloadUrl falls back to releaseNotesUrl, then synthesized URL", () => {
    const withNotes = JSON.parse(
      buildBlockedDiagnosticsBlob(
        { ...baseState(), releaseNotesUrl: "https://rud1.es/changelog/v1.7.0" },
        FIXED_AT,
      ),
    );
    expect(withNotes.downloadUrl).toBe("https://rud1.es/changelog/v1.7.0");

    const synth = JSON.parse(buildBlockedDiagnosticsBlob(baseState(), FIXED_AT));
    expect(synth.downloadUrl).toBe(
      "https://rud1.es/desktop/download?version=1.7.0",
    );
  });

  it("bridgeSha256 normalised to lowercase when shape gate passes", () => {
    const out = JSON.parse(
      buildBlockedDiagnosticsBlob(
        { ...baseState(), bridgeSha256: VALID_BRIDGE_SHA.toUpperCase() },
        FIXED_AT,
      ),
    );
    expect(out.bridgeSha256).toBe(VALID_BRIDGE_SHA);
  });

  it("bridgeSha256 is null when missing OR malformed", () => {
    const missing = JSON.parse(
      buildBlockedDiagnosticsBlob(baseState(), FIXED_AT),
    );
    expect(missing.bridgeSha256).toBe(null);
    const malformed = JSON.parse(
      buildBlockedDiagnosticsBlob(
        { ...baseState(), bridgeSha256: "not-a-hex" },
        FIXED_AT,
      ),
    );
    expect(malformed.bridgeSha256).toBe(null);
  });

  it("releaseNotesUrl + manifestVersion echo verbatim, default to null", () => {
    const present = JSON.parse(
      buildBlockedDiagnosticsBlob(
        {
          ...baseState(),
          releaseNotesUrl: "https://rud1.es/changelog/v1.7.0",
          manifestVersion: 2,
        },
        FIXED_AT,
      ),
    );
    expect(present.releaseNotesUrl).toBe("https://rud1.es/changelog/v1.7.0");
    expect(present.manifestVersion).toBe(2);

    const minimal = JSON.parse(
      buildBlockedDiagnosticsBlob(
        {
          currentVersion: "1.0.0",
          targetVersion: "2.0.0",
          requiredMinVersion: "1.5.0",
        },
        FIXED_AT,
      ),
    );
    expect(minimal.releaseNotesUrl).toBe(null);
    expect(minimal.manifestVersion).toBe(null);
  });

  it("output is human-readable JSON (2-space indent, multi-line)", () => {
    const blob = buildBlockedDiagnosticsBlob(baseState(), FIXED_AT);
    expect(blob.startsWith("{\n")).toBe(true);
    expect(blob.includes("\n  ")).toBe(true);
  });

  it("key order is stable: capturedAt → kind → versions → url → sha → notes → manifestVersion", () => {
    // Pinned so future contributors can't silently shuffle the layout —
    // any external regex-based scraper run on past tickets would break.
    const blob = buildBlockedDiagnosticsBlob(baseState(), FIXED_AT);
    const order = [
      '"capturedAt"',
      '"kind"',
      '"currentVersion"',
      '"targetVersion"',
      '"requiredMinVersion"',
      '"downloadUrl"',
      '"bridgeSha256"',
      '"releaseNotesUrl"',
      '"manifestVersion"',
    ];
    let prev = -1;
    for (const k of order) {
      const idx = blob.indexOf(k);
      expect(idx).toBeGreaterThan(prev);
      prev = idx;
    }
  });
});
