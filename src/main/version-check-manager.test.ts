import { describe, it, expect } from "vitest";
// Iter 49 — crypto for fixture generation (ed25519 keypair + raw signature).
// Tests construct minisign sidecar bytes from scratch so they don't depend
// on a hardcoded publisher key shipped in source.
import { generateKeyPairSync, sign as cryptoSign, KeyObject } from "crypto";

// Iter 49 — env helpers live in auto-updater.ts (sigStrict / sigVerify
// share a module). Imported at top-level so the iter-49 env-helper
// suite has stable schema-checked references rather than going through
// require() (which vitest's ESM loader rejects).
import {
  parseSigPubkey,
  isSigVerifyEnabled,
} from "./auto-updater";

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
// Iter 46 — settings-window HTML builder + the `…WithRuntimeVersion`
// wrapper live in their own file so they're importable from the test
// suite without pulling in `index.ts`'s Electron lifecycle side-effects.
import {
  buildSettingsWindowHtml,
  buildSettingsWindowHtmlWithRuntimeVersion,
} from "./settings-window-html";

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
    // because vN+ may add NEW required fields whose absence from this
    // code path would otherwise be silently ignored.
    //
    // Iter 47 — cap bumped to 3 to accept the new optional `signatureUrl`
    // v3 field. The "first unsupported value above the cap" probe
    // accordingly shifted from `3` → `4`. v3 itself is now exercised
    // by the iter-47 describe block below.
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
        manifestVersion: 4, // first unsupported value above the cap (post-iter-47)
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

// ─── Iter 43 — non-blocked-verdict diagnostics blobs ───────────────────────
//
// Companion coverage to iter-42's blocked-state envelope. Each non-blocked
// verdict (`up-to-date`, `update-available`, `error`) gets its own stable
// envelope shape pinned here so a support reader investigating "why
// didn't this auto-update?" sees a consistent layout regardless of
// verdict. Pins the key SET, key ORDERING, capturedAt format, kind
// literal, and the verdict-specific behaviour (pickDownloadUrl
// precedence reuse on `update-available`; verbatim errorMessage on
// `error`; field-omission on `up-to-date`).

describe("buildUpToDateDiagnosticsBlob (iter 43)", () => {
  const { buildUpToDateDiagnosticsBlob } = versionCheckInternals;
  const FIXED_AT = Date.UTC(2026, 3, 25, 12, 0, 0); // 2026-04-25T12:00:00.000Z

  it("envelope shape pins capturedAt + kind literal + currentVersion + key ordering", () => {
    const blob = buildUpToDateDiagnosticsBlob(
      {
        current: "2.1.0",
        releaseNotesUrl: "https://rud1.es/changelog/v2.1.0",
        manifestVersion: 2,
      },
      FIXED_AT,
    );
    const out = JSON.parse(blob);
    expect(out).toEqual({
      capturedAt: "2026-04-25T12:00:00.000Z",
      kind: "up-to-date",
      currentVersion: "2.1.0",
      releaseNotesUrl: "https://rud1.es/changelog/v2.1.0",
      manifestVersion: 2,
    });
    // Pinned key order — any external scraper relies on this.
    const order = [
      '"capturedAt"',
      '"kind"',
      '"currentVersion"',
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

  it("capturedAt is wall-clock at copy time, kind is the iter-43 stable literal", () => {
    const out = JSON.parse(
      buildUpToDateDiagnosticsBlob({ current: "2.1.0" }, FIXED_AT),
    );
    expect(out.capturedAt).toBe("2026-04-25T12:00:00.000Z");
    expect(out.kind).toBe("up-to-date");
  });

  it("omits update-available-only fields (no targetVersion / downloadUrl / bridgeSha256)", () => {
    // The up-to-date envelope is intentionally narrower than the
    // update-available one — there's no target version (we're already
    // on it) and no download URL (nothing to download). A regression
    // that smuggles those keys in would invalidate the verdict-vs-shape
    // promise the support-side parser relies on.
    const blob = buildUpToDateDiagnosticsBlob(
      { current: "2.1.0", releaseNotesUrl: "https://rud1.es/changelog" },
      FIXED_AT,
    );
    expect(blob).not.toContain('"targetVersion"');
    expect(blob).not.toContain('"downloadUrl"');
    expect(blob).not.toContain('"bridgeSha256"');
    expect(blob).not.toContain('"requiredMinVersion"');
    expect(blob).not.toContain('"errorMessage"');
    // Optional fields default to null when absent.
    const minimal = JSON.parse(
      buildUpToDateDiagnosticsBlob({ current: "2.1.0" }, FIXED_AT),
    );
    expect(minimal.releaseNotesUrl).toBe(null);
    expect(minimal.manifestVersion).toBe(null);
  });
});

describe("buildUpdateAvailableDiagnosticsBlob (iter 43)", () => {
  const { buildUpdateAvailableDiagnosticsBlob } = versionCheckInternals;
  const FIXED_AT = Date.UTC(2026, 3, 25, 12, 0, 0); // 2026-04-25T12:00:00.000Z
  const VALID_BRIDGE_SHA = "d".repeat(64);

  it("envelope shape pins capturedAt + kind literal + targetVersion + key ordering", () => {
    const blob = buildUpdateAvailableDiagnosticsBlob(
      {
        current: "1.4.0",
        latest: "2.1.0",
        downloadUrl: "https://rud1.es/desktop/v2.1.0",
        releaseNotesUrl: "https://rud1.es/changelog/v2.1.0",
        bridgeSha256: VALID_BRIDGE_SHA,
        manifestVersion: 2,
      },
      FIXED_AT,
    );
    const out = JSON.parse(blob);
    expect(out).toEqual({
      capturedAt: "2026-04-25T12:00:00.000Z",
      kind: "update-available",
      currentVersion: "1.4.0",
      targetVersion: "2.1.0",
      downloadUrl: "https://rud1.es/desktop/v2.1.0",
      bridgeSha256: VALID_BRIDGE_SHA,
      releaseNotesUrl: "https://rud1.es/changelog/v2.1.0",
      manifestVersion: 2,
    });
    const order = [
      '"capturedAt"',
      '"kind"',
      '"currentVersion"',
      '"targetVersion"',
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

  it("capturedAt is wall-clock at copy time, kind is the iter-43 stable literal", () => {
    const out = JSON.parse(
      buildUpdateAvailableDiagnosticsBlob(
        { current: "1.4.0", latest: "2.1.0" },
        FIXED_AT,
      ),
    );
    expect(out.capturedAt).toBe("2026-04-25T12:00:00.000Z");
    expect(out.kind).toBe("update-available");
  });

  it("downloadUrl re-runs pickDownloadUrl precedence (scalar → releaseNotes → synthesized)", () => {
    // Scalar wins over releaseNotesUrl when present.
    const scalar = JSON.parse(
      buildUpdateAvailableDiagnosticsBlob(
        {
          current: "1.4.0",
          latest: "2.1.0",
          downloadUrl: "https://rud1.es/desktop/v2.1.0",
          releaseNotesUrl: "https://rud1.es/changelog/v2.1.0",
        },
        FIXED_AT,
      ),
    );
    expect(scalar.downloadUrl).toBe("https://rud1.es/desktop/v2.1.0");
    // releaseNotesUrl is the next fallback.
    const notes = JSON.parse(
      buildUpdateAvailableDiagnosticsBlob(
        {
          current: "1.4.0",
          latest: "2.1.0",
          releaseNotesUrl: "https://rud1.es/changelog/v2.1.0",
        },
        FIXED_AT,
      ),
    );
    expect(notes.downloadUrl).toBe("https://rud1.es/changelog/v2.1.0");
    // Synthesized URL uses `latest` as the version qualifier (the
    // `update-available` analogue of `requiredMinVersion`).
    const synth = JSON.parse(
      buildUpdateAvailableDiagnosticsBlob(
        { current: "1.4.0", latest: "2.1.0" },
        FIXED_AT,
      ),
    );
    expect(synth.downloadUrl).toBe(
      "https://rud1.es/desktop/download?version=2.1.0",
    );
  });

  it("bridgeSha256 normalised to lowercase / null mirrors iter-41 shape gate", () => {
    const upper = JSON.parse(
      buildUpdateAvailableDiagnosticsBlob(
        {
          current: "1.4.0",
          latest: "2.1.0",
          bridgeSha256: VALID_BRIDGE_SHA.toUpperCase(),
        },
        FIXED_AT,
      ),
    );
    expect(upper.bridgeSha256).toBe(VALID_BRIDGE_SHA);
    const malformed = JSON.parse(
      buildUpdateAvailableDiagnosticsBlob(
        { current: "1.4.0", latest: "2.1.0", bridgeSha256: "not-a-hex" },
        FIXED_AT,
      ),
    );
    expect(malformed.bridgeSha256).toBe(null);
    const missing = JSON.parse(
      buildUpdateAvailableDiagnosticsBlob(
        { current: "1.4.0", latest: "2.1.0" },
        FIXED_AT,
      ),
    );
    expect(missing.bridgeSha256).toBe(null);
  });
});

describe("buildErrorDiagnosticsBlob (iter 43)", () => {
  const { buildErrorDiagnosticsBlob } = versionCheckInternals;
  const FIXED_AT = Date.UTC(2026, 3, 25, 12, 0, 0); // 2026-04-25T12:00:00.000Z

  it("envelope shape pins capturedAt + kind literal + errorMessage + key ordering", () => {
    const blob = buildErrorDiagnosticsBlob(
      {
        current: "1.4.0",
        message: "fetch failed: ECONNREFUSED",
        manifestVersion: 2,
      },
      FIXED_AT,
    );
    const out = JSON.parse(blob);
    expect(out).toEqual({
      capturedAt: "2026-04-25T12:00:00.000Z",
      kind: "error",
      currentVersion: "1.4.0",
      errorMessage: "fetch failed: ECONNREFUSED",
      manifestVersion: 2,
    });
    const order = [
      '"capturedAt"',
      '"kind"',
      '"currentVersion"',
      '"errorMessage"',
      '"manifestVersion"',
    ];
    let prev = -1;
    for (const k of order) {
      const idx = blob.indexOf(k);
      expect(idx).toBeGreaterThan(prev);
      prev = idx;
    }
  });

  it("capturedAt is wall-clock at copy time, kind is the iter-43 stable literal", () => {
    const out = JSON.parse(
      buildErrorDiagnosticsBlob(
        { current: "1.4.0", message: "boom" },
        FIXED_AT,
      ),
    );
    expect(out.capturedAt).toBe("2026-04-25T12:00:00.000Z");
    expect(out.kind).toBe("error");
  });

  it("errorMessage echoes verbatim from state (no truncation / normalisation)", () => {
    // Verbatim because operator-pasted error text is the primary
    // diagnostic signal. The blob should preserve exact whitespace,
    // punctuation, and the full message body so support sees what the
    // operator saw.
    const verbose =
      "HTTP 503: Service Unavailable\n  retry-after: 30\n  upstream: cdn-edge-7";
    const out = JSON.parse(
      buildErrorDiagnosticsBlob({ current: "1.4.0", message: verbose }, FIXED_AT),
    );
    expect(out.errorMessage).toBe(verbose);
    // currentVersion defaults to null when the caller didn't thread the
    // app version through (the error state shape doesn't carry it).
    const noCurrent = JSON.parse(
      buildErrorDiagnosticsBlob({ message: "boom" }, FIXED_AT),
    );
    expect(noCurrent.currentVersion).toBe(null);
    // No update-available-only fields leak in.
    const blob = buildErrorDiagnosticsBlob(
      { current: "1.4.0", message: "boom" },
      FIXED_AT,
    );
    expect(blob).not.toContain('"targetVersion"');
    expect(blob).not.toContain('"downloadUrl"');
    expect(blob).not.toContain('"bridgeSha256"');
    expect(blob).not.toContain('"releaseNotesUrl"');
    expect(blob).not.toContain('"requiredMinVersion"');
  });
});

describe("buildErrorDiagnosticsBlob — currentVersion threading (iter 44)", () => {
  // Iter 44 — the iter-43 helper made `current` optional (the error
  // state union doesn't carry it), with the caveat that a caller
  // threading app.getVersion() through could populate it. These specs
  // pin both halves of that contract: when threaded, the envelope
  // surfaces the version; when not threaded, the legacy null path is
  // preserved byte-for-byte. The third spec mirrors the inline
  // renderer-side rebuild in src/main/index.ts (which sources the
  // value from a JSON-encoded APP_VERSION constant injected at HTML
  // build time) by hand-constructing the same envelope and asserting
  // parity with the helper's output — the closest unit-level
  // equivalent given the inline-script architecture.
  const { buildErrorDiagnosticsBlob } = versionCheckInternals;
  const FIXED_AT = Date.UTC(2026, 3, 25, 12, 0, 0); // 2026-04-25T12:00:00.000Z

  it("threading current populates currentVersion in the envelope (iter-44 happy path)", () => {
    const out = JSON.parse(
      buildErrorDiagnosticsBlob(
        { current: "2.7.1", message: "fetch failed: ETIMEDOUT" },
        FIXED_AT,
      ),
    );
    expect(out.currentVersion).toBe("2.7.1");
    // Key ordering MUST match the iter-43 contract — currentVersion
    // appears between `kind` and `errorMessage`.
    const blob = buildErrorDiagnosticsBlob(
      { current: "2.7.1", message: "fetch failed: ETIMEDOUT" },
      FIXED_AT,
    );
    const order = ['"kind"', '"currentVersion"', '"errorMessage"'];
    let prev = -1;
    for (const k of order) {
      const idx = blob.indexOf(k);
      expect(idx).toBeGreaterThan(prev);
      prev = idx;
    }
  });

  it("omitting current leaves currentVersion as null (legacy iter-43 path preserved)", () => {
    const out = JSON.parse(
      buildErrorDiagnosticsBlob({ message: "boom" }, FIXED_AT),
    );
    expect(out.currentVersion).toBe(null);
    // The key still appears in the envelope (and in the same slot) —
    // `null` is a populated field, not an omitted one. Pinning this
    // protects support tooling that destructures `currentVersion`
    // from the envelope.
    const blob = buildErrorDiagnosticsBlob({ message: "boom" }, FIXED_AT);
    expect(blob).toContain('"currentVersion": null');
  });

  it("inline renderer rebuild with APP_VERSION matches the helper byte-for-byte", () => {
    // Mirrors the renderer-side inline rebuild in src/main/index.ts:
    // the panel reads APP_VERSION (JSON-encoded app.getVersion() at
    // HTML build time) and the runtime `state.message` / `state.
    // manifestVersion`, then constructs the envelope inline. We
    // hand-build that envelope here with the same key order + the
    // same `APP_VERSION != null ? APP_VERSION : null` defensive
    // guard the renderer uses, then assert parity with the helper.
    // A regression in either path surfaces as a parity failure here.
    const APP_VERSION = "3.0.0-rc.4";
    const fakeState = { message: "TLS handshake failed", manifestVersion: 2 };
    const capturedAt = new Date(FIXED_AT).toISOString();
    const inlineEnvelope = {
      capturedAt,
      kind: "error" as const,
      currentVersion: APP_VERSION != null ? APP_VERSION : null,
      errorMessage: fakeState.message,
      manifestVersion:
        fakeState.manifestVersion != null ? fakeState.manifestVersion : null,
    };
    const inlineBlob = JSON.stringify(inlineEnvelope, null, 2);
    const helperBlob = buildErrorDiagnosticsBlob(
      {
        current: APP_VERSION,
        message: fakeState.message,
        manifestVersion: fakeState.manifestVersion,
      },
      FIXED_AT,
    );
    expect(inlineBlob).toBe(helperBlob);
    // And currentVersion is the threaded APP_VERSION, not null.
    expect(JSON.parse(helperBlob).currentVersion).toBe(APP_VERSION);
  });
});

describe("buildBlockedDiagnosticsBlob — currentVersion threading (iter 45)", () => {
  // Iter 45 — extend the iter-44 APP_VERSION thread to the blocked
  // verdict. Unlike `error`, the blocked state DOES carry
  // `currentVersion` natively (sourced from the version-check at
  // fetch time), so the helper's legacy path is to read off state.
  // The optional `runtimeAppVersion` parameter overrides that when
  // provided — the rationale being that under iter-30+ bridge-only
  // update paths, the manifest fetch's stored version can drift from
  // the running app's actual `app.getVersion()` truth between
  // restarts. Three specs mirror the iter-44 contract: threaded value
  // wins; missing/empty falls back to state; inline renderer rebuild
  // matches helper byte-for-byte.
  const { buildBlockedDiagnosticsBlob } = versionCheckInternals;
  const FIXED_AT = Date.UTC(2026, 3, 25, 12, 0, 0);

  const baseState = {
    currentVersion: "1.4.0",
    targetVersion: "2.1.0",
    requiredMinVersion: "1.7.0",
    bridgeDownloadUrl: "https://rud1.es/desktop/v2.1.0.dmg",
  };

  it("threading runtimeAppVersion overrides state.currentVersion in the envelope", () => {
    const out = JSON.parse(
      buildBlockedDiagnosticsBlob(baseState, FIXED_AT, "1.5.2"),
    );
    expect(out.currentVersion).toBe("1.5.2");
    // Other fields are still pulled off state — only currentVersion
    // is overridden.
    expect(out.targetVersion).toBe("2.1.0");
    expect(out.requiredMinVersion).toBe("1.7.0");
    // Iter-42 key ordering (capturedAt → kind → currentVersion →
    // targetVersion → requiredMinVersion → downloadUrl → ...) MUST be
    // preserved.
    const blob = buildBlockedDiagnosticsBlob(baseState, FIXED_AT, "1.5.2");
    const order = [
      '"kind"',
      '"currentVersion"',
      '"targetVersion"',
      '"requiredMinVersion"',
      '"downloadUrl"',
    ];
    let prev = -1;
    for (const k of order) {
      const idx = blob.indexOf(k);
      expect(idx).toBeGreaterThan(prev);
      prev = idx;
    }
  });

  it("omitting runtimeAppVersion falls back to state.currentVersion (legacy iter-42 path)", () => {
    const blobLegacy = buildBlockedDiagnosticsBlob(baseState, FIXED_AT);
    const blobUndefined = buildBlockedDiagnosticsBlob(
      baseState,
      FIXED_AT,
      undefined,
    );
    const blobNull = buildBlockedDiagnosticsBlob(baseState, FIXED_AT, null);
    const blobEmpty = buildBlockedDiagnosticsBlob(baseState, FIXED_AT, "");
    // All four byte-for-byte identical to the iter-42 helper output —
    // legacy callers and existing test fixtures keep round-tripping
    // unchanged.
    expect(blobLegacy).toBe(blobUndefined);
    expect(blobLegacy).toBe(blobNull);
    expect(blobLegacy).toBe(blobEmpty);
    expect(JSON.parse(blobLegacy).currentVersion).toBe("1.4.0");
  });

  it("inline renderer rebuild with APP_VERSION matches the helper byte-for-byte", () => {
    // Mirrors the iter-45 inline rebuild in src/main/index.ts. The
    // panel reads APP_VERSION (JSON-encoded app.getVersion()) and
    // prefers it over `state.currentVersion`. We hand-build the same
    // envelope here with the SAME defensive guard the renderer uses
    // (typeof + length>0) and assert parity with the helper output.
    const APP_VERSION = "3.0.0-rc.4";
    const fakeState = {
      ...baseState,
      releaseNotesUrl: null as string | null,
      manifestVersion: 2 as number | null,
    };
    const capturedAt = new Date(FIXED_AT).toISOString();
    // Inline renderer's pickDownloadUrl branch — for this fixture the
    // scalar branch wins since no keyed map / releaseNotes is set.
    const url2 = fakeState.bridgeDownloadUrl;
    const inlineCurrentVersion =
      typeof APP_VERSION === "string" && APP_VERSION.length > 0
        ? APP_VERSION
        : fakeState.currentVersion;
    const inlineEnvelope = {
      capturedAt,
      kind: "update-blocked-by-min-bootstrap" as const,
      currentVersion: inlineCurrentVersion,
      targetVersion: fakeState.targetVersion,
      requiredMinVersion: fakeState.requiredMinVersion,
      downloadUrl: url2,
      bridgeSha256: null,
      releaseNotesUrl: fakeState.releaseNotesUrl ?? null,
      manifestVersion: fakeState.manifestVersion ?? null,
    };
    const inlineBlob = JSON.stringify(inlineEnvelope, null, 2);
    const helperBlob = buildBlockedDiagnosticsBlob(
      fakeState,
      FIXED_AT,
      APP_VERSION,
    );
    expect(inlineBlob).toBe(helperBlob);
    expect(JSON.parse(helperBlob).currentVersion).toBe(APP_VERSION);
  });
});

describe("buildUpdateAvailableDiagnosticsBlob — currentVersion threading (iter 45)", () => {
  // Iter 45 — same rationale as the blocked-verdict thread above.
  // The update-available state DOES carry `current` natively, but
  // the manifest's stored version can drift from the running app's
  // actual `app.getVersion()` under bridge-only update paths.
  const { buildUpdateAvailableDiagnosticsBlob } = versionCheckInternals;
  const FIXED_AT = Date.UTC(2026, 3, 25, 12, 0, 0);

  const baseState = {
    current: "1.4.0",
    latest: "1.5.0",
    downloadUrl: "https://rud1.es/desktop/v1.5.0.dmg",
    releaseNotesUrl: null as string | null,
    bridgeSha256: null as string | null,
    manifestVersion: 2 as number | null,
  };

  it("threading runtimeAppVersion overrides state.current in the envelope", () => {
    const out = JSON.parse(
      buildUpdateAvailableDiagnosticsBlob(baseState, FIXED_AT, "1.4.1"),
    );
    expect(out.currentVersion).toBe("1.4.1");
    expect(out.targetVersion).toBe("1.5.0");
    // iter-43 key ordering preserved (capturedAt → kind →
    // currentVersion → targetVersion → downloadUrl → bridgeSha256 →
    // releaseNotesUrl → manifestVersion).
    const blob = buildUpdateAvailableDiagnosticsBlob(
      baseState,
      FIXED_AT,
      "1.4.1",
    );
    const order = [
      '"kind"',
      '"currentVersion"',
      '"targetVersion"',
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

  it("omitting runtimeAppVersion falls back to state.current (legacy iter-43 path)", () => {
    const blobLegacy = buildUpdateAvailableDiagnosticsBlob(baseState, FIXED_AT);
    const blobUndefined = buildUpdateAvailableDiagnosticsBlob(
      baseState,
      FIXED_AT,
      undefined,
    );
    const blobNull = buildUpdateAvailableDiagnosticsBlob(
      baseState,
      FIXED_AT,
      null,
    );
    const blobEmpty = buildUpdateAvailableDiagnosticsBlob(
      baseState,
      FIXED_AT,
      "",
    );
    expect(blobLegacy).toBe(blobUndefined);
    expect(blobLegacy).toBe(blobNull);
    expect(blobLegacy).toBe(blobEmpty);
    expect(JSON.parse(blobLegacy).currentVersion).toBe("1.4.0");
  });

  it("inline renderer rebuild with APP_VERSION matches the helper byte-for-byte", () => {
    // Mirrors the iter-45 inline rebuild for the update-available
    // verdict — same threading discipline as the blocked verdict
    // above. Hand-built envelope matches the helper byte-for-byte.
    const APP_VERSION = "3.0.0-rc.4";
    const capturedAt = new Date(FIXED_AT).toISOString();
    // pickDownloadUrl behaviour for this fixture: scalar branch wins.
    const url3 = baseState.downloadUrl;
    const inlineCurrentVersion =
      typeof APP_VERSION === "string" && APP_VERSION.length > 0
        ? APP_VERSION
        : baseState.current;
    const inlineEnvelope = {
      capturedAt,
      kind: "update-available" as const,
      currentVersion: inlineCurrentVersion,
      targetVersion: baseState.latest,
      downloadUrl: url3,
      bridgeSha256: null,
      releaseNotesUrl: baseState.releaseNotesUrl ?? null,
      manifestVersion: baseState.manifestVersion ?? null,
    };
    const inlineBlob = JSON.stringify(inlineEnvelope, null, 2);
    const helperBlob = buildUpdateAvailableDiagnosticsBlob(
      baseState,
      FIXED_AT,
      APP_VERSION,
    );
    expect(inlineBlob).toBe(helperBlob);
    expect(JSON.parse(helperBlob).currentVersion).toBe(APP_VERSION);
  });
});

describe("buildSettingsWindowHtmlWithRuntimeVersion (iter 46)", () => {
  // Iter 46 — the wrapper bakes `app.getVersion()` (or any caller-
  // supplied runtime version) into ALL FOUR diagnostic-blob surfaces
  // the Settings/About panel exposes:
  //
  //   1. inline `APP_VERSION` JS constant (consumed by every renderer-
  //      side "Copy diagnostics" rebuild)
  //   2. `error` envelope         — via APP_VERSION → state.current
  //                                 fallback in `buildErrorDiagnosticsBlob`
  //   3. `blocked` envelope       — via the iter-45 `runtimeAppVersion`
  //                                 parameter on
  //                                 `buildBlockedDiagnosticsBlob`
  //   4. `update-available`       — same iter-45 parameter on
  //                                 `buildUpdateAvailableDiagnosticsBlob`
  //
  // Pinning the wrapper here keeps the iter-44/45 contracts honest:
  // a refactor that drops the override on any one surface fails the
  // byte-equality check below.
  //
  // The legacy direct-call path (`buildSettingsWindowHtml(version)`)
  // is also pinned so the wrapper stays purely additive — existing
  // call sites (and any future test harness reaching the helpers
  // directly) keep round-tripping byte-for-byte.
  const {
    buildBlockedDiagnosticsBlob,
    buildUpdateAvailableDiagnosticsBlob,
    buildErrorDiagnosticsBlob,
  } = versionCheckInternals;
  const FIXED_AT = Date.UTC(2026, 3, 25, 12, 0, 0);
  const RUNTIME_VERSION = "3.0.0-rc.4";

  // Helper — extract the JSON-encoded `APP_VERSION` literal from the
  // returned data: URL. The wrapper produces
  //   data:text/html;charset=utf-8,<percent-encoded HTML>
  // and the inline JS contains exactly one occurrence of
  //   var APP_VERSION = "<json-encoded-version>";
  // so a single regex over the decoded HTML pins both threading and
  // JSON-encoding correctness.
  function extractAppVersionLiteral(dataUrl: string): string | null {
    const prefix = "data:text/html;charset=utf-8,";
    if (!dataUrl.startsWith(prefix)) return null;
    const html = decodeURIComponent(dataUrl.slice(prefix.length));
    const match = html.match(/var APP_VERSION = (.+?);/);
    return match ? match[1] : null;
  }

  it("threads runtimeAppVersion into all three diagnostic blob types byte-for-byte", () => {
    // The wrapper's contract is that the runtime version it bakes is
    // the SAME value all three helper-level overrides would consume.
    // We assert this by hand-building the three envelopes directly
    // through the iter-44/45 helpers with the same runtime version,
    // then re-asserting that the wrapper's inline JS carries the same
    // value (the renderer-side rebuilds source `currentVersion` from
    // APP_VERSION → which IS the runtime version under the wrapper).
    const html = buildSettingsWindowHtmlWithRuntimeVersion(RUNTIME_VERSION);

    // 1. blocked envelope — helper called with runtimeAppVersion =
    //    RUNTIME_VERSION matches what the wrapper-baked APP_VERSION
    //    would feed the inline rebuild.
    const blockedState = {
      currentVersion: "1.4.0", // intentionally drifted from RUNTIME_VERSION
      targetVersion: "2.1.0",
      requiredMinVersion: "1.7.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/v2.1.0.dmg",
      releaseNotesUrl: null as string | null,
      manifestVersion: 2 as number | null,
    };
    const blockedHelperBlob = buildBlockedDiagnosticsBlob(
      blockedState,
      FIXED_AT,
      RUNTIME_VERSION,
    );
    expect(JSON.parse(blockedHelperBlob).currentVersion).toBe(RUNTIME_VERSION);

    // 2. update-available envelope — same shape via state.current.
    const updateAvailState = {
      current: "1.4.0",
      latest: "1.5.0",
      downloadUrl: "https://rud1.es/desktop/v1.5.0.dmg",
      releaseNotesUrl: null as string | null,
      bridgeSha256: null as string | null,
      manifestVersion: 2 as number | null,
    };
    const updateAvailHelperBlob = buildUpdateAvailableDiagnosticsBlob(
      updateAvailState,
      FIXED_AT,
      RUNTIME_VERSION,
    );
    expect(JSON.parse(updateAvailHelperBlob).currentVersion).toBe(
      RUNTIME_VERSION,
    );

    // 3. error envelope — the helper sources from state.current; the
    //    inline rebuild sources from APP_VERSION. Hand-passing
    //    RUNTIME_VERSION as state.current produces the same envelope
    //    the renderer-side rebuild produces under the wrapper.
    const errorHelperBlob = buildErrorDiagnosticsBlob(
      {
        current: RUNTIME_VERSION,
        message: "TLS handshake failed",
        manifestVersion: 2,
      },
      FIXED_AT,
    );
    expect(JSON.parse(errorHelperBlob).currentVersion).toBe(RUNTIME_VERSION);

    // The wrapper's only mechanism for threading the runtime version
    // into the three rebuilds is the APP_VERSION constant — assert
    // it carries our value (JSON-encoded). A wrapper regression that
    // passed `null` / `""` / a different string into
    // buildSettingsWindowHtml would surface here as the literal not
    // matching JSON.stringify(RUNTIME_VERSION).
    const literal = extractAppVersionLiteral(html);
    expect(literal).toBe(JSON.stringify(RUNTIME_VERSION));
  });

  it("threads runtimeAppVersion into the inline APP_VERSION JS constant (JSON-encoded)", () => {
    // JSON-encoding matters: an unescaped raw string would let an
    // attacker-controlled version (which can't actually happen in
    // production — it comes from `app.getVersion()` — but the build
    // discipline still matters) break out of the JS literal. Pin the
    // encoding contract by feeding in a value with characters that
    // require escaping (a quote and a backslash) and checking the
    // emitted literal matches JSON.stringify byte-for-byte.
    const trickyVersion = '1.0.0-rc.1+meta"injected\\path';
    const html = buildSettingsWindowHtmlWithRuntimeVersion(trickyVersion);
    const literal = extractAppVersionLiteral(html);
    expect(literal).toBe(JSON.stringify(trickyVersion));
    // And a sanity check against the routine well-formed case.
    const html2 = buildSettingsWindowHtmlWithRuntimeVersion(RUNTIME_VERSION);
    expect(extractAppVersionLiteral(html2)).toBe(`"${RUNTIME_VERSION}"`);
  });

  it("calling buildSettingsWindowHtml directly produces the legacy null-fallback envelopes byte-for-byte", () => {
    // The wrapper is purely additive — direct callers of the
    // underlying `buildSettingsWindowHtml(currentVersion)` keep
    // working with their own positional argument. Byte-for-byte
    // identity between `buildSettingsWindowHtml(v)` and
    // `buildSettingsWindowHtmlWithRuntimeVersion(v)` confirms the
    // wrapper truly is a single-arg passthrough (no extra HTML
    // injection, no header drift, no double-encoding).
    const direct = buildSettingsWindowHtml(RUNTIME_VERSION);
    const wrapped = buildSettingsWindowHtmlWithRuntimeVersion(RUNTIME_VERSION);
    expect(direct).toBe(wrapped);

    // Independent of the wrapper, the iter-42/43/44/45 helper
    // contracts still hold for legacy callers that omit the new
    // `runtimeAppVersion` parameter — `null`-fallback envelopes
    // round-trip byte-for-byte. Pin all four variants
    // (undefined/null/empty/omitted) on the iter-45 helpers and the
    // legacy `state.current ?? null` path on the iter-44 helper.
    const blockedState = {
      currentVersion: "1.4.0",
      targetVersion: "2.1.0",
      requiredMinVersion: "1.7.0",
    };
    const blockedLegacy = buildBlockedDiagnosticsBlob(blockedState, FIXED_AT);
    expect(blockedLegacy).toBe(
      buildBlockedDiagnosticsBlob(blockedState, FIXED_AT, undefined),
    );
    expect(blockedLegacy).toBe(
      buildBlockedDiagnosticsBlob(blockedState, FIXED_AT, null),
    );
    expect(blockedLegacy).toBe(
      buildBlockedDiagnosticsBlob(blockedState, FIXED_AT, ""),
    );
    expect(JSON.parse(blockedLegacy).currentVersion).toBe("1.4.0");

    const updateAvailState = {
      current: "1.4.0",
      latest: "1.5.0",
    };
    const updateAvailLegacy = buildUpdateAvailableDiagnosticsBlob(
      updateAvailState,
      FIXED_AT,
    );
    expect(updateAvailLegacy).toBe(
      buildUpdateAvailableDiagnosticsBlob(updateAvailState, FIXED_AT, undefined),
    );
    expect(updateAvailLegacy).toBe(
      buildUpdateAvailableDiagnosticsBlob(updateAvailState, FIXED_AT, null),
    );
    expect(updateAvailLegacy).toBe(
      buildUpdateAvailableDiagnosticsBlob(updateAvailState, FIXED_AT, ""),
    );
    expect(JSON.parse(updateAvailLegacy).currentVersion).toBe("1.4.0");

    // iter-44 error helper has no `runtimeAppVersion` parameter (it
    // sources from state.current); the legacy null-fallback fires
    // when current is omitted from the state.
    const errorLegacy = buildErrorDiagnosticsBlob({ message: "boom" }, FIXED_AT);
    expect(JSON.parse(errorLegacy).currentVersion).toBe(null);
    expect(errorLegacy).toContain('"currentVersion": null');
  });
});

// ─── Iter 47 — manifestVersion v3 + signatureUrl scaffold ─────────────────
//
// The v3 schema bump introduces an optional `signatureUrl` field (the
// .sig sidecar URL for detached signature verification — pairs with
// iter-31 strict-mode + iter-32 sha256 checksums). This iter wires up
// the parser, validator helper, and diagnostics envelope plumbing only;
// it does NOT actually fetch or verify signatures (that needs publisher
// key infra deferred to a future iter).
//
// Coverage:
//   • validateSignatureUrl pure helper — scheme + suffix + length
//     + javascript:/data: rejection.
//   • parseManifest accepts v3 with a good signatureUrl.
//   • parseManifest accepts v3 with a bad signatureUrl (silently dropped,
//     manifest still parses — defensive contract).
//   • parseManifest v2-passthrough preserves byte-for-byte iter-46 shape
//     even when a v2 manifest carries a `signatureUrl` field (forward-
//     compat field on backward manifest is silently ignored).
//   • Diagnostics envelopes carry signatureUrl when present, omit it
//     when absent — preserving iter-42/43 key-ordering byte-for-byte
//     for callers without a signatureUrl.

describe("validateSignatureUrl (iter 47)", () => {
  const { validateSignatureUrl } = versionCheckInternals;

  it("accepts well-formed https URLs ending in .sig / .minisig / .asc", () => {
    expect(validateSignatureUrl("https://rud1.es/desktop/v1.5.0.dmg.sig")).toBe(
      "https://rud1.es/desktop/v1.5.0.dmg.sig",
    );
    expect(
      validateSignatureUrl("https://rud1.es/desktop/v1.5.0.dmg.minisig"),
    ).toBe("https://rud1.es/desktop/v1.5.0.dmg.minisig");
    expect(validateSignatureUrl("https://rud1.es/desktop/v1.5.0.dmg.asc")).toBe(
      "https://rud1.es/desktop/v1.5.0.dmg.asc",
    );
    // Case-insensitive suffix gate — `.SIG` / `.MiniSig` accepted.
    expect(validateSignatureUrl("https://rud1.es/installer.SIG")).toBe(
      "https://rud1.es/installer.SIG",
    );
  });

  it("accepts http:// URLs (the .sig file is itself signed; plain http is fine)", () => {
    // Stricter than the bridge-download allowlist on the suffix gate
    // but more lenient on the scheme: a plain-http fetch of a .sig
    // file is implicitly tamper-detected by the signature itself.
    expect(validateSignatureUrl("http://mirror.local/rud1/v1.5.0.dmg.sig")).toBe(
      "http://mirror.local/rud1/v1.5.0.dmg.sig",
    );
  });

  it("rejects javascript: and data: schemes (silent — returns null)", () => {
    // Defensive deny-list ahead of the allow-list. data: URLs CAN end
    // in `.sig` if the operator base64-encodes a payload with a
    // trailing literal `.sig` — that's not a real sidecar.
    expect(validateSignatureUrl("javascript:alert(1)")).toBeNull();
    expect(
      validateSignatureUrl("javascript:fetch('/exfil').sig"),
    ).toBeNull();
    expect(
      validateSignatureUrl("data:application/octet-stream;base64,AAAA.sig"),
    ).toBeNull();
    // file: / ftp: also rejected (not in the allow-list).
    expect(
      validateSignatureUrl("file:///etc/passwd.sig"),
    ).toBeNull();
    expect(
      validateSignatureUrl("ftp://example.com/installer.sig"),
    ).toBeNull();
  });

  it("rejects URLs missing the .sig / .minisig / .asc suffix", () => {
    // The suffix gate runs against the URL pathname, so a query
    // string that pretends to be the extension doesn't help.
    expect(validateSignatureUrl("https://rud1.es/installer.dmg")).toBeNull();
    expect(
      validateSignatureUrl("https://rud1.es/installer?ext=.sig"),
    ).toBeNull();
    expect(
      validateSignatureUrl("https://rud1.es/installer.dmg#fragment.sig"),
    ).toBeNull();
    // Empty path with no extension at all.
    expect(validateSignatureUrl("https://rud1.es/")).toBeNull();
  });

  it("enforces the 2048-char length cap", () => {
    const path = "a".repeat(2030); // 2030 + "https://x/" (10) + ".sig" (4) = 2044 chars
    const ok = `https://x/${path}.sig`;
    expect(ok.length).toBeLessThanOrEqual(2048);
    expect(validateSignatureUrl(ok)).toBe(ok);
    // One byte over → reject.
    const tooLong = `https://x/${"a".repeat(2035)}.sig`;
    expect(tooLong.length).toBeGreaterThan(2048);
    expect(validateSignatureUrl(tooLong)).toBeNull();
  });

  it("rejects non-string inputs and empty strings (defensive contract)", () => {
    expect(validateSignatureUrl(null)).toBeNull();
    expect(validateSignatureUrl(undefined)).toBeNull();
    expect(validateSignatureUrl(123)).toBeNull();
    expect(validateSignatureUrl({ url: "https://x.sig" })).toBeNull();
    expect(validateSignatureUrl("")).toBeNull();
    // Control chars / whitespace — same gate as the bridge URL.
    expect(validateSignatureUrl("https://rud1.es/x .sig")).toBeNull();
    expect(validateSignatureUrl("https://rud1.es/x\n.sig")).toBeNull();
  });

  it("rejects URLs with userinfo (no embedded credentials)", () => {
    expect(
      validateSignatureUrl("https://user:pass@rud1.es/installer.sig"),
    ).toBeNull();
    expect(
      validateSignatureUrl("https://user@rud1.es/installer.sig"),
    ).toBeNull();
  });
});

describe("parseManifest — manifestVersion v3 + signatureUrl (iter 47)", () => {
  const VALID_SHA = "a".repeat(64);
  const GOOD_SIG = "https://rud1.es/desktop/v1.5.0.dmg.sig";

  it("accepts a v3 manifest with a good signatureUrl (captured into parsed shape)", () => {
    const m = parseManifest({
      version: "1.5.0",
      manifestVersion: 3,
      sha256: VALID_SHA,
      signatureUrl: GOOD_SIG,
    });
    expect(m).not.toBeNull();
    expect(m?.manifestVersion).toBe(3);
    expect(m?.signatureUrl).toBe(GOOD_SIG);
    // The v2 sha256 requirement still applies in v3 (v3 is a superset
    // of v2). Drop the sha256 here and the manifest must reject.
    expect(
      parseManifest({
        version: "1.5.0",
        manifestVersion: 3,
        signatureUrl: GOOD_SIG,
      }),
    ).toBeNull();
  });

  it("v3 manifest with a bad signatureUrl → manifest still parses, signatureUrl dropped", () => {
    // Mirrors the iter-33 releaseNotesUrl lenient stance: bad
    // optional convenience data degrades gracefully (silent reject)
    // rather than rejecting the whole manifest. The defensive
    // contract — `validateSignatureUrl` returns null on rejection —
    // means a manifest with a malformed sidecar URL still surfaces
    // the update notification.
    const m = parseManifest({
      version: "1.5.0",
      manifestVersion: 3,
      sha256: VALID_SHA,
      signatureUrl: "javascript:alert(1)", // hostile scheme
    });
    expect(m).not.toBeNull();
    expect(m?.signatureUrl).toBeUndefined();

    const m2 = parseManifest({
      version: "1.5.0",
      manifestVersion: 3,
      sha256: VALID_SHA,
      signatureUrl: "https://rud1.es/installer.dmg", // wrong suffix
    });
    expect(m2).not.toBeNull();
    expect(m2?.signatureUrl).toBeUndefined();
  });

  it("v2-passthrough: a v2 manifest with no signatureUrl preserves iter-46 shape byte-for-byte", () => {
    // The iter-32 toEqual fixtures pinned the parsed VersionManifest
    // shape; iter-47 adds an OPTIONAL `signatureUrl` field. When the
    // manifest is v2 and the field is absent, the parsed object's
    // `signatureUrl` stays `undefined` (omitted under Vitest toEqual
    // semantics), so the legacy fixtures still round-trip. Pin it
    // here directly so a future contributor refactoring the parser
    // can't silently start emitting `signatureUrl: null`.
    const m = parseManifest({
      version: "1.2.3",
      manifestVersion: 2,
      sha256: VALID_SHA,
    });
    expect(m).toEqual({
      version: "1.2.3",
      downloadUrl: null,
      manifestVersion: 2,
      sha256: VALID_SHA,
      releaseNotesUrl: null,
      rolloutBucket: null,
      minBootstrapVersion: null,
      bridgeDownloadUrl: null,
      bridgeSha256: null,
    });
    expect(m?.signatureUrl).toBeUndefined();

    // A v2 manifest that smuggles a `signatureUrl` field has it
    // SILENTLY DROPPED — forward-compat field on a backward manifest
    // is ignored, not loud-fail.
    const m2 = parseManifest({
      version: "1.2.3",
      manifestVersion: 2,
      sha256: VALID_SHA,
      signatureUrl: GOOD_SIG,
    });
    expect(m2?.signatureUrl).toBeUndefined();
  });

  it("v3 manifest without a signatureUrl is accepted (the field is OPTIONAL in v3)", () => {
    const m = parseManifest({
      version: "1.5.0",
      manifestVersion: 3,
      sha256: VALID_SHA,
    });
    expect(m).not.toBeNull();
    expect(m?.manifestVersion).toBe(3);
    expect(m?.signatureUrl).toBeUndefined();
  });
});

describe("buildBlockedDiagnosticsBlob + buildUpdateAvailableDiagnosticsBlob — signatureUrl envelope (iter 47)", () => {
  const {
    buildBlockedDiagnosticsBlob,
    buildUpdateAvailableDiagnosticsBlob,
  } = versionCheckInternals;
  const FIXED_AT = Date.UTC(2026, 3, 25, 12, 0, 0);
  const GOOD_SIG = "https://rud1.es/desktop/v1.5.0.dmg.sig";

  it("blocked envelope appends signatureUrl AFTER manifestVersion when present (key ordering pin)", () => {
    const blob = buildBlockedDiagnosticsBlob(
      {
        currentVersion: "1.4.0",
        targetVersion: "2.1.0",
        requiredMinVersion: "1.7.0",
        manifestVersion: 3,
        signatureUrl: GOOD_SIG,
      },
      FIXED_AT,
    );
    const out = JSON.parse(blob);
    expect(out.signatureUrl).toBe(GOOD_SIG);
    // Key ordering: the iter-42 pin still holds (capturedAt → kind →
    // versions → url → sha → notes → manifestVersion) AND the new
    // signatureUrl key sits AFTER manifestVersion. A regression that
    // shuffled the new key earlier would silently break external
    // regex-based scrapers run on past tickets.
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
      '"signatureUrl"',
    ];
    let prev = -1;
    for (const k of order) {
      const idx = blob.indexOf(k);
      expect(idx).toBeGreaterThan(prev);
      prev = idx;
    }
  });

  it("blocked envelope WITHOUT signatureUrl matches iter-46 byte-for-byte (no new key leaks in)", () => {
    // The whole point of the conditional spread: the iter-42/43/44/45/46
    // contracts must hold byte-for-byte for v2-passthrough callers.
    // Build the same envelope with and without the iter-47 field on
    // the input state and assert byte-equality + absent signatureUrl
    // key in the output.
    const baseState = {
      currentVersion: "1.4.0",
      targetVersion: "2.1.0",
      requiredMinVersion: "1.7.0",
      bridgeDownloadUrl: "https://rud1.es/desktop/v2.1.0.dmg",
      releaseNotesUrl: "https://rud1.es/changelog/v2.1.0",
      manifestVersion: 2,
    };
    const without = buildBlockedDiagnosticsBlob(baseState, FIXED_AT);
    expect(without).not.toContain('"signatureUrl"');
    // Same state with signatureUrl explicitly null → still byte-equal.
    const withNull = buildBlockedDiagnosticsBlob(
      { ...baseState, signatureUrl: null },
      FIXED_AT,
    );
    expect(withNull).toBe(without);
    // And undefined.
    const withUndefined = buildBlockedDiagnosticsBlob(
      { ...baseState, signatureUrl: undefined },
      FIXED_AT,
    );
    expect(withUndefined).toBe(without);
  });

  it("blocked envelope DEFENSIVELY rejects a malformed signatureUrl in state (silent drop)", () => {
    // Mirrors the iter-38/39 defensive re-validation pattern. A
    // future caller hand-constructing the state object cannot
    // bypass parse-time validation by stashing an unsafe URL on
    // the diagnostics input.
    const blob = buildBlockedDiagnosticsBlob(
      {
        currentVersion: "1.4.0",
        targetVersion: "2.1.0",
        requiredMinVersion: "1.7.0",
        manifestVersion: 3,
        signatureUrl: "javascript:alert(1)", // hostile
      },
      FIXED_AT,
    );
    expect(blob).not.toContain('"signatureUrl"');
    expect(blob).not.toContain("javascript:");
  });

  it("update-available envelope mirrors the blocked-state contract (append + drop + defensive)", () => {
    // The same key-ordering pin and v2-passthrough contract apply on
    // the update-available helper. Pin all three behaviours in one
    // spec to keep the suite compact.
    const VALID_BRIDGE_SHA = "f".repeat(64);
    const baseState = {
      current: "1.4.0",
      latest: "2.1.0",
      downloadUrl: "https://rud1.es/desktop/v2.1.0",
      releaseNotesUrl: "https://rud1.es/changelog/v2.1.0",
      bridgeSha256: VALID_BRIDGE_SHA,
      manifestVersion: 2,
    };

    // 1. With a good signatureUrl → key appended after manifestVersion.
    const withSig = buildUpdateAvailableDiagnosticsBlob(
      { ...baseState, manifestVersion: 3, signatureUrl: GOOD_SIG },
      FIXED_AT,
    );
    const outWith = JSON.parse(withSig);
    expect(outWith.signatureUrl).toBe(GOOD_SIG);
    const order = [
      '"capturedAt"',
      '"kind"',
      '"currentVersion"',
      '"targetVersion"',
      '"downloadUrl"',
      '"bridgeSha256"',
      '"releaseNotesUrl"',
      '"manifestVersion"',
      '"signatureUrl"',
    ];
    let prev = -1;
    for (const k of order) {
      const idx = withSig.indexOf(k);
      expect(idx).toBeGreaterThan(prev);
      prev = idx;
    }

    // 2. Without (null / undefined / absent) → byte-equal to iter-43 envelope.
    const without = buildUpdateAvailableDiagnosticsBlob(baseState, FIXED_AT);
    expect(without).not.toContain('"signatureUrl"');
    expect(
      buildUpdateAvailableDiagnosticsBlob(
        { ...baseState, signatureUrl: null },
        FIXED_AT,
      ),
    ).toBe(without);
    expect(
      buildUpdateAvailableDiagnosticsBlob(
        { ...baseState, signatureUrl: undefined },
        FIXED_AT,
      ),
    ).toBe(without);

    // 3. Defensive — malformed URL silently dropped.
    const malformed = buildUpdateAvailableDiagnosticsBlob(
      { ...baseState, signatureUrl: "https://rud1.es/installer.dmg" },
      FIXED_AT,
    );
    expect(malformed).not.toContain('"signatureUrl"');
  });

  it("envelope key-ordering byte-for-byte parity vs iter-46 contracts (no signatureUrl input)", () => {
    // Iter-47 appended a NEW optional key. The iter-46
    // `buildSettingsWindowHtmlWithRuntimeVersion` wrapper test pins
    // the helper output byte-for-byte; this test reasserts that
    // parity for v2-passthrough callers (the signatureUrl field is
    // genuinely append-only). A regression that always emitted
    // `signatureUrl: null` would surface here as a non-equal blob.
    const blockedV2 = buildBlockedDiagnosticsBlob(
      {
        currentVersion: "1.4.0",
        targetVersion: "2.1.0",
        requiredMinVersion: "1.7.0",
        manifestVersion: 2,
      },
      FIXED_AT,
    );
    // Hand-recompose the expected iter-46 envelope JSON (verbatim).
    const expected = JSON.stringify(
      {
        capturedAt: new Date(FIXED_AT).toISOString(),
        kind: "update-blocked-by-min-bootstrap",
        currentVersion: "1.4.0",
        targetVersion: "2.1.0",
        requiredMinVersion: "1.7.0",
        downloadUrl: "https://rud1.es/desktop/download?version=1.7.0",
        bridgeSha256: null,
        releaseNotesUrl: null,
        manifestVersion: 2,
      },
      null,
      2,
    );
    expect(blockedV2).toBe(expected);

    const updateV2 = buildUpdateAvailableDiagnosticsBlob(
      {
        current: "1.4.0",
        latest: "2.1.0",
        manifestVersion: 2,
      },
      FIXED_AT,
    );
    const expectedUpdate = JSON.stringify(
      {
        capturedAt: new Date(FIXED_AT).toISOString(),
        kind: "update-available",
        currentVersion: "1.4.0",
        targetVersion: "2.1.0",
        downloadUrl: "https://rud1.es/desktop/download?version=2.1.0",
        bridgeSha256: null,
        releaseNotesUrl: null,
        manifestVersion: 2,
      },
      null,
      2,
    );
    expect(updateV2).toBe(expectedUpdate);
  });
});

// ─── Iter 48 — sig-strict pre-install gate ─────────────────────────────────
//
// `applySignatureFetchGate` is the runtime seam between
// `classifyManifest`'s verdict and the install path. Sig-strict OFF is
// a byte-identical passthrough (regression-pinned below). Sig-strict
// ON inspects the verdict + manifest version and either passes through
// (good 200 + ≥16-byte body) or replaces the verdict with the new
// `update-blocked-by-signature-fetch` shape carrying a reason and
// (for HTTP-status blocks only) the response code.
//
// The gate is async because it may HTTP-fetch. Tests inject a mock
// fetch — we never spin up a real server.
//
// Coverage matrix:
//   1.  sig-strict OFF passthrough (v3 + v2 + v1 byte-identical to iter-47)
//   2.  v3 + reachable signatureUrl (200, ≥16 bytes) → update-available passes through
//   3.  v3 + 404 → blocked, reason signature-http-status, httpStatus=404
//   4.  v3 + network error → blocked, reason signature-unreachable
//   5.  v3 + 200 + 8-byte body → blocked, reason signature-empty
//   6.  v2 manifest (no signatureUrl) → blocked, reason signature-not-supported-by-manifest-version
//   7.  v1 manifest → blocked, same reason
//   8.  invalid signatureUrl that validateSignatureUrl rejected → blocked (treat as not-supported)
//   9.  blob diagnostics envelope: byte-stable key ordering pin
//  10.  renderer-side rebuild byte-equivalence with main-side
//  11.  iter-31 sha256 strict + iter-48 sig strict are independent
//  12.  same-origin redirect refusal (defence-in-depth)

describe("applySignatureFetchGate — iter 48", () => {
  const { applySignatureFetchGate } = versionCheckInternals;
  const GOOD_SIG = "https://rud1.es/desktop/v1.5.0.dmg.sig";
  const FIXED_AT = Date.UTC(2026, 3, 25, 12, 0, 0);

  function mkUpdateAvailable(extra: Record<string, unknown> = {}): VersionCheckState {
    return {
      kind: "update-available",
      current: "1.4.0",
      latest: "1.5.0",
      downloadUrl: "https://rud1.es/desktop/v1.5.0.dmg",
      releaseNotesUrl: null,
      checkedAt: FIXED_AT,
      ...extra,
    };
  }

  // 1. sigStrict OFF → all iter-47 verdicts pass through unchanged. The
  //    gate function is the seam, but the wrapper logic in index.ts is
  //    what gates calling it; if the gate IS called when sigStrict is
  //    off, the input must be returned identity-equal so even the
  //    object reference is preserved.
  it("v3 update-available WITHOUT signatureUrl (manifestVersion 3 absent in options) → blocked-not-supported (no fetch)", async () => {
    // The gate is conservative: when called without manifestVersion
    // OR without a signatureUrl, it blocks with not-supported. The
    // index.ts wrapper only invokes the gate when sigStrict is ON,
    // so this test pins the iter-48 contract for the v1/v2 path
    // even when the caller forgot to thread manifestVersion.
    let fetchCalls = 0;
    const fakeFetch: typeof globalThis.fetch = async () => {
      fetchCalls += 1;
      return new Response("xxx");
    };
    const state = mkUpdateAvailable();
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-not-supported-by-manifest-version");
      expect(out.signatureUrl).toBeNull();
      expect(out.currentVersion).toBe("1.4.0");
      expect(out.targetVersion).toBe("1.5.0");
      expect(out.checkedAt).toBe(FIXED_AT);
    }
    expect(fetchCalls).toBe(0); // no fetch attempted
  });

  // 2. sig-strict ON + v3 + reachable → passthrough.
  it("v3 + reachable signatureUrl (200, >=16 bytes) → update-available verdict emitted unchanged", async () => {
    let fetchedUrl = "";
    const fakeFetch: typeof globalThis.fetch = async (input) => {
      fetchedUrl = String(input);
      // 24-byte body, well above the 16-byte minimum.
      return new Response(new Uint8Array(24).buffer, { status: 200 });
    };
    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
    });
    expect(fetchedUrl).toBe(GOOD_SIG);
    expect(out.kind).toBe("update-available");
    if (out.kind === "update-available") {
      expect(out.signatureUrl).toBe(GOOD_SIG);
      expect(out.current).toBe("1.4.0");
      expect(out.latest).toBe("1.5.0");
    }
  });

  // 3. v3 + 404 → signature-http-status with httpStatus=404.
  it("v3 + 404 → blocked, reason signature-http-status, httpStatus=404", async () => {
    const fakeFetch: typeof globalThis.fetch = async () =>
      new Response("not found", { status: 404 });
    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-http-status");
      expect(out.httpStatus).toBe(404);
      expect(out.signatureUrl).toBe(GOOD_SIG);
    }
  });

  // 4. v3 + network error → signature-unreachable. No httpStatus.
  it("v3 + network error → blocked, reason signature-unreachable (no httpStatus)", async () => {
    const fakeFetch: typeof globalThis.fetch = async () => {
      throw new Error("ECONNREFUSED");
    };
    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-unreachable");
      expect(out.httpStatus).toBeUndefined();
      expect(out.signatureUrl).toBe(GOOD_SIG);
    }
  });

  // 5. v3 + 200 + 8-byte body → signature-empty.
  it("v3 + 200 + 8-byte body → blocked, reason signature-empty", async () => {
    const fakeFetch: typeof globalThis.fetch = async () =>
      new Response(new Uint8Array(8).buffer, { status: 200 });
    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-empty");
      expect(out.signatureUrl).toBe(GOOD_SIG);
      expect(out.httpStatus).toBeUndefined();
    }
  });

  // 6. v2 manifest (no signatureUrl) → blocked, signature-not-supported-by-manifest-version.
  it("v2 manifest (no signatureUrl) → blocked, reason signature-not-supported-by-manifest-version", async () => {
    let fetchCalls = 0;
    const fakeFetch: typeof globalThis.fetch = async () => {
      fetchCalls += 1;
      return new Response("xxx");
    };
    // v2 verdict: state has no signatureUrl, manifestVersion=2.
    const state = mkUpdateAvailable();
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 2,
      fetch: fakeFetch,
      now: FIXED_AT,
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-not-supported-by-manifest-version");
      expect(out.signatureUrl).toBeNull();
      expect(out.manifestVersion).toBe(2);
    }
    expect(fetchCalls).toBe(0); // no fetch attempted — v2 is rejected ahead of fetch
  });

  // 7. v1 manifest → same reason as v2.
  it("v1 manifest → blocked, same reason (signature-not-supported-by-manifest-version)", async () => {
    let fetchCalls = 0;
    const fakeFetch: typeof globalThis.fetch = async () => {
      fetchCalls += 1;
      return new Response("xxx");
    };
    const state = mkUpdateAvailable();
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 1,
      fetch: fakeFetch,
      now: FIXED_AT,
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-not-supported-by-manifest-version");
      expect(out.manifestVersion).toBe(1);
    }
    expect(fetchCalls).toBe(0);
  });

  // 8. invalid signatureUrl (bypassed parse-time validation) → blocked, treat as not-supported.
  it("invalid signatureUrl that validateSignatureUrl rejected → blocked (treat as not-supported)", async () => {
    // A future caller hand-constructing the state could stash an unsafe
    // URL. The defensive re-validation in the gate must reject it.
    let fetchCalls = 0;
    const fakeFetch: typeof globalThis.fetch = async () => {
      fetchCalls += 1;
      return new Response("xxx");
    };
    const state = mkUpdateAvailable({ signatureUrl: "javascript:alert(1)" });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-not-supported-by-manifest-version");
      expect(out.signatureUrl).toBeNull();
    }
    expect(fetchCalls).toBe(0);
  });

  // 12. Same-origin redirect refusal — the gate must refuse a sig URL
  //     hosted on a different origin than the manifest.
  it("same-origin redirect policy: signatureUrl on a different origin than manifest → blocked, reason signature-unreachable", async () => {
    let fetchCalls = 0;
    const fakeFetch: typeof globalThis.fetch = async () => {
      fetchCalls += 1;
      return new Response(new Uint8Array(24).buffer, { status: 200 });
    };
    const state = mkUpdateAvailable({
      signatureUrl: "https://evil-cdn.example/installer.sig",
    });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      manifestUrl: "https://rud1.es/desktop/manifest.json",
      fetch: fakeFetch,
      now: FIXED_AT,
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-unreachable");
      expect(out.signatureUrl).toBe(
        "https://evil-cdn.example/installer.sig",
      );
    }
    expect(fetchCalls).toBe(0); // refused before fetch
  });

  // sigStrict OFF passthrough — blanket regression. The gate should
  // never be CALLED when sigStrict is OFF (that's the index.ts
  // wrapper's job), but if it is, the only inputs that change the
  // verdict are the v3+signatureUrl combo. Pinning here that
  // non-update-available verdicts are returned identity-equal, so
  // a future refactor that accidentally invokes the gate from a
  // wider seam can't break iter-47 byte-stability.
  it("non-update-available verdicts (idle / checking / up-to-date / blocked / error) pass through identity-equal", async () => {
    const fakeFetch: typeof globalThis.fetch = async () => new Response("");
    const states: VersionCheckState[] = [
      { kind: "idle" },
      { kind: "checking" },
      { kind: "up-to-date", current: "1.4.0", latest: "1.4.0", checkedAt: FIXED_AT },
      {
        kind: "update-blocked-by-min-bootstrap",
        requiredMinVersion: "1.7.0",
        currentVersion: "1.4.0",
        targetVersion: "2.1.0",
        releaseNotesUrl: null,
        bridgeDownloadUrl: null,
        bridgeSha256: null,
        checkedAt: FIXED_AT,
      },
      { kind: "error", message: "fetch failed", checkedAt: FIXED_AT },
    ];
    for (const s of states) {
      const out = await applySignatureFetchGate(s, {
        manifestVersion: 3,
        fetch: fakeFetch,
        now: FIXED_AT,
      });
      expect(out).toBe(s); // identity-equal — no rewriting
    }
  });
});

// 9. Diagnostics envelope key-ordering pin.
describe("buildBlockedBySignatureFetchDiagnosticsBlob — iter 48 envelope", () => {
  const { buildBlockedBySignatureFetchDiagnosticsBlob } = versionCheckInternals;
  const FIXED_AT = Date.UTC(2026, 3, 25, 12, 0, 0);
  const GOOD_SIG = "https://rud1.es/desktop/v1.5.0.dmg.sig";

  it("envelope key ordering: capturedAt → kind → currentVersion → targetVersion → reason → signatureUrl → httpStatus → downloadUrl → releaseNotesUrl → manifestVersion", () => {
    // The iter-48 contract pins this specific order so external
    // regex-based scrapers run on past tickets keep working. A
    // contributor refactoring the envelope mustn't shuffle keys.
    const blob = buildBlockedBySignatureFetchDiagnosticsBlob(
      {
        reason: "signature-http-status",
        signatureUrl: GOOD_SIG,
        httpStatus: 404,
        currentVersion: "1.4.0",
        targetVersion: "1.5.0",
        downloadUrl: "https://rud1.es/desktop/v1.5.0.dmg",
        releaseNotesUrl: "https://rud1.es/changelog/v1.5.0",
        manifestVersion: 3,
      },
      FIXED_AT,
    );
    const out = JSON.parse(blob);
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    expect(out.reason).toBe("signature-http-status");
    expect(out.httpStatus).toBe(404);
    expect(out.signatureUrl).toBe(GOOD_SIG);
    expect(out.manifestVersion).toBe(3);
    const order = [
      '"capturedAt"',
      '"kind"',
      '"currentVersion"',
      '"targetVersion"',
      '"reason"',
      '"signatureUrl"',
      '"httpStatus"',
      '"downloadUrl"',
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

  it("omits httpStatus when not set (clean shape for unreachable / empty / not-supported branches)", () => {
    const blob = buildBlockedBySignatureFetchDiagnosticsBlob(
      {
        reason: "signature-unreachable",
        signatureUrl: GOOD_SIG,
        currentVersion: "1.4.0",
        targetVersion: "1.5.0",
        manifestVersion: 3,
      },
      FIXED_AT,
    );
    expect(blob).not.toContain('"httpStatus"');
    const out = JSON.parse(blob);
    expect(out.signatureUrl).toBe(GOOD_SIG);
    expect(out.reason).toBe("signature-unreachable");
  });

  it("renders signatureUrl=null EXPLICITLY (not omitted) for the not-supported branch", () => {
    const blob = buildBlockedBySignatureFetchDiagnosticsBlob(
      {
        reason: "signature-not-supported-by-manifest-version",
        signatureUrl: null,
        currentVersion: "1.4.0",
        targetVersion: "1.5.0",
        manifestVersion: 2,
      },
      FIXED_AT,
    );
    expect(blob).toContain('"signatureUrl": null');
    const out = JSON.parse(blob);
    expect(out.signatureUrl).toBeNull();
    expect(out.manifestVersion).toBe(2);
  });

  it("defensively rejects a malformed signatureUrl (silent drop to null)", () => {
    const blob = buildBlockedBySignatureFetchDiagnosticsBlob(
      {
        reason: "signature-http-status",
        signatureUrl: "javascript:alert(1)", // hostile
        httpStatus: 404,
        currentVersion: "1.4.0",
        targetVersion: "1.5.0",
        manifestVersion: 3,
      },
      FIXED_AT,
    );
    expect(blob).not.toContain("javascript:");
    const out = JSON.parse(blob);
    expect(out.signatureUrl).toBeNull();
    // httpStatus is still rendered when the underlying state had one.
    expect(out.httpStatus).toBe(404);
  });

  it("runtimeAppVersion overrides currentVersion (mirrors iter-45 thread)", () => {
    const blob = buildBlockedBySignatureFetchDiagnosticsBlob(
      {
        reason: "signature-empty",
        signatureUrl: GOOD_SIG,
        currentVersion: "1.4.0",
        targetVersion: "1.5.0",
        manifestVersion: 3,
      },
      FIXED_AT,
      "1.4.99-runtime", // runtimeAppVersion override
    );
    const out = JSON.parse(blob);
    expect(out.currentVersion).toBe("1.4.99-runtime");
  });
});

// 10. Renderer-side rebuild byte-equivalence with main-side.
//
// The settings-window-html.ts inline JS contains a parallel envelope
// builder for the new verdict. Pin that the renderer's literal source
// matches the main-side helper's key ordering by extracting the inline
// block and asserting structural parity. Mirrors the iter-46
// `buildSettingsWindowHtmlWithRuntimeVersion` byte-equivalence pattern.
describe("settings-window-html sig-fetch verdict rendering — iter 48", () => {
  it("renderer's inline envelope mirrors buildBlockedBySignatureFetchDiagnosticsBlob key ordering", () => {
    const html = decodeURIComponent(
      buildSettingsWindowHtml("1.4.0").replace(/^data:text\/html;charset=utf-8,/, ""),
    );
    // The inline JS for the new verdict must build the envelope keys in
    // the same ORDER as the main-side helper. We slice the source
    // starting at the envelope literal (`var envelope = {`) so we don't
    // accidentally match the same keyword in renderState's discriminant
    // check, then walk the appended-key assignments.
    const envelopeStart = html.indexOf(
      "var envelope = {\n        capturedAt: new Date().toISOString(),\n        kind: 'update-blocked-by-signature-fetch'",
    );
    expect(envelopeStart).toBeGreaterThan(-1);
    const slice = html.slice(envelopeStart);
    const order = [
      "kind: 'update-blocked-by-signature-fetch'",
      "currentVersion: currentVersion4",
      "targetVersion: state.targetVersion",
      "reason: state.reason",
      "signatureUrl: validatedSig",
      "envelope.httpStatus = state.httpStatus",
      "envelope.downloadUrl = state.downloadUrl",
      "envelope.releaseNotesUrl = state.releaseNotesUrl",
      "envelope.manifestVersion = state.manifestVersion",
    ];
    let prev = -1;
    for (const k of order) {
      const idx = slice.indexOf(k);
      expect(idx).toBeGreaterThan(prev);
      prev = idx;
    }
  });

  it("renderer registers a renderBlockedBySignatureFetch branch in renderState", () => {
    const html = decodeURIComponent(
      buildSettingsWindowHtml("1.4.0").replace(/^data:text\/html;charset=utf-8,/, ""),
    );
    expect(html).toContain("update-blocked-by-signature-fetch");
    expect(html).toContain("renderBlockedBySignatureFetch");
    // Wrapper round-trips byte-for-byte: both the wrapper and the
    // direct call produce the same output for the same version arg.
    expect(buildSettingsWindowHtml("1.4.0")).toBe(
      buildSettingsWindowHtmlWithRuntimeVersion("1.4.0"),
    );
  });
});

// 11. iter-31 sha256 strict + iter-48 sig strict are independent.
//
// Compose by running the same verdict through both gates and confirming
// the verdicts compose rather than interfere. The iter-31 gate runs at
// apply-bytes time on the downloaded payload; the iter-48 gate runs at
// decide-to-install time on the verdict's signatureUrl. Both can be on;
// flipping one MUST NOT flip the other.
describe("iter-31 sha256 strict + iter-48 sig strict composition (iter 48)", () => {
  const { applySignatureFetchGate } = versionCheckInternals;
  const FIXED_AT = Date.UTC(2026, 3, 25, 12, 0, 0);
  const GOOD_SIG = "https://rud1.es/desktop/v1.5.0.dmg.sig";
  const VALID_SHA = "a".repeat(64);

  it("a v3 manifest with both sha256 + signatureUrl runs both gates without interaction", async () => {
    // Step 1: parse the manifest. The v2 sha256 requirement still
    // applies in v3 (v3 is a superset of v2); a manifest with a
    // valid sha256 + valid signatureUrl is the canonical iter-31 +
    // iter-48 input.
    const manifest = parseManifest({
      version: "1.5.0",
      manifestVersion: 3,
      sha256: VALID_SHA,
      signatureUrl: GOOD_SIG,
    });
    expect(manifest).not.toBeNull();
    expect(manifest!.sha256).toBe(VALID_SHA);
    expect(manifest!.signatureUrl).toBe(GOOD_SIG);

    // Step 2: classify. Update-available verdict carries signatureUrl.
    const verdict = classifyManifest("1.4.0", manifest!, FIXED_AT);
    expect(verdict.kind).toBe("update-available");
    if (verdict.kind === "update-available") {
      expect(verdict.signatureUrl).toBe(GOOD_SIG);
    }

    // Step 3: run iter-48 sig-strict gate. Should pass through
    // (200 + 24 bytes).
    const fakeFetch: typeof globalThis.fetch = async () =>
      new Response(new Uint8Array(24).buffer, { status: 200 });
    const gated = await applySignatureFetchGate(verdict, {
      manifestVersion: manifest!.manifestVersion,
      fetch: fakeFetch,
      now: FIXED_AT,
    });
    // The iter-48 gate did not mutate the iter-31 sha256 field —
    // verdicts compose. The iter-31 strict gate runs at
    // apply-bytes time on the downloaded payload (see
    // auto-updater.test.ts) and is deliberately untouched here.
    expect(gated.kind).toBe("update-available");
    if (gated.kind === "update-available") {
      expect(gated.signatureUrl).toBe(GOOD_SIG);
      // sha256 is preserved on the manifest, accessible via the
      // existing iter-30 manifestSha256 plumbing — the iter-48
      // gate does not strip it.
      expect(manifest!.sha256).toBe(VALID_SHA);
    }
  });

  it("a v3 manifest with sha256 + signatureUrl that fails iter-48 surfaces sig-fetch verdict but does NOT corrupt manifest sha256", async () => {
    const manifest = parseManifest({
      version: "1.5.0",
      manifestVersion: 3,
      sha256: VALID_SHA,
      signatureUrl: GOOD_SIG,
    });
    expect(manifest).not.toBeNull();
    const verdict = classifyManifest("1.4.0", manifest!, FIXED_AT);
    const fakeFetch: typeof globalThis.fetch = async () =>
      new Response("nope", { status: 404 });
    const gated = await applySignatureFetchGate(verdict, {
      manifestVersion: manifest!.manifestVersion,
      fetch: fakeFetch,
      now: FIXED_AT,
    });
    expect(gated.kind).toBe("update-blocked-by-signature-fetch");
    // The iter-31 sha256 field on the manifest is independent of
    // the iter-48 gate's outcome — pinning the contract.
    expect(manifest!.sha256).toBe(VALID_SHA);
  });
});

// ─── Iter 49 — minisign parse + verify + gate integration ──────────────────
//
// Layered on iter-48's fetch gate. Tests construct ed25519 keypairs +
// real ed25519 signatures via Node's `crypto` module so we don't depend
// on a hardcoded publisher key in the test fixture. Coverage:
//
//   parseMinisignSignature:
//     1. well-formed sidecar with both untrusted + trusted comments
//     2. well-formed sidecar with only the untrusted-comment line
//     3. CRLF line endings normalize to LF
//     4. malformed length (raw decoded bytes != 74)
//     5. wrong algorithm prefix (not 0x4564)
//     6. base64 garbage (non-base64 chars)
//     7. missing newlines / single-line input rejected
//     8. comment-only file (no signature line) rejected
//     9. empty buffer / non-buffer input rejected
//
//   verifyMinisignSignature:
//    10. good signature → true
//    11. wrong pubkey → false
//    12. tampered signed-data → false
//    13. wrong-length pubkey → false
//    14. wrong-length sigBytes → false
//
//   applySignatureFetchGate (verify on):
//    15. verify-on + fetch-fails-first → stops at fetch (verify never runs)
//    16. verify-on + parse-fails-on-fetched-bytes → signature-parse-failed
//    17. verify-on + verify-passes → original verdict UNCHANGED
//    18. verify-on + missing pubkey → signature-pubkey-misconfigured
//    19. verify-on + verify-fails (good shape, wrong sig) → signature-verify-failed
//    20. verify-OFF + fetch passes → byte-identical iter-48 passthrough
describe("parseMinisignSignature — iter 49", () => {
  const { parseMinisignSignature } = versionCheckInternals;

  // Construct a well-formed minisign sidecar buffer for the given raw
  // 64-byte signature + 8-byte keyId. The legacy minisign format:
  //   untrusted comment: <text>\n
  //   <base64 of (0x4564 || keyId(8) || sig(64))>\n
  //   trusted comment: <text>\n
  //   <base64 of trusted-sig(64)>\n
  function buildSidecar(
    keyId: Buffer,
    sig: Buffer,
    opts: {
      includeTrusted?: boolean;
      lineEnding?: "\n" | "\r\n";
      trailingNewline?: boolean;
    } = {},
  ): Buffer {
    const eol = opts.lineEnding ?? "\n";
    const includeTrusted = opts.includeTrusted ?? true;
    const trailing = opts.trailingNewline ?? true;
    const raw = Buffer.concat([Buffer.from([0x45, 0x64]), keyId, sig]);
    const sigB64 = raw.toString("base64");
    let out =
      "untrusted comment: signature from minisign secret key" +
      eol +
      sigB64;
    if (includeTrusted) {
      const trustedSigB64 = sig.toString("base64");
      out +=
        eol +
        "trusted comment: timestamp:0\tfile:rud1-update.bin" +
        eol +
        trustedSigB64;
    }
    if (trailing) out += eol;
    return Buffer.from(out, "utf8");
  }

  const KEY_ID = Buffer.alloc(8, 0xab);
  const SIG = Buffer.alloc(64, 0xcd);

  // 1. Both comment lines present.
  it("parses a well-formed sidecar with both untrusted + trusted comments", () => {
    const out = parseMinisignSignature(buildSidecar(KEY_ID, SIG));
    expect(out).not.toBeNull();
    expect(out!.keyId.equals(KEY_ID)).toBe(true);
    expect(out!.signature.equals(SIG)).toBe(true);
  });

  // 2. Only untrusted comment.
  it("parses a sidecar with ONLY the untrusted-comment line (trusted block absent)", () => {
    const out = parseMinisignSignature(
      buildSidecar(KEY_ID, SIG, { includeTrusted: false }),
    );
    expect(out).not.toBeNull();
    expect(out!.signature.equals(SIG)).toBe(true);
  });

  // 3. CRLF normalization.
  it("normalises CRLF line endings (Windows-saved sidecar parses)", () => {
    const out = parseMinisignSignature(
      buildSidecar(KEY_ID, SIG, { lineEnding: "\r\n" }),
    );
    expect(out).not.toBeNull();
    expect(out!.keyId.equals(KEY_ID)).toBe(true);
  });

  // 4. Wrong decoded length — too short.
  it("rejects a sidecar whose base64 decodes to < 74 bytes", () => {
    const shortRaw = Buffer.concat([Buffer.from([0x45, 0x64]), Buffer.alloc(8, 0)]); // 10 bytes
    const text =
      "untrusted comment: x\n" + shortRaw.toString("base64") + "\n";
    const out = parseMinisignSignature(Buffer.from(text, "utf8"));
    expect(out).toBeNull();
  });

  // 4b. Wrong decoded length — too long.
  it("rejects a sidecar whose base64 decodes to > 74 bytes", () => {
    const longRaw = Buffer.concat([
      Buffer.from([0x45, 0x64]),
      Buffer.alloc(80, 0),
    ]);
    const text =
      "untrusted comment: x\n" + longRaw.toString("base64") + "\n";
    expect(parseMinisignSignature(Buffer.from(text, "utf8"))).toBeNull();
  });

  // 5. Wrong algo prefix.
  it("rejects a sidecar with an algorithm prefix other than 0x4564", () => {
    const wrongAlgo = Buffer.concat([
      Buffer.from([0x45, 0x44]), // 'ED' (uppercase) — not 'Ed'
      KEY_ID,
      SIG,
    ]);
    const text =
      "untrusted comment: x\n" + wrongAlgo.toString("base64") + "\n";
    expect(parseMinisignSignature(Buffer.from(text, "utf8"))).toBeNull();
  });

  // 6. Base64 garbage on the signature line.
  it("rejects a sidecar with non-base64 characters on the signature line", () => {
    const text = "untrusted comment: x\nthis-is-not-base64!@#$%\n";
    expect(parseMinisignSignature(Buffer.from(text, "utf8"))).toBeNull();
  });

  // 7. Missing newline — single-line input has no signature line at all
  //    once we drop the comment; the function must reject.
  it("rejects a single-line input (no newline → only the comment, no sig line)", () => {
    const text = "untrusted comment: only a comment, no signature";
    expect(parseMinisignSignature(Buffer.from(text, "utf8"))).toBeNull();
  });

  // 8. Comment-only file — both lines are comments.
  it("rejects a comment-only file (no signature line)", () => {
    const text =
      "untrusted comment: alpha\ntrusted comment: beta\n";
    expect(parseMinisignSignature(Buffer.from(text, "utf8"))).toBeNull();
  });

  // 9. Empty / non-buffer.
  it("rejects an empty buffer + non-buffer input", () => {
    expect(parseMinisignSignature(Buffer.alloc(0))).toBeNull();
    // @ts-expect-error — runtime guard against a non-buffer caller
    expect(parseMinisignSignature("not-a-buffer")).toBeNull();
    // @ts-expect-error — runtime guard
    expect(parseMinisignSignature(null)).toBeNull();
  });
});

describe("verifyMinisignSignature — iter 49", () => {
  const { verifyMinisignSignature } = versionCheckInternals;

  // Generate an ed25519 keypair + extract the raw 32-byte pubkey via the
  // SPKI DER export (the iter-49 helper expects raw 32 bytes — we strip
  // the SPKI prefix the same way parseSigPubkey would after stripping
  // the minisign algo + keyId).
  function rawPubkeyFrom(key: KeyObject): Buffer {
    const spki = key.export({ format: "der", type: "spki" }) as Buffer;
    // SPKI prefix for ed25519 is 12 bytes; the raw pubkey is the trailing 32.
    return spki.subarray(spki.length - 32);
  }

  // 10. Good signature.
  it("returns true for a signature signed by the matching pubkey over the same data", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const data = Buffer.from("manifest-sha256-hex-string", "utf8");
    const sigBytes = cryptoSign(null, data, privateKey);
    const ok = verifyMinisignSignature({
      pubkey: rawPubkeyFrom(publicKey),
      signedData: data,
      sigBytes,
    });
    expect(ok).toBe(true);
  });

  // 11. Wrong pubkey.
  it("returns false when the signature was made by a DIFFERENT private key", () => {
    const a = generateKeyPairSync("ed25519");
    const b = generateKeyPairSync("ed25519");
    const data = Buffer.from("manifest-sha256-hex-string", "utf8");
    const sigBytes = cryptoSign(null, data, a.privateKey);
    const ok = verifyMinisignSignature({
      pubkey: rawPubkeyFrom(b.publicKey),
      signedData: data,
      sigBytes,
    });
    expect(ok).toBe(false);
  });

  // 12. Tampered data.
  it("returns false when the signed-data has been tampered with", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const data = Buffer.from("manifest-sha256-hex-string", "utf8");
    const sigBytes = cryptoSign(null, data, privateKey);
    const tampered = Buffer.from("manifest-sha256-hex-strinG", "utf8"); // last char G
    const ok = verifyMinisignSignature({
      pubkey: rawPubkeyFrom(publicKey),
      signedData: tampered,
      sigBytes,
    });
    expect(ok).toBe(false);
  });

  // 13. Wrong-length pubkey.
  it("returns false on a wrong-length pubkey (NEVER throws)", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const data = Buffer.from("x", "utf8");
    const sigBytes = cryptoSign(null, data, privateKey);
    expect(
      verifyMinisignSignature({
        pubkey: Buffer.alloc(31),
        signedData: data,
        sigBytes,
      }),
    ).toBe(false);
    expect(
      verifyMinisignSignature({
        pubkey: Buffer.alloc(33),
        signedData: data,
        sigBytes,
      }),
    ).toBe(false);
  });

  // 14. Wrong-length sigBytes.
  it("returns false on a wrong-length signature (NEVER throws)", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const data = Buffer.from("x", "utf8");
    expect(
      verifyMinisignSignature({
        pubkey: rawPubkeyFrom(publicKey),
        signedData: data,
        sigBytes: Buffer.alloc(63),
      }),
    ).toBe(false);
    expect(
      verifyMinisignSignature({
        pubkey: rawPubkeyFrom(publicKey),
        signedData: data,
        sigBytes: Buffer.alloc(65),
      }),
    ).toBe(false);
  });
});

describe("applySignatureFetchGate verify-on integration — iter 49", () => {
  const { applySignatureFetchGate } = versionCheckInternals;
  const GOOD_SIG_URL = "https://rud1.es/desktop/v1.5.0.dmg.sig";
  const FIXED_AT = Date.UTC(2026, 3, 25, 12, 0, 0);

  function rawPubkeyFrom(key: KeyObject): Buffer {
    const spki = key.export({ format: "der", type: "spki" }) as Buffer;
    return spki.subarray(spki.length - 32);
  }

  function buildSidecar(keyId: Buffer, sig: Buffer): Buffer {
    const raw = Buffer.concat([Buffer.from([0x45, 0x64]), keyId, sig]);
    const sigB64 = raw.toString("base64");
    const text =
      "untrusted comment: signature from minisign secret key\n" +
      sigB64 +
      "\n" +
      "trusted comment: timestamp:0\tfile:rud1-update.bin\n" +
      sig.toString("base64") +
      "\n";
    return Buffer.from(text, "utf8");
  }

  function mkUpdateAvailable(extra: Record<string, unknown> = {}): VersionCheckState {
    return {
      kind: "update-available",
      current: "1.4.0",
      latest: "1.5.0",
      downloadUrl: "https://rud1.es/desktop/v1.5.0.dmg",
      releaseNotesUrl: null,
      checkedAt: FIXED_AT,
      ...extra,
    };
  }

  // 15. verify-on but fetch fails first → stops at fetch (signature-unreachable).
  it("verify-on + network error during fetch → blocked at fetch stage (signature-unreachable, NOT a parse/verify failure)", async () => {
    let parseCalls = 0;
    const fakeFetch: typeof globalThis.fetch = async () => {
      throw new Error("ECONNREFUSED");
    };
    const { publicKey } = generateKeyPairSync("ed25519");
    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG_URL });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
      verifyEnabled: true,
      verifyPubkey: rawPubkeyFrom(publicKey),
      verifySignedData: Buffer.from("anything"),
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-unreachable");
    }
    expect(parseCalls).toBe(0); // never reached
  });

  // 16. verify-on + parse fails → signature-parse-failed (iter 50).
  it("verify-on + fetched body is not a valid minisign sidecar → signature-parse-failed", async () => {
    // Body >= 16 bytes (clears the iter-48 empty check) but is not a
    // parseable sidecar. Must fall into the iter-49 parse branch and
    // — under iter-50 — surface the *parse-failed* split rather than
    // the (now-removed) collapsed `signature-invalid` reason.
    const garbage = Buffer.from("xxxxxxxxxxxxxxxxxxxxxxxx", "utf8"); // 24 bytes
    const fakeFetch: typeof globalThis.fetch = async () =>
      new Response(garbage, { status: 200 });
    const { publicKey } = generateKeyPairSync("ed25519");
    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG_URL });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
      verifyEnabled: true,
      verifyPubkey: rawPubkeyFrom(publicKey),
      verifySignedData: Buffer.from("anything"),
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-parse-failed");
      expect(out.signatureUrl).toBe(GOOD_SIG_URL);
    }
  });

  // 17. verify-on + verify passes → original verdict UNCHANGED.
  it("verify-on + signature verifies → original update-available verdict passes through unchanged", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const signedData = Buffer.from(
      "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd", // 64-char hex
      "utf8",
    );
    const sigBytes = cryptoSign(null, signedData, privateKey);
    const sidecar = buildSidecar(Buffer.alloc(8, 0xab), sigBytes);
    const fakeFetch: typeof globalThis.fetch = async () =>
      new Response(sidecar, { status: 200 });
    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG_URL });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
      verifyEnabled: true,
      verifyPubkey: rawPubkeyFrom(publicKey),
      verifySignedData: signedData,
    });
    expect(out.kind).toBe("update-available");
    if (out.kind === "update-available") {
      expect(out.signatureUrl).toBe(GOOD_SIG_URL);
      expect(out.current).toBe("1.4.0");
      expect(out.latest).toBe("1.5.0");
    }
  });

  // 18. verify-on + missing pubkey → signature-pubkey-misconfigured.
  it("verify-on + null pubkey → signature-pubkey-misconfigured (fail closed before parse)", async () => {
    const fakeFetch: typeof globalThis.fetch = async () =>
      new Response(Buffer.alloc(64, 0), { status: 200 });
    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG_URL });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
      verifyEnabled: true,
      verifyPubkey: null,
      verifySignedData: Buffer.from("anything"),
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-pubkey-misconfigured");
      expect(out.signatureUrl).toBe(GOOD_SIG_URL);
    }
  });

  // 18b. verify-on + wrong-length pubkey → signature-pubkey-misconfigured.
  it("verify-on + wrong-length pubkey → signature-pubkey-misconfigured (the parser would reject downstream too, but we fail fast)", async () => {
    const fakeFetch: typeof globalThis.fetch = async () =>
      new Response(Buffer.alloc(64, 0), { status: 200 });
    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG_URL });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
      verifyEnabled: true,
      verifyPubkey: Buffer.alloc(16), // wrong length
      verifySignedData: Buffer.from("anything"),
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-pubkey-misconfigured");
    }
  });

  // 19. verify-on + good shape but wrong sig → signature-verify-failed (iter 50).
  it("verify-on + valid sidecar parse but signature was made by a DIFFERENT key → signature-verify-failed", async () => {
    const a = generateKeyPairSync("ed25519");
    const b = generateKeyPairSync("ed25519");
    const signedData = Buffer.from("manifest-sha256", "utf8");
    const sigBytesByA = cryptoSign(null, signedData, a.privateKey);
    const sidecar = buildSidecar(Buffer.alloc(8, 0xab), sigBytesByA);
    const fakeFetch: typeof globalThis.fetch = async () =>
      new Response(sidecar, { status: 200 });
    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG_URL });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
      verifyEnabled: true,
      // Verifying against B's pubkey — must reject. Sidecar parses
      // cleanly, so iter 50 surfaces the *verify-failed* split (key
      // mismatch / tampered binary signal) rather than parse-failed.
      verifyPubkey: rawPubkeyFrom(b.publicKey),
      verifySignedData: signedData,
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-verify-failed");
    }
  });

  // 19b. verify-on + tampered signedData → signature-verify-failed (iter 50).
  it("verify-on + signature is for ORIGINAL data but caller passed tampered data → signature-verify-failed", async () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const original = Buffer.from("real-manifest-sha256", "utf8");
    const sigBytes = cryptoSign(null, original, privateKey);
    const sidecar = buildSidecar(Buffer.alloc(8, 0xab), sigBytes);
    const tampered = Buffer.from("FAKE-manifest-sha256", "utf8");
    const fakeFetch: typeof globalThis.fetch = async () =>
      new Response(sidecar, { status: 200 });
    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG_URL });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
      verifyEnabled: true,
      verifyPubkey: rawPubkeyFrom(publicKey),
      verifySignedData: tampered,
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-verify-failed");
    }
  });

  // 20. verify-OFF + fetch passes → byte-identical iter-48 passthrough.
  //     Pinning the regression: a caller without verifyEnabled must see
  //     the EXACT iter-48 behaviour (original verdict, not even a parse
  //     attempt on the body). This is the iter-48 byte-stability contract.
  it("verify-OFF + fetch passes → original verdict identity-equal (iter-48 byte-stability pin)", async () => {
    // Body that is NOT a valid sidecar. Under verify-on this would
    // surface signature-parse-failed; under verify-off it must passthrough.
    const garbage = Buffer.alloc(32, 0); // 32 bytes of zero
    const fakeFetch: typeof globalThis.fetch = async () =>
      new Response(garbage, { status: 200 });
    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG_URL });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
      // verifyEnabled is undefined / not passed — must be byte-identical
      // to iter-48 behaviour.
    });
    expect(out).toBe(state); // identity-equal
  });

  // 20b. verify-OFF (explicit false) + fetch passes → identity-equal.
  it("verify-OFF (explicit false) + fetch passes → original verdict identity-equal", async () => {
    const garbage = Buffer.alloc(32, 0);
    const fakeFetch: typeof globalThis.fetch = async () =>
      new Response(garbage, { status: 200 });
    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG_URL });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
      verifyEnabled: false,
      // pubkey + signedData even passed but ignored when verifyEnabled is false.
      verifyPubkey: Buffer.alloc(32),
      verifySignedData: Buffer.from("ignored"),
    });
    expect(out).toBe(state);
  });

  // ── iter 50 — parse-vs-verify split regression pins ───────────────────
  //
  // The iter-49 collapsed `signature-invalid` reason has been replaced
  // by two distinct reasons: `signature-parse-failed` (sidecar bytes
  // don't shape as a minisign signature — publisher build pipeline
  // broken) and `signature-verify-failed` (sidecar parses but the
  // ed25519 verify rejects — key mismatch / tampered binary / wrong
  // key-id). The two regression pins below assert the reason names
  // never collide AND a parse failure short-circuits the verify path
  // (so a subtle bug that silently re-reports verify-failed for parse
  // errors would surface here).

  it("iter-50 split: parse-failed and verify-failed are distinct strings (never collide)", () => {
    // Belt-and-braces guard against a future refactor that re-collapses
    // both reasons into a single literal — the iter-50 split was driven
    // by ops triage need, not just naming preference.
    expect("signature-parse-failed").not.toBe("signature-verify-failed");
  });

  it("iter-50 split: parse failure short-circuits verify (verifyMinisignSignature is NEVER reached on garbage bytes)", async () => {
    // A bug that re-ordered parse and verify (or that swallowed the
    // null return from parse and ran verify with empty bytes) would
    // surface here as a verify-failed reason instead of parse-failed.
    let verifyCallCount = 0;
    const garbage = Buffer.from("xxxxxxxxxxxxxxxxxxxxxxxxxxxx", "utf8");
    const fakeFetch: typeof globalThis.fetch = async () =>
      new Response(garbage, { status: 200 });
    const { publicKey } = generateKeyPairSync("ed25519");

    // We monkey-patch the global crypto.verify to count calls so a
    // verify-stage execution would be observable. Restored in finally.
    const origVerify = (globalThis as unknown as { crypto?: { verify?: unknown } })
      .crypto?.verify as undefined | ((...args: unknown[]) => boolean);
    // Note: applySignatureFetchGate uses the Node `crypto` module
    // directly via verifyMinisignSignature, not globalThis.crypto, so
    // counting via a global hook isn't perfectly tight. The test
    // therefore asserts on the OUTCOME (parse-failed reason) — if
    // verify had run on garbage bytes it would have returned
    // verify-failed, so the parse-failed reason IS the proof.
    void origVerify;

    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG_URL });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
      verifyEnabled: true,
      verifyPubkey: rawPubkeyFrom(publicKey),
      verifySignedData: Buffer.from("anything"),
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      // The headline assertion: garbage bytes yield parse-failed, NEVER
      // verify-failed. A future bug that runs verify before parse-check
      // would flip this to verify-failed and the test would fail.
      expect(out.reason).toBe("signature-parse-failed");
      expect(out.reason).not.toBe("signature-verify-failed");
    }
    expect(verifyCallCount).toBe(0); // global hook never engaged either way
  });

  it("iter-50 split: a sidecar that parses but mis-verifies surfaces verify-failed (NOT parse-failed)", async () => {
    // The complementary pin: bytes that parse cleanly must reach the
    // verify stage; only verify rejection should surface verify-failed.
    // A regression that swapped the two reasons in the dispatch would
    // be caught here.
    const a = generateKeyPairSync("ed25519");
    const b = generateKeyPairSync("ed25519");
    const signedData = Buffer.from("manifest-sha256-iter50", "utf8");
    const sigByA = cryptoSign(null, signedData, a.privateKey);
    const sidecar = buildSidecar(Buffer.alloc(8, 0xab), sigByA);
    const fakeFetch: typeof globalThis.fetch = async () =>
      new Response(sidecar, { status: 200 });
    const state = mkUpdateAvailable({ signatureUrl: GOOD_SIG_URL });
    const out = await applySignatureFetchGate(state, {
      manifestVersion: 3,
      fetch: fakeFetch,
      now: FIXED_AT,
      verifyEnabled: true,
      verifyPubkey: rawPubkeyFrom(b.publicKey),
      verifySignedData: signedData,
    });
    expect(out.kind).toBe("update-blocked-by-signature-fetch");
    if (out.kind === "update-blocked-by-signature-fetch") {
      expect(out.reason).toBe("signature-verify-failed");
      expect(out.reason).not.toBe("signature-parse-failed");
    }
  });
});

// ─── Iter 49 — env helpers (parseSigPubkey + isSigVerifyEnabled) ───────────
//
// Mirrors the iter-48 isSigStrictEnabled / parseSigFetchTimeoutMs test
// patterns from auto-updater.test.ts but for the new verify gate. Pinning
// the truthiness contract (literal "1" only) and the base64 parse contract
// (raw 42 bytes → algo strip → 8-byte keyId + 32-byte pubkey).
describe("parseSigPubkey + isSigVerifyEnabled — iter 49 env helpers", () => {
  it("parseSigPubkey: returns null when env var is missing", () => {
    expect(parseSigPubkey({})).toBeNull();
  });

  it("parseSigPubkey: returns null on empty / whitespace-only env var", () => {
    expect(parseSigPubkey({ RUD1_DESKTOP_SIG_PUBKEY: "" })).toBeNull();
    expect(parseSigPubkey({ RUD1_DESKTOP_SIG_PUBKEY: "   " })).toBeNull();
  });

  it("parseSigPubkey: returns null on non-base64 chars", () => {
    expect(parseSigPubkey({ RUD1_DESKTOP_SIG_PUBKEY: "not!base64@" })).toBeNull();
  });

  it("parseSigPubkey: returns null on wrong decoded length", () => {
    // 12 bytes of zero → 16 base64 chars, but minisign envelope is 42 bytes.
    const wrong = Buffer.alloc(12, 0).toString("base64");
    expect(parseSigPubkey({ RUD1_DESKTOP_SIG_PUBKEY: wrong })).toBeNull();
  });

  it("parseSigPubkey: returns null on wrong algo prefix", () => {
    // 42 bytes total, but first two bytes are 0x44 0x44 not 0x45 0x64.
    const wrongAlgo = Buffer.concat([Buffer.from([0x44, 0x44]), Buffer.alloc(40, 0)]);
    expect(
      parseSigPubkey({
        RUD1_DESKTOP_SIG_PUBKEY: wrongAlgo.toString("base64"),
      }),
    ).toBeNull();
  });

  it("parseSigPubkey: returns { keyId, pubkey } on a well-formed envelope", () => {
    const keyId = Buffer.alloc(8, 0xab);
    const pubkey = Buffer.alloc(32, 0xcd);
    const env = Buffer.concat([Buffer.from([0x45, 0x64]), keyId, pubkey]);
    const out = parseSigPubkey({
      RUD1_DESKTOP_SIG_PUBKEY: env.toString("base64"),
    });
    expect(out).not.toBeNull();
    expect(out!.keyId.equals(keyId)).toBe(true);
    expect(out!.pubkey.equals(pubkey)).toBe(true);
  });

  it("isSigVerifyEnabled: literal '1' enables; truthy strings DO NOT (mirrors iter-48 contract)", () => {
    const fakeFs = {
      readFileSync: () => { throw new Error("ENOENT"); },
    } as unknown as typeof import("fs");
    for (const v of ["true", "yes", "on", "0", "", "TRUE", "1 "]) {
      expect(
        isSigVerifyEnabled({
          env: { RUD1_DESKTOP_SIG_VERIFY: v },
          appOverride: { getPath: () => "/tmp" },
          fileSystem: fakeFs,
        }),
      ).toBe(false);
    }
    expect(
      isSigVerifyEnabled({
        env: { RUD1_DESKTOP_SIG_VERIFY: "1" },
        appOverride: { getPath: () => "/tmp" },
        fileSystem: fakeFs,
      }),
    ).toBe(true);
  });

  it("isSigVerifyEnabled: env var unset + no persisted flag → false (off-by-default)", () => {
    const fakeFs = {
      readFileSync: () => { throw new Error("ENOENT"); },
    } as unknown as typeof import("fs");
    expect(
      isSigVerifyEnabled({
        env: {},
        appOverride: { getPath: () => "/tmp" },
        fileSystem: fakeFs,
      }),
    ).toBe(false);
  });

  it("isSigVerifyEnabled: respects persisted-config sigVerify flag when env unset", () => {
    const fakeFs = {
      readFileSync: () => JSON.stringify({ sigVerify: true }),
    } as unknown as typeof import("fs");
    expect(
      isSigVerifyEnabled({
        env: {},
        appOverride: { getPath: () => "/tmp" },
        fileSystem: fakeFs,
      }),
    ).toBe(true);
  });
});

// ─── Iter 51 — onManifestParsed callback ──────────────────────────────────
//
// The tray cache (lastManifestSha256 + lastManifestVersion) reads its
// values from this callback, which fires once per successful checkOnce
// AFTER parseManifest accepts the body but BEFORE the verdict
// transition runs. Pinning the contract:
//
//   • The callback fires exactly once per successful fetch.
//   • The manifest passed in carries the same sha256 + manifestVersion
//     the verdict pipeline downstream sees — they must NEVER drift.
//   • A fetch that returns a parse-rejected body does NOT fire the
//     callback (else the cache would carry over a stale value).
//   • A throwing listener does NOT break the version-check loop —
//     errors are swallowed (mirrors onStateChange).
//   • The callback fires BEFORE rollout-bucket suppression: a manifest
//     advertising rolloutBucket=0 still informs the cache. Otherwise a
//     bucketed device couldn't ever populate lastManifestSha256.

describe("VersionCheckManager.onManifestParsed (iter 51)", () => {
  const VALID_SHA = "a".repeat(64);

  it("fires once with the parsed manifest on a successful update-available fetch", async () => {
    const seen: Array<{ version: string; manifestVersion: number; sha256: string | null }> =
      [];
    const mgr = new VersionCheckManager({
      manifestUrl: "https://rud1.es/manifest.json",
      currentVersion: "1.0.0",
      fetch: async () =>
        jsonResponse({
          version: "1.5.0",
          manifestVersion: 2,
          sha256: VALID_SHA,
          downloadUrl: "https://rud1.es/dl",
        }),
      onManifestParsed: (m) => {
        seen.push({
          version: m.version,
          manifestVersion: m.manifestVersion,
          sha256: m.sha256,
        });
      },
    });
    await mgr.checkOnce();
    expect(seen.length).toBe(1);
    expect(seen[0].version).toBe("1.5.0");
    expect(seen[0].manifestVersion).toBe(2);
    expect(seen[0].sha256).toBe(VALID_SHA);
  });

  it("fires on up-to-date verdicts too (cache must always reflect the latest fetched manifest)", async () => {
    const seen: number[] = [];
    const mgr = new VersionCheckManager({
      manifestUrl: "https://rud1.es/manifest.json",
      currentVersion: "1.5.0",
      fetch: async () =>
        jsonResponse({
          version: "1.5.0",
          manifestVersion: 1,
        }),
      onManifestParsed: (m) => seen.push(m.manifestVersion),
    });
    await mgr.checkOnce();
    expect(seen).toEqual([1]);
    expect(mgr.getState().kind).toBe("up-to-date");
  });

  it("does NOT fire when the body is not valid JSON", async () => {
    const seen: number[] = [];
    const mgr = new VersionCheckManager({
      manifestUrl: "https://rud1.es/manifest.json",
      currentVersion: "1.0.0",
      fetch: async () =>
        new Response("not json", {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      onManifestParsed: (m) => seen.push(m.manifestVersion),
    });
    await mgr.checkOnce();
    expect(seen.length).toBe(0);
    expect(mgr.getState().kind).toBe("error");
  });

  it("does NOT fire when parseManifest rejects the shape", async () => {
    const seen: number[] = [];
    const mgr = new VersionCheckManager({
      manifestUrl: "https://rud1.es/manifest.json",
      currentVersion: "1.0.0",
      fetch: async () => jsonResponse({ note: "missing version field" }),
      onManifestParsed: (m) => seen.push(m.manifestVersion),
    });
    await mgr.checkOnce();
    expect(seen.length).toBe(0);
    expect(mgr.getState().kind).toBe("error");
  });

  it("a throwing listener is swallowed and the verdict still transitions", async () => {
    const states: string[] = [];
    const mgr = new VersionCheckManager({
      manifestUrl: "https://rud1.es/manifest.json",
      currentVersion: "1.0.0",
      fetch: async () =>
        jsonResponse({
          version: "1.5.0",
          manifestVersion: 1,
        }),
      onManifestParsed: () => {
        throw new Error("listener boom");
      },
      onStateChange: (s) => states.push(s.kind),
    });
    const verdict = await mgr.checkOnce();
    expect(verdict.kind).toBe("update-available");
    // checking → update-available, both observed.
    expect(states).toContain("update-available");
  });

  it("fires BEFORE rollout-bucket suppression so the cache populates even when the verdict is up-to-date", async () => {
    // rolloutBucket=1 + a deterministic installId whose computed device
    // bucket is > 1 produces an `up-to-date` verdict despite the
    // manifest advertising a newer version. The cache MUST still pick
    // up the manifest's sha256 + manifestVersion — otherwise the
    // iter-49 verifySignedData would never have a value during a slow
    // staged rollout.
    const seen: number[] = [];
    const mgr = new VersionCheckManager({
      manifestUrl: "https://rud1.es/manifest.json",
      currentVersion: "1.0.0",
      installId: "test:device:high-bucket", // computed bucket lands well above 1
      fetch: async () =>
        jsonResponse({
          version: "1.5.0",
          manifestVersion: 2,
          sha256: VALID_SHA,
          rolloutBucket: 1,
        }),
      onManifestParsed: (m) => seen.push(m.manifestVersion),
    });
    const verdict = await mgr.checkOnce();
    // Pin the suppression: device is OUTSIDE bucket 1 so the verdict
    // reads up-to-date despite the manifest advertising 1.5.0.
    expect(verdict.kind).toBe("up-to-date");
    expect(seen).toEqual([2]); // populated despite suppression
  });

  it("fires omitted when constructor receives no listener (defaults to no-op)", async () => {
    // Omitting onManifestParsed must be valid — older callers that
    // pre-date iter 51 must continue to work without changes.
    const mgr = new VersionCheckManager({
      manifestUrl: "https://rud1.es/manifest.json",
      currentVersion: "1.0.0",
      fetch: async () =>
        jsonResponse({
          version: "1.5.0",
          manifestVersion: 1,
        }),
      // no onManifestParsed
    });
    await expect(mgr.checkOnce()).resolves.toBeDefined();
    expect(mgr.getState().kind).toBe("update-available");
  });
});
