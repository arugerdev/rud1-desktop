import { describe, it, expect } from "vitest";

import {
  VersionCheckManager,
  parseManifest,
  classifyManifest,
  type VersionManifest,
} from "./version-check-manager";

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
  });

  it("flags an update when remote > current", () => {
    const out = classifyManifest("1.2.0", m("1.3.0"), NOW);
    expect(out).toEqual({
      kind: "update-available",
      current: "1.2.0",
      latest: "1.3.0",
      downloadUrl: null,
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
