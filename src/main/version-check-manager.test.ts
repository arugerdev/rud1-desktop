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
  it("accepts a minimal valid manifest", () => {
    const m = parseManifest({ version: "1.2.3" });
    expect(m).toEqual({ version: "1.2.3", downloadUrl: null });
  });

  it("preserves a https downloadUrl", () => {
    const m = parseManifest({
      version: "1.2.3",
      downloadUrl: "https://rud1.es/desktop/download",
    });
    expect(m).toEqual({
      version: "1.2.3",
      downloadUrl: "https://rud1.es/desktop/download",
    });
  });

  it("drops a downloadUrl that fails the feed-url allowlist", () => {
    const m = parseManifest({
      version: "1.2.3",
      downloadUrl: "javascript:alert(1)",
    });
    expect(m).toEqual({ version: "1.2.3", downloadUrl: null });
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

describe("classifyManifest", () => {
  const NOW = 1_700_000_000_000;
  const m = (version: string, downloadUrl: string | null = null): VersionManifest => ({
    version,
    downloadUrl,
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
