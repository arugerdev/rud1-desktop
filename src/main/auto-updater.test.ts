/**
 * Unit tests for auto-updater (iter 21).
 *
 * Scope:
 *   • isValidFeedUrl — allowlist: https only, no userinfo, no shell
 *     metacharacters, no CRLF in the path, length-capped. These are
 *     the guards that keep a compromised IPC channel from pointing
 *     the updater at a malicious feed.
 *   • isValidChannel — fixed allowlist ("latest" / "beta" / "alpha").
 *   • parseSemver / compareSemver — minimal semver 2.0 precedence
 *     (including the prerelease < release rule and numeric-vs-string
 *     identifier comparison). Covers the "don't downgrade" predicate.
 *   • isNewerVersion — pure predicate used to gate update-available UI.
 *   • configureAutoUpdater — assembles the above via a stub updater
 *     handle. Pins the order of operations (validate BEFORE mutate) so a
 *     future refactor can't accidentally leave a half-configured updater
 *     pointing at an unvalidated URL.
 *
 * Event-flow tests (checkForUpdates → 'update-available' → download →
 * install) are `it.todo` on purpose: electron-updater's event chain is
 * implemented in terms of its own internal state machine and timers;
 * mocking it faithfully enough to be meaningful has the same
 * brittleness-vs-value ratio we hit in iter 17–19 for the spawn event
 * chains. The validators above already pin every trust boundary.
 */

import { describe, expect, it, vi } from "vitest";

// electron-updater is a heavy dependency that pulls in `electron.app`
// at import time. auto-updater.ts is carefully written NOT to import
// electron-updater at module load, but we stub it anyway so a future
// refactor doesn't silently start pulling it in during tests.
vi.mock("electron-updater", () => ({
  autoUpdater: {
    autoDownload: false,
    allowPrerelease: false,
    channel: null,
    setFeedURL: vi.fn(),
    checkForUpdates: vi.fn(async () => null),
    on: vi.fn(),
  },
}));

import { configureAutoUpdater, __test } from "./auto-updater";

const {
  isValidFeedUrl,
  assertFeedUrl,
  isValidChannel,
  parseSemver,
  compareSemver,
  isNewerVersion,
  ALLOWED_CHANNELS,
} = __test;

// ─── 1. isValidFeedUrl ──────────────────────────────────────────────────────

describe("isValidFeedUrl", () => {
  it("accepts typical https feed URLs", () => {
    for (const ok of [
      "https://releases.rud1.es/",
      "https://releases.rud1.es/stable/",
      "https://releases.rud1.es/path/with-dashes_and.dots/v1",
      "https://example.com",
      "https://a.b.c.d/",
      "https://releases.rud1.es/?channel=latest",
    ]) {
      expect(isValidFeedUrl(ok)).toBe(true);
    }
  });

  it("rejects non-https schemes", () => {
    for (const bad of [
      "http://releases.rud1.es/",       // plain HTTP — MITM risk
      "file:///etc/passwd",             // local file read
      "ftp://releases.rud1.es/",
      "javascript:alert(1)",
      "data:text/plain,hi",
      "ws://releases.rud1.es/",
    ]) {
      expect(isValidFeedUrl(bad)).toBe(false);
    }
  });

  it("rejects URLs with userinfo (credential-smuggling shape)", () => {
    // `https://user:pass@evil.example/` is often used to bypass
    // hostname-allowlist checks in naive validators. We forbid any
    // non-empty username OR password component.
    expect(isValidFeedUrl("https://user@releases.rud1.es/")).toBe(false);
    expect(isValidFeedUrl("https://user:pass@releases.rud1.es/")).toBe(false);
    expect(isValidFeedUrl("https://:pass@releases.rud1.es/")).toBe(false);
  });

  it("rejects URLs with a fragment", () => {
    // Feed URLs don't use fragments; a stray `#` is likely an injection.
    expect(isValidFeedUrl("https://releases.rud1.es/#section")).toBe(false);
  });

  it("rejects shell metacharacters and whitespace in path/query", () => {
    for (const bad of [
      "https://releases.rud1.es/path;rm",
      "https://releases.rud1.es/path|cat",
      "https://releases.rud1.es/`whoami`",
      "https://releases.rud1.es/$(id)",
      "https://releases.rud1.es/path with space",
      "https://releases.rud1.es/path\\backslash",
      'https://releases.rud1.es/"quote',
      "https://releases.rud1.es/'quote",
      "https://releases.rud1.es/(paren)",
      "https://releases.rud1.es/{brace}",
      "https://releases.rud1.es/[bracket]",
    ]) {
      expect(isValidFeedUrl(bad)).toBe(false);
    }
  });

  it("rejects percent-encoded CRLF (header-injection shape)", () => {
    // `%0A` / `%0D` in a path can split HTTP headers in a permissive
    // fetcher. electron-updater uses a modern HTTP stack that refuses
    // these, but we pre-reject at the validator boundary anyway.
    expect(isValidFeedUrl("https://releases.rud1.es/path%0AHeader")).toBe(false);
    expect(isValidFeedUrl("https://releases.rud1.es/path%0DHeader")).toBe(false);
    expect(isValidFeedUrl("https://releases.rud1.es/path%0aHeader")).toBe(false);
  });

  it("rejects malformed and degenerate hostnames", () => {
    for (const bad of [
      "https://",                 // no host at all — URL parses but host=""
      "https://releases.rud1.es./", // trailing dot
      "https://releases..rud1.es/", // empty label
      "https://-releases.rud1.es/", // leading hyphen
      "https://releases.rud1.es-/", // trailing hyphen
    ]) {
      expect(isValidFeedUrl(bad)).toBe(false);
    }
  });

  it("rejects non-string / empty / oversize input", () => {
    expect(isValidFeedUrl("")).toBe(false);
    expect(isValidFeedUrl(undefined)).toBe(false);
    expect(isValidFeedUrl(null)).toBe(false);
    expect(isValidFeedUrl(42)).toBe(false);
    expect(isValidFeedUrl({})).toBe(false);
    // >2048-char URL — hard cap so a megabyte IPC payload can't OOM
    // URL parsing or trip log-flooding.
    expect(isValidFeedUrl("https://releases.rud1.es/" + "a".repeat(3000))).toBe(false);
  });

  it("assertFeedUrl throws for rejected input and is a no-op for accepted", () => {
    expect(() => assertFeedUrl("https://releases.rud1.es/")).not.toThrow();
    expect(() => assertFeedUrl("http://releases.rud1.es/")).toThrow(/invalid feed URL/);
    expect(() => assertFeedUrl("https://user@releases.rud1.es/")).toThrow(/invalid feed URL/);
    expect(() => assertFeedUrl("")).toThrow(/invalid feed URL/);
    expect(() => assertFeedUrl(undefined)).toThrow(/invalid feed URL/);
  });
});

// ─── 2. isValidChannel ──────────────────────────────────────────────────────

describe("isValidChannel", () => {
  it("accepts the fixed allowlist", () => {
    for (const ok of ALLOWED_CHANNELS) {
      expect(isValidChannel(ok)).toBe(true);
    }
  });

  it("rejects anything outside the allowlist (incl. shell-meta shapes)", () => {
    for (const bad of [
      "",
      "stable",               // close-but-not-allowed
      "LATEST",               // case-sensitive on purpose
      "latest;rm -rf /",
      "latest/../beta",
      "latest\nbeta",
      "../etc/passwd",
      undefined,
      null,
      42,
      {},
    ]) {
      expect(isValidChannel(bad)).toBe(false);
    }
  });
});

// ─── 3. parseSemver ─────────────────────────────────────────────────────────

describe("parseSemver", () => {
  it("parses plain MAJOR.MINOR.PATCH", () => {
    expect(parseSemver("1.2.3")).toEqual({
      major: 1, minor: 2, patch: 3, prerelease: "",
    });
    expect(parseSemver("0.0.1")).toEqual({
      major: 0, minor: 0, patch: 1, prerelease: "",
    });
    expect(parseSemver("10.20.30")).toEqual({
      major: 10, minor: 20, patch: 30, prerelease: "",
    });
  });

  it("strips a leading `v`", () => {
    expect(parseSemver("v1.2.3")).toEqual({
      major: 1, minor: 2, patch: 3, prerelease: "",
    });
  });

  it("parses prerelease identifiers", () => {
    expect(parseSemver("1.2.3-beta.1")).toEqual({
      major: 1, minor: 2, patch: 3, prerelease: "beta.1",
    });
    expect(parseSemver("1.2.3-alpha")).toEqual({
      major: 1, minor: 2, patch: 3, prerelease: "alpha",
    });
    expect(parseSemver("1.2.3-rc.2.test-5")).toEqual({
      major: 1, minor: 2, patch: 3, prerelease: "rc.2.test-5",
    });
  });

  it("drops build metadata (anything after `+`)", () => {
    expect(parseSemver("1.2.3+sha.abcd")).toEqual({
      major: 1, minor: 2, patch: 3, prerelease: "",
    });
    expect(parseSemver("1.2.3-beta+build.7")).toEqual({
      major: 1, minor: 2, patch: 3, prerelease: "beta",
    });
  });

  it("returns null for malformed input", () => {
    for (const bad of [
      "",
      "1",
      "1.2",
      "1.2.3.4",
      "a.b.c",
      "1.2.-3",
      "1.2.3-",           // empty prerelease
      "1.2.3-beta!",      // disallowed char
      "1.2.3 beta",       // whitespace
      "v",
      "latest",
      undefined,
      null,
      42,
    ]) {
      expect(parseSemver(bad)).toBeNull();
    }
  });
});

// ─── 4. compareSemver ───────────────────────────────────────────────────────

describe("compareSemver", () => {
  function cmp(a: string, b: string): number {
    const pa = parseSemver(a);
    const pb = parseSemver(b);
    if (!pa || !pb) throw new Error(`parse failed: ${a} / ${b}`);
    const raw = compareSemver(pa, pb);
    return raw === 0 ? 0 : raw > 0 ? 1 : -1; // normalise sign
  }

  it("orders by major/minor/patch", () => {
    expect(cmp("2.0.0", "1.9.9")).toBe(1);
    expect(cmp("1.10.0", "1.9.9")).toBe(1);
    expect(cmp("1.2.4", "1.2.3")).toBe(1);
    expect(cmp("1.2.3", "1.2.3")).toBe(0);
    expect(cmp("1.2.3", "1.2.4")).toBe(-1);
    expect(cmp("1.9.9", "2.0.0")).toBe(-1);
  });

  it("ranks a prerelease BELOW the matching release (semver 2.0 rule)", () => {
    // This is the rule that keeps `1.2.3-beta.1` from looking "newer"
    // than `1.2.3`. Electron-updater does this too; we cross-check.
    expect(cmp("1.2.3", "1.2.3-beta.1")).toBe(1);
    expect(cmp("1.2.3-beta.1", "1.2.3")).toBe(-1);
  });

  it("orders prereleases numerically when both identifiers are digits", () => {
    expect(cmp("1.2.3-beta.2", "1.2.3-beta.11")).toBe(-1); // 2 < 11 numerically
    expect(cmp("1.2.3-rc.10", "1.2.3-rc.2")).toBe(1);
  });

  it("orders numeric identifiers BELOW non-numeric (semver 2.0 rule)", () => {
    expect(cmp("1.2.3-1", "1.2.3-alpha")).toBe(-1);
    expect(cmp("1.2.3-alpha", "1.2.3-1")).toBe(1);
  });

  it("treats a shorter prerelease prefix as lower", () => {
    expect(cmp("1.2.3-alpha", "1.2.3-alpha.1")).toBe(-1);
    expect(cmp("1.2.3-alpha.1", "1.2.3-alpha")).toBe(1);
  });

  it("orders prerelease identifiers lexically when non-numeric", () => {
    expect(cmp("1.2.3-alpha", "1.2.3-beta")).toBe(-1);
    expect(cmp("1.2.3-beta", "1.2.3-alpha")).toBe(1);
    expect(cmp("1.2.3-alpha.1", "1.2.3-alpha.1")).toBe(0);
  });
});

// ─── 5. isNewerVersion ──────────────────────────────────────────────────────

describe("isNewerVersion", () => {
  it("is true only when remote strictly > current", () => {
    expect(isNewerVersion("1.2.4", "1.2.3")).toBe(true);
    expect(isNewerVersion("2.0.0", "1.99.99")).toBe(true);
    expect(isNewerVersion("1.2.3", "1.2.3")).toBe(false); // equal → no prompt
    expect(isNewerVersion("1.2.2", "1.2.3")).toBe(false); // downgrade
  });

  it("tolerates a `v` prefix on either side", () => {
    expect(isNewerVersion("v1.2.4", "1.2.3")).toBe(true);
    expect(isNewerVersion("1.2.4", "v1.2.3")).toBe(true);
    expect(isNewerVersion("v1.2.3", "v1.2.3")).toBe(false);
  });

  it("returns false when either side fails to parse", () => {
    // If the feed sends us garbage we refuse to offer an update rather
    // than guessing. Surfacing "update available" based on garbage is
    // worse than silently not-offering.
    expect(isNewerVersion("not-a-version", "1.2.3")).toBe(false);
    expect(isNewerVersion("1.2.4", "not-a-version")).toBe(false);
    expect(isNewerVersion(undefined, "1.2.3")).toBe(false);
    expect(isNewerVersion("1.2.4", null)).toBe(false);
    expect(isNewerVersion(42, "1.2.3")).toBe(false);
  });

  it("does not offer a prerelease when current is the matching release", () => {
    // 1.2.3-beta.1 is LOWER than 1.2.3 per semver, so isNewerVersion
    // must return false — critical for not auto-"updating" a stable
    // build to a beta behind the operator's back.
    expect(isNewerVersion("1.2.3-beta.1", "1.2.3")).toBe(false);
    expect(isNewerVersion("1.2.3", "1.2.3-beta.1")).toBe(true);
  });
});

// ─── 6. configureAutoUpdater ────────────────────────────────────────────────

describe("configureAutoUpdater", () => {
  function makeStub() {
    return {
      autoDownload: true,     // non-default sentinels so we can detect writes
      allowPrerelease: true,
      channel: "whatever" as string | null,
      setFeedURL: vi.fn(),
      checkForUpdates: vi.fn(async () => null),
      on: vi.fn(),
    };
  }

  it("applies a valid config end-to-end", () => {
    const stub = makeStub();
    configureAutoUpdater(stub, {
      feedUrl: "https://releases.rud1.es/stable/",
      channel: "latest",
      allowPrerelease: false,
      autoDownload: false,
    });
    expect(stub.autoDownload).toBe(false);
    expect(stub.allowPrerelease).toBe(false);
    expect(stub.channel).toBe("latest");
    expect(stub.setFeedURL).toHaveBeenCalledWith({
      provider: "generic",
      url: "https://releases.rud1.es/stable/",
      channel: "latest",
    });
  });

  it("defaults channel=latest, autoDownload=false, allowPrerelease=false", () => {
    // Conservative defaults: never auto-download without explicit opt-in,
    // never allow prereleases unless the operator asked.
    const stub = makeStub();
    configureAutoUpdater(stub, { feedUrl: "https://releases.rud1.es/" });
    expect(stub.autoDownload).toBe(false);
    expect(stub.allowPrerelease).toBe(false);
    expect(stub.channel).toBe("latest");
  });

  it("throws `invalid feed URL` BEFORE mutating the updater", () => {
    // Security invariant: a bad URL must not leave the updater in a
    // half-configured state — autoDownload/channel must be untouched
    // so a subsequent checkForUpdates() either uses the previous valid
    // config or fails closed.
    const stub = makeStub();
    expect(() =>
      configureAutoUpdater(stub, {
        feedUrl: "http://releases.rud1.es/",
        channel: "latest",
      }),
    ).toThrow(/invalid feed URL/);
    expect(stub.setFeedURL).not.toHaveBeenCalled();
    expect(stub.autoDownload).toBe(true);    // untouched sentinel
    expect(stub.allowPrerelease).toBe(true); // untouched sentinel
    expect(stub.channel).toBe("whatever");   // untouched sentinel
  });

  it("throws `invalid channel` BEFORE mutating the updater", () => {
    const stub = makeStub();
    expect(() =>
      configureAutoUpdater(stub, {
        feedUrl: "https://releases.rud1.es/",
        channel: "staging",
      }),
    ).toThrow(/invalid channel/);
    expect(stub.setFeedURL).not.toHaveBeenCalled();
    expect(stub.channel).toBe("whatever"); // untouched
  });

  it("rejects metacharacter-laden channel strings", () => {
    const stub = makeStub();
    expect(() =>
      configureAutoUpdater(stub, {
        feedUrl: "https://releases.rud1.es/",
        channel: "latest;rm -rf /",
      }),
    ).toThrow(/invalid channel/);
    expect(stub.setFeedURL).not.toHaveBeenCalled();
  });
});

// ─── 7. Event-flow wiring — honest it.todo ──────────────────────────────────

describe("checkForUpdates event flow", () => {
  it.todo(
    "emits update-available → download-progress → update-downloaded in " +
      "order (skipped: faithfully mocking electron-updater's internal state " +
      "machine + timers would reimplement the library under test. The trust " +
      "boundaries — feed URL, channel, version-compare — are covered above " +
      "against the real pure helpers; the rest is delegation to a library " +
      "whose own test suite covers the event sequencing.)",
  );

  it.todo(
    "surfaces a typed error on HTTPS certificate failure without " +
      "auto-installing (skipped: requires intercepting the Node HTTPS stack " +
      "via nock or undici mocks; the validator layer refuses non-HTTPS URLs " +
      "at configuration time, which is the only code path under our control.)",
  );
});
