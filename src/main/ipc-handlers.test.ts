/**
 * Unit tests for ipc-handlers (iter 22).
 *
 * Scope:
 *   • isOriginAllowed — the trust boundary between the renderer frame and
 *     the main process. This is the single predicate every IPC channel
 *     funnels through via checkSender(). If it regresses, EVERY channel
 *     regresses, so we over-cover the shape invariants here and leave the
 *     per-handler wiring to `it.todo`'d integration tests (see §4 below).
 *   • Key shapes we pin:
 *       - prefix-smuggling rejection (`https://rud1.es.evil.com/` vs
 *         ALLOWED_ORIGIN `https://rud1.es`)
 *       - subdomain-smuggling rejection (`https://evil.rud1.es/`)
 *       - javascript: / file: / data: / ws: / about: scheme rejection
 *       - CRLF / null-byte / control-char rejection (on the RAW string,
 *         BEFORE URL canonicalisation — mirrors the iter-21 pattern used
 *         by auto-updater.isValidFeedUrl)
 *       - userinfo rejection (`https://user:pass@rud1.es/`)
 *       - length cap (2048 chars)
 *       - senderFrame = null → rejected (frame-disposed race)
 *       - dev-mode: exact `localhost` / `127.0.0.1` match only, not
 *         `localhost.evil.com`
 *   • __test surface exposes the pure helpers so we don't need an
 *     Electron main-process stub to exercise the security boundary.
 *
 * Mocking strategy:
 *   • We `vi.mock("electron", ...)` at the top of the file because
 *     ipc-handlers.ts imports `ipcMain`, `app`, and `BrowserWindow` at
 *     module load. We don't exercise `registerIpcHandlers` in this suite
 *     (that would require a full Electron main process); instead we
 *     exercise the `checkSender` / `isOriginAllowed` boundary directly.
 *     The per-handler dispatch is covered by `it.todo` entries below with
 *     a rationale matching iter 21's approach for electron-updater.
 *   • We also vi.mock every ./X-manager import because they pull in
 *     child_process, fs, and in some cases `electron.shell` — we don't
 *     want them to execute during a unit test of the origin check.
 */

import { beforeAll, describe, expect, it, vi } from "vitest";

// electron is a native module; importing it in a plain Node vitest run
// without mocking produces `app is undefined` at ipc-handlers.ts line 38.
// We only need a stub of the three symbols used at module load.
vi.mock("electron", () => {
  // Notification needs both a constructor (for `new Notification(...)`)
  // and an `isSupported` static — notifications.ts feature-detects
  // before constructing. The mock returns a no-op `show()` so the
  // ipc-handlers can fire toasts without blowing up the test run.
  const NotificationStub = vi.fn().mockImplementation(() => ({
    show: vi.fn(),
    on: vi.fn(),
  })) as unknown as { isSupported?: () => boolean };
  NotificationStub.isSupported = () => true;
  return {
    ipcMain: {
      handle: vi.fn(),
      on: vi.fn(),
    },
    app: {
      isPackaged: true,
      getVersion: () => "0.1.0-test",
    },
    BrowserWindow: {
      fromWebContents: vi.fn(() => null),
    },
    Notification: NotificationStub,
    // Iter 37 — clipboard + shell:openExternal channels need stubs so the
    // ipc-handlers module can be loaded under vitest. The dispatch tests
    // exercise the handler closures directly via the captured handler
    // table; assertions check that these stubs were called with the
    // sanitised payload (or NOT called when the validator rejects).
    clipboard: {
      writeText: vi.fn(),
    },
    shell: {
      openExternal: vi.fn(async () => undefined),
      // usb:launchInstaller channel calls shell.openPath. Empty string
      // = success per Electron's contract.
      openPath: vi.fn(async () => ""),
    },
  };
});

// Manager modules pull in child_process / fs / network probes at import
// time. We stub them to be inert — this suite is about the origin check,
// not about the managers' behavior (each has its own *.test.ts file).
vi.mock("./vpn-manager", () => ({
  vpnConnect: vi.fn(async () => undefined),
  vpnDisconnect: vi.fn(async () => undefined),
  vpnStatus: vi.fn(async () => ({ connected: false })),
}));
vi.mock("./usb-manager", () => ({
  usbAttach: vi.fn(async () => 1),
  usbDetach: vi.fn(async () => undefined),
  usbList: vi.fn(async () => []),
  isUsbipInstalled: vi.fn(() => true),
  getUsbipInstallerPath: vi.fn(() => null),
  // Re-exported error class so `instanceof UsbipMissingError` checks
  // inside ipc-handlers compile and behave under the mock.
  UsbipMissingError: class UsbipMissingError extends Error {
    installerPath: string | null = null;
    constructor() {
      super("USB/IP missing (test stub)");
      this.name = "UsbipMissingError";
    }
  },
}));
vi.mock("./net-diag-manager", () => ({
  ping: vi.fn(async () => ({ ok: true })),
  interfaces: vi.fn(() => []),
  resolveRoute: vi.fn(async () => null),
  traceroute: vi.fn(async () => []),
  dnsLookup: vi.fn(async () => []),
  publicIp: vi.fn(async () => ({ ipv4: null, ipv6: null })),
  portCheck: vi.fn(async () => ({ ok: true, latencyMs: 0 })),
}));
vi.mock("./tunnel-diag-manager", () => ({
  wgStatus: vi.fn(async () => ({ tunnels: [] })),
  tunnelHealth: vi.fn(async () => ({ verdict: "healthy" })),
  mtuProbe: vi.fn(async () => ({ mtu: 1500 })),
  fullDiagnosis: vi.fn(async () => ({})),
  exportReport: vi.fn(async () => ({ path: "" })),
  listReports: vi.fn(async () => []),
  readReport: vi.fn(async () => ({})),
  deleteReport: vi.fn(async () => undefined),
  openReportsFolder: vi.fn(async () => undefined),
  saveReportCopy: vi.fn(async () => ({ path: "" })),
  compareReports: vi.fn(async () => ({})),
}));
vi.mock("./auto-snapshot-manager", () => ({
  configureAutoSnapshot: vi.fn(async () => ({})),
  getAutoSnapshotStatus: vi.fn(() => ({ enabled: false })),
  triggerAutoSnapshotNow: vi.fn(async () => ({ ok: true })),
}));
vi.mock("./system-manager", () => ({
  getStats: vi.fn(async () => ({})),
}));

import { __test } from "./ipc-handlers";

const { isOriginAllowed, checkSender, UNSAFE_URL_CHARS, MAX_SENDER_URL_LENGTH } =
  __test;

const PACKAGED = { isPackaged: true } as const;
const DEV = { isPackaged: false } as const;

// ─── 1. isOriginAllowed — accepted shapes ───────────────────────────────────

describe("isOriginAllowed — accepted origins (packaged build)", () => {
  it("accepts the exact production origin", () => {
    expect(isOriginAllowed("https://rud1.es/", PACKAGED)).toBe(true);
    // Trailing path, query, and hash are fine — origin-level compare
    // ignores them.
    expect(isOriginAllowed("https://rud1.es/app", PACKAGED)).toBe(true);
    expect(isOriginAllowed("https://rud1.es/app?x=1", PACKAGED)).toBe(true);
  });

  it("accepts the www. host alongside the apex by default (PIN)", () => {
    // Vercel canonicalises one of the two hosts and 308s the other; the
    // BrowserWindow follows the redirect, so by the time IPC fires the
    // sender frame is on whichever the canonical happens to be. We
    // accept both up front so this isn't fragile to a Vercel domain
    // re-config.
    expect(isOriginAllowed("https://www.rud1.es/", PACKAGED)).toBe(true);
    expect(
      isOriginAllowed("https://www.rud1.es/dashboard/devices/abc/connect", PACKAGED),
    ).toBe(true);
  });

  it("accepts a custom allowedOrigin when provided", () => {
    expect(
      isOriginAllowed("https://staging.rud1.es/", {
        isPackaged: true,
        allowedOrigin: "https://staging.rud1.es",
      }),
    ).toBe(true);
  });

  it("accepts a custom allowedOrigins list (comma-separated env var shape)", () => {
    const list = ["https://staging.rud1.es", "https://preview.rud1.es"];
    expect(
      isOriginAllowed("https://staging.rud1.es/", {
        isPackaged: true,
        allowedOrigins: list,
      }),
    ).toBe(true);
    expect(
      isOriginAllowed("https://preview.rud1.es/x", {
        isPackaged: true,
        allowedOrigins: list,
      }),
    ).toBe(true);
    // An origin NOT in the list still fails — the list does NOT widen
    // the check beyond what's enumerated.
    expect(
      isOriginAllowed("https://other.rud1.es/", {
        isPackaged: true,
        allowedOrigins: list,
      }),
    ).toBe(false);
  });

  it("allowedOrigins wins when both allowedOrigin and allowedOrigins are set", () => {
    expect(
      isOriginAllowed("https://b.example/", {
        isPackaged: true,
        allowedOrigin: "https://a.example",
        allowedOrigins: ["https://b.example"],
      }),
    ).toBe(true);
    expect(
      isOriginAllowed("https://a.example/", {
        isPackaged: true,
        allowedOrigin: "https://a.example",
        allowedOrigins: ["https://b.example"],
      }),
    ).toBe(false);
  });

  it("an empty allowedOrigins array falls back to defaults (does NOT lock everyone out)", () => {
    // Defensive: a misconfigured caller passing `[]` mustn't accidentally
    // brick IPC. We treat empty as "no override" and let the singular
    // `allowedOrigin` (or the default list) decide.
    expect(
      isOriginAllowed("https://rud1.es/", {
        isPackaged: true,
        allowedOrigins: [],
      }),
    ).toBe(true);
  });
});

// ─── 2. isOriginAllowed — prefix / subdomain smuggling ──────────────────────

describe("isOriginAllowed — origin-boundary rejections (regression pins)", () => {
  // These are the bugs the iter-21 → iter-22 refactor fixed. Before the
  // fix, `url.startsWith("https://rud1.es")` accepted every shape below.
  // If any of these start returning true again, something regressed.
  it("rejects prefix-smuggling against the allowed origin (PIN)", () => {
    // `https://rud1.es` is a prefix of `https://rud1.es.evil.com` — the
    // old startsWith check accepted this, which is how renderer-origin
    // allowlists get bypassed in the wild.
    expect(isOriginAllowed("https://rud1.es.evil.com/", PACKAGED)).toBe(false);
    expect(isOriginAllowed("https://rud1.es@evil.com/", PACKAGED)).toBe(false);
    expect(isOriginAllowed("https://rud1.eszz/", PACKAGED)).toBe(false);
  });

  it("rejects subdomain smuggling (PIN)", () => {
    // `https://evil.rud1.es/` is a DIFFERENT origin per RFC 6454 / URL
    // spec — subdomains do NOT inherit origin. A `startsWith` or
    // `endsWith` check would often let this through.
    expect(isOriginAllowed("https://evil.rud1.es/", PACKAGED)).toBe(false);
    expect(isOriginAllowed("https://a.b.rud1.es/", PACKAGED)).toBe(false);
  });

  it("rejects scheme downgrade (http:// when allowed is https://)", () => {
    // A plain-HTTP frame with the same host is a MITM risk — the renderer
    // might have been hijacked mid-load. Origin mismatch → reject.
    expect(isOriginAllowed("http://rud1.es/", PACKAGED)).toBe(false);
  });

  it("rejects a port mismatch", () => {
    // `https://rud1.es:8443/` has a different `origin` string than
    // `https://rud1.es/` — origin-level compare catches it.
    expect(isOriginAllowed("https://rud1.es:8443/", PACKAGED)).toBe(false);
  });
});

// ─── 3. isOriginAllowed — dangerous schemes ─────────────────────────────────

describe("isOriginAllowed — scheme allowlist", () => {
  it("rejects javascript:, file:, data:, about:, ws:, ftp:", () => {
    for (const bad of [
      "javascript:alert(1)",
      "file:///etc/passwd",
      "data:text/html,<script>alert(1)</script>",
      "about:blank",
      "ws://rud1.es/",
      "wss://rud1.es/",
      "ftp://rud1.es/",
      "chrome://settings",
      "chrome-extension://abc/",
    ]) {
      expect(isOriginAllowed(bad, PACKAGED)).toBe(false);
    }
  });

  it("rejects javascript: even if it textually contains the allowed host", () => {
    // A compromised preload that somehow sets senderFrame.url to this
    // shape must still be rejected — the protocol check runs after URL
    // parse, before the origin compare.
    expect(
      isOriginAllowed("javascript://rud1.es/%0Aalert(1)", PACKAGED),
    ).toBe(false);
  });
});

// ─── 4. isOriginAllowed — control chars / CRLF / null byte ──────────────────

describe("isOriginAllowed — unsafe raw characters (pre-parse)", () => {
  // These all MUST be rejected on the RAW string BEFORE new URL(), because
  // WHATWG URL canonicalises %0A / %0D / \0 into percent-encoded forms
  // inside the path, making a post-parse scan miss them.
  it("rejects CRLF in the raw URL", () => {
    expect(isOriginAllowed("https://rud1.es/\r\nSet-Cookie:evil=1", PACKAGED))
      .toBe(false);
    expect(isOriginAllowed("https://rud1.es/\nX-Evil:1", PACKAGED)).toBe(false);
    expect(isOriginAllowed("https://rud1.es/\rX-Evil:1", PACKAGED)).toBe(false);
  });

  it("rejects null-byte injection", () => {
    expect(isOriginAllowed("https://rud1.es/\x00evil", PACKAGED)).toBe(false);
    expect(isOriginAllowed("https://rud1.es\x00.evil.com/", PACKAGED)).toBe(
      false,
    );
  });

  it("rejects tab / vertical-tab / form-feed / DEL", () => {
    for (const ch of ["\t", "\v", "\f", "\x7f"]) {
      expect(isOriginAllowed(`https://rud1.es/${ch}x`, PACKAGED)).toBe(false);
    }
  });

  it("rejects whitespace in the middle of the URL", () => {
    expect(isOriginAllowed("https://rud1.es/ path", PACKAGED)).toBe(false);
    expect(isOriginAllowed("https://rud1. es/", PACKAGED)).toBe(false);
  });

  it("rejects quote / angle-bracket / backslash / backtick chars", () => {
    for (const ch of ['"', "<", ">", "\\", "`", "{", "|", "}"]) {
      expect(isOriginAllowed(`https://rud1.es/${ch}`, PACKAGED)).toBe(false);
    }
  });

  it("UNSAFE_URL_CHARS regex is direction-specific (pins the char set)", () => {
    // Make sure nobody loosens the regex accidentally — at least these
    // control chars MUST continue to be flagged.
    expect(UNSAFE_URL_CHARS.test("\r")).toBe(true);
    expect(UNSAFE_URL_CHARS.test("\n")).toBe(true);
    expect(UNSAFE_URL_CHARS.test("\x00")).toBe(true);
    expect(UNSAFE_URL_CHARS.test("\t")).toBe(true);
    expect(UNSAFE_URL_CHARS.test(" ")).toBe(true);
    // And ordinary ASCII in the allowed set is NOT flagged.
    expect(UNSAFE_URL_CHARS.test("a")).toBe(false);
    expect(UNSAFE_URL_CHARS.test("/")).toBe(false);
    expect(UNSAFE_URL_CHARS.test("-")).toBe(false);
  });
});

// ─── 5. isOriginAllowed — userinfo, fragment, malformed, oversized ──────────

describe("isOriginAllowed — misc input hygiene", () => {
  it("rejects URLs carrying userinfo", () => {
    // Credential-smuggling shape. Useful for defeating naive host checks.
    expect(isOriginAllowed("https://user@rud1.es/", PACKAGED)).toBe(false);
    expect(isOriginAllowed("https://user:pass@rud1.es/", PACKAGED)).toBe(false);
    expect(isOriginAllowed("https://:pass@rud1.es/", PACKAGED)).toBe(false);
  });

  it("rejects malformed URLs", () => {
    // Only include shapes that WHATWG URL actually rejects or canonicalises
    // to something other than the allowed origin. We deliberately DON'T
    // include `https:/rud1.es` / `https:rud1.es` here: Node canonicalises
    // them to `https://rud1.es/`, which IS the allowed origin — and the
    // same origin-level compare would correctly accept them. Rejecting a
    // parser quirk that resolves to the trusted origin buys nothing.
    for (const bad of [
      "not-a-url",
      "://rud1.es",
      "https://",
    ]) {
      expect(isOriginAllowed(bad, PACKAGED)).toBe(false);
    }
  });

  it("rejects non-string / empty / oversized input", () => {
    expect(isOriginAllowed("", PACKAGED)).toBe(false);
    expect(isOriginAllowed(undefined, PACKAGED)).toBe(false);
    expect(isOriginAllowed(null, PACKAGED)).toBe(false);
    expect(isOriginAllowed(42, PACKAGED)).toBe(false);
    expect(isOriginAllowed({}, PACKAGED)).toBe(false);
    expect(isOriginAllowed([], PACKAGED)).toBe(false);
    // A padded URL just over the cap — must fail without parsing.
    const oversized = "https://rud1.es/" + "a".repeat(MAX_SENDER_URL_LENGTH);
    expect(oversized.length).toBeGreaterThan(MAX_SENDER_URL_LENGTH);
    expect(isOriginAllowed(oversized, PACKAGED)).toBe(false);
  });

  it("rejects when allowedOrigin itself is malformed", () => {
    // Defensive: a broken RUD1_APP_ORIGIN env var must fail-closed, not
    // somehow accept everything.
    expect(
      isOriginAllowed("https://rud1.es/", {
        isPackaged: true,
        allowedOrigin: "not-a-url",
      }),
    ).toBe(false);
  });
});

// ─── 6. isOriginAllowed — dev-mode localhost ────────────────────────────────

describe("isOriginAllowed — dev-mode localhost bypass", () => {
  it("accepts localhost and 127.0.0.1 when !isPackaged", () => {
    expect(isOriginAllowed("http://localhost/", DEV)).toBe(true);
    expect(isOriginAllowed("http://localhost:5173/", DEV)).toBe(true);
    expect(isOriginAllowed("http://127.0.0.1/", DEV)).toBe(true);
    expect(isOriginAllowed("http://127.0.0.1:3000/", DEV)).toBe(true);
    expect(isOriginAllowed("https://localhost/", DEV)).toBe(true);
  });

  it("rejects the dev-mode bypass when packaged (PIN)", () => {
    // Critical: a packaged build must NEVER accept localhost. Otherwise a
    // compromised renderer that navigates to http://localhost/ bypasses
    // the production origin check.
    expect(isOriginAllowed("http://localhost/", PACKAGED)).toBe(false);
    expect(isOriginAllowed("http://127.0.0.1/", PACKAGED)).toBe(false);
  });

  it("rejects localhost-prefix smuggling in dev mode (PIN)", () => {
    // Old code did `url.startsWith("http://localhost")` which matches
    // `http://localhost.evil.com/` — classic DNS-rebinding + prefix
    // attack. Exact hostname compare rejects it.
    expect(isOriginAllowed("http://localhost.evil.com/", DEV)).toBe(false);
    expect(isOriginAllowed("http://127.0.0.1.evil.com/", DEV)).toBe(false);
    expect(isOriginAllowed("http://localhostx/", DEV)).toBe(false);
  });

  it("rejects 127.0.0.1-look-alike IPs in dev mode", () => {
    // `127.0.0.2`, `0.0.0.0` don't canonicalise to `127.0.0.1` and must
    // fall through to the (non-matching) production origin check.
    expect(isOriginAllowed("http://127.0.0.2/", DEV)).toBe(false);
    expect(isOriginAllowed("http://0.0.0.0/", DEV)).toBe(false);
    // IPv6 loopback — not currently accepted; flagged here as a pin.
    expect(isOriginAllowed("http://[::1]/", DEV)).toBe(false);
    // NOTE: we DO accept `http://127.1/` in dev mode. WHATWG URL
    // canonicalises `127.1` → `127.0.0.1` (IPv4 shorthand, RFC 3986
    // compatible), so after parsing it's the same hostname as the
    // standard loopback literal. This is defensible: the shorthand only
    // ever resolves to actual loopback — there's no DNS step that could
    // be rebinded. Pinned here as documented behavior.
    expect(isOriginAllowed("http://127.1/", DEV)).toBe(true);
  });

  it("dev mode still accepts the configured production origin", () => {
    // Running a dev build pointed at a real RUD1_APP_ORIGIN must still
    // work — the dev-mode branch falls through to the origin check when
    // the hostname isn't localhost.
    expect(isOriginAllowed("https://rud1.es/", DEV)).toBe(true);
  });
});

// ─── 7. checkSender — wraps isOriginAllowed via senderFrame ─────────────────

describe("checkSender — event.senderFrame integration", () => {
  // Minimal fake IpcMainInvokeEvent: just enough of the shape for the
  // sender check. We deliberately don't import the real Electron type
  // because it references `webContents` which is a class.
  function fakeEvent(senderFrame: { url: string } | null): Electron.IpcMainInvokeEvent {
    return { senderFrame } as unknown as Electron.IpcMainInvokeEvent;
  }

  it("accepts a trusted senderFrame.url", () => {
    expect(checkSender(fakeEvent({ url: "https://rud1.es/app" }))).toBe(true);
  });

  it("rejects a forged senderFrame.url (prefix attack)", () => {
    expect(checkSender(fakeEvent({ url: "https://rud1.es.evil.com/" }))).toBe(
      false,
    );
  });

  it("rejects when senderFrame is null (frame disposed race)", () => {
    // Electron's senderFrame getter can return null if the frame was
    // destroyed between dispatch and main-process handling. The check
    // must NOT throw and MUST fail closed.
    expect(() => checkSender(fakeEvent(null))).not.toThrow();
    expect(checkSender(fakeEvent(null))).toBe(false);
  });

  it("rejects when senderFrame.url is non-string", () => {
    // A hostile preload could plausibly set this to any JS value. The
    // check must not accept `undefined` or throw.
    const e = { senderFrame: { url: undefined } } as unknown as Electron.IpcMainInvokeEvent;
    expect(checkSender(e)).toBe(false);
    const e2 = { senderFrame: { url: 42 } } as unknown as Electron.IpcMainInvokeEvent;
    expect(checkSender(e2)).toBe(false);
  });

  it("rejects a senderFrame.url carrying CRLF (regression pin)", () => {
    expect(
      checkSender(fakeEvent({ url: "https://rud1.es/\r\nX-Evil:1" })),
    ).toBe(false);
  });
});

// ─── 8. Per-handler dispatch coverage ───────────────────────────────────────

describe("registerIpcHandlers — per-channel dispatch", () => {
  // Rationale (mirrors iter 21's auto-updater event-flow decision):
  //
  // Exercising each `ipcMain.handle` callback would require either
  //   (a) a full Electron main process (heavy, flakey in CI), or
  //   (b) re-implementing `ipcMain.handle` as a dispatch table here.
  //
  // For most channels (vpn:*, usb:*, net:*, diag:readReport, etc.) the only
  // per-handler logic is `checkSender + delegate-to-manager`, both already
  // exercised: checkSender by the suites above, the manager guards by their
  // own *.test.ts files. Re-running each as a dispatch test would be O(n)
  // duplication with no extra signal — left as `it.todo` placeholders.
  //
  // The exceptions are the three channels with INLINE arg-shape validators
  // (diag:mtuProbe / diag:compareReports / diag:autoSnapshotConfigure). Those
  // typeof checks live nowhere else, so they need direct coverage here. We
  // re-implement option (b) for those three only, scoped to one capture
  // harness shared across the iter-23 suites below.

  it.todo(
    "diag:readReport / diag:deleteReport with `../../../etc/passwd` " +
      "(skipped: path-traversal rejection is implemented in " +
      "tunnel-diag-manager.validateReportPath and covered in " +
      "tunnel-diag-manager.test.ts — this handler is pure delegation).",
  );

  it.todo(
    "vpn:connect rejects when sender origin is unauthorized " +
      "(skipped: identical control-flow for every channel — covered by " +
      "checkSender + isOriginAllowed suites above; registering each channel " +
      "as a dispatch test would be O(n) duplication with no extra signal).",
  );
});

// ─── 9. Inline arg-shape validators (iter 23) ───────────────────────────────
//
// These three channels carry a typeof-check the renderer payload must clear
// BEFORE the call reaches the manager. The manager has its own guards but
// they assume a typed shape — if the IPC validator regresses (e.g. someone
// drops the `typeof args.host !== "string"` line), a raw `123` flows through
// to the manager and produces a confusing crash instead of a clean envelope.
//
// Harness: re-use the existing `vi.mock("electron", ...)` ipcMain.handle
// spy. Calling `registerIpcHandlers()` populates `mock.calls` with
// `[channel, callback]` pairs — we reconstruct a `handlers` table from that
// and invoke individual callbacks with a fake event whose `senderFrame.url`
// is the allowlisted production origin (so checkSender passes and we
// actually exercise the validator instead of bouncing on the origin check).

import * as electronMock from "electron";
import { registerIpcHandlers } from "./ipc-handlers";
import { mtuProbe as mtuProbeMock } from "./tunnel-diag-manager";
import { compareReports as compareReportsMock } from "./tunnel-diag-manager";
import { configureAutoSnapshot as configureAutoSnapshotMock } from "./auto-snapshot-manager";

type Handler = (event: unknown, ...args: unknown[]) => unknown;
const handlers: Record<string, Handler> = {};

beforeAll(() => {
  // registerIpcHandlers() pushes 28 (channel, callback) pairs into our
  // `ipcMain.handle` vi.fn(). Build the dispatch table once.
  registerIpcHandlers();
  const calls = (electronMock.ipcMain.handle as unknown as { mock: { calls: unknown[][] } })
    .mock.calls;
  for (const [channel, callback] of calls) {
    handlers[channel as string] = callback as Handler;
  }
});

// fakeEvent with an allowlisted senderFrame.url — checkSender returns true
// for `https://rud1.es/` (matches ALLOWED_ORIGIN), so the validator runs.
const allowedEvent = {
  senderFrame: { url: "https://rud1.es/app" },
  sender: {},
} as unknown as Electron.IpcMainInvokeEvent;

describe("diag:mtuProbe — inline validator", () => {
  it("accepts a valid {host: string} payload and delegates to mtuProbe()", async () => {
    vi.mocked(mtuProbeMock).mockClear();
    const result = await handlers["diag:mtuProbe"](allowedEvent, {
      host: "10.0.0.1",
    });
    expect(result).toEqual({ ok: true, result: { mtu: 1500 } });
    expect(mtuProbeMock).toHaveBeenCalledWith("10.0.0.1", undefined);
  });

  it("forwards optional `opts` through to the manager", async () => {
    vi.mocked(mtuProbeMock).mockClear();
    await handlers["diag:mtuProbe"](allowedEvent, {
      host: "10.0.0.1",
      opts: { start: 1500, min: 1280, timeoutMs: 1000 },
    });
    expect(mtuProbeMock).toHaveBeenCalledWith("10.0.0.1", {
      start: 1500,
      min: 1280,
      timeoutMs: 1000,
    });
  });

  it("rejects when host is a number (typeof check)", async () => {
    vi.mocked(mtuProbeMock).mockClear();
    const result = await handlers["diag:mtuProbe"](allowedEvent, { host: 123 });
    expect(result).toEqual({ ok: false, error: "invalid args" });
    expect(mtuProbeMock).not.toHaveBeenCalled();
  });

  it("rejects when host is missing entirely", async () => {
    vi.mocked(mtuProbeMock).mockClear();
    const result = await handlers["diag:mtuProbe"](allowedEvent, {});
    expect(result).toEqual({ ok: false, error: "invalid args" });
    expect(mtuProbeMock).not.toHaveBeenCalled();
  });

  it("rejects when args is null / undefined / non-object", async () => {
    vi.mocked(mtuProbeMock).mockClear();
    for (const bad of [null, undefined, "10.0.0.1", 42, true]) {
      const result = await handlers["diag:mtuProbe"](allowedEvent, bad);
      expect(result).toEqual({ ok: false, error: "invalid args" });
    }
    expect(mtuProbeMock).not.toHaveBeenCalled();
  });

  it("returns Unauthorized envelope when checkSender fails", async () => {
    // Smuggle a forged senderFrame.url — validator must NOT run.
    vi.mocked(mtuProbeMock).mockClear();
    const evilEvent = {
      senderFrame: { url: "https://rud1.es.evil.com/" },
      sender: {},
    } as unknown as Electron.IpcMainInvokeEvent;
    const result = await handlers["diag:mtuProbe"](evilEvent, {
      host: "10.0.0.1",
    });
    expect(result).toEqual({ ok: false, error: "Unauthorized origin" });
    expect(mtuProbeMock).not.toHaveBeenCalled();
  });
});

describe("diag:compareReports — inline validator", () => {
  it("accepts {pathA, pathB} both strings and delegates to compareReports()", async () => {
    vi.mocked(compareReportsMock).mockClear();
    const result = await handlers["diag:compareReports"](allowedEvent, {
      pathA: "report-a.json",
      pathB: "report-b.json",
    });
    expect(result).toEqual({ ok: true, result: {} });
    expect(compareReportsMock).toHaveBeenCalledWith({
      pathA: "report-a.json",
      pathB: "report-b.json",
    });
  });

  it("rejects when pathA is missing", async () => {
    vi.mocked(compareReportsMock).mockClear();
    const result = await handlers["diag:compareReports"](allowedEvent, {
      pathB: "report-b.json",
    });
    expect(result).toEqual({ ok: false, error: "invalid args" });
    expect(compareReportsMock).not.toHaveBeenCalled();
  });

  it("rejects when pathB is missing", async () => {
    vi.mocked(compareReportsMock).mockClear();
    const result = await handlers["diag:compareReports"](allowedEvent, {
      pathA: "report-a.json",
    });
    expect(result).toEqual({ ok: false, error: "invalid args" });
    expect(compareReportsMock).not.toHaveBeenCalled();
  });

  it("rejects when either path is a non-string", async () => {
    vi.mocked(compareReportsMock).mockClear();
    for (const bad of [
      { pathA: 1, pathB: "ok.json" },
      { pathA: "ok.json", pathB: null },
      { pathA: ["a"], pathB: "ok.json" },
      { pathA: "ok.json", pathB: { nested: "x" } },
    ]) {
      const result = await handlers["diag:compareReports"](allowedEvent, bad);
      expect(result).toEqual({ ok: false, error: "invalid args" });
    }
    expect(compareReportsMock).not.toHaveBeenCalled();
  });

  it("rejects when args is null / undefined / non-object", async () => {
    vi.mocked(compareReportsMock).mockClear();
    for (const bad of [null, undefined, "report-a.json", 42]) {
      const result = await handlers["diag:compareReports"](allowedEvent, bad);
      expect(result).toEqual({ ok: false, error: "invalid args" });
    }
    expect(compareReportsMock).not.toHaveBeenCalled();
  });
});

describe("diag:autoSnapshotConfigure — inline validator", () => {
  it("accepts {enabled: true} and delegates to configureAutoSnapshot()", async () => {
    vi.mocked(configureAutoSnapshotMock).mockClear();
    const payload = { enabled: true, intervalMs: 600_000 };
    const result = await handlers["diag:autoSnapshotConfigure"](
      allowedEvent,
      payload,
    );
    expect(result).toEqual({ ok: true, result: {} });
    expect(configureAutoSnapshotMock).toHaveBeenCalledWith(payload);
  });

  it("accepts {enabled: false}", async () => {
    vi.mocked(configureAutoSnapshotMock).mockClear();
    const result = await handlers["diag:autoSnapshotConfigure"](allowedEvent, {
      enabled: false,
    });
    expect(result).toEqual({ ok: true, result: {} });
    expect(configureAutoSnapshotMock).toHaveBeenCalledWith({ enabled: false });
  });

  it("rejects when .enabled is a string (typeof check)", async () => {
    vi.mocked(configureAutoSnapshotMock).mockClear();
    const result = await handlers["diag:autoSnapshotConfigure"](allowedEvent, {
      enabled: "yes",
    });
    expect(result).toEqual({ ok: false, error: "invalid args" });
    expect(configureAutoSnapshotMock).not.toHaveBeenCalled();
  });

  it("rejects when .enabled is a number (1/0 are NOT booleans)", async () => {
    vi.mocked(configureAutoSnapshotMock).mockClear();
    for (const bad of [1, 0, NaN]) {
      const result = await handlers["diag:autoSnapshotConfigure"](
        allowedEvent,
        { enabled: bad },
      );
      expect(result).toEqual({ ok: false, error: "invalid args" });
    }
    expect(configureAutoSnapshotMock).not.toHaveBeenCalled();
  });

  it("rejects when .enabled is missing", async () => {
    vi.mocked(configureAutoSnapshotMock).mockClear();
    const result = await handlers["diag:autoSnapshotConfigure"](allowedEvent, {
      intervalMs: 600_000,
    });
    expect(result).toEqual({ ok: false, error: "invalid args" });
    expect(configureAutoSnapshotMock).not.toHaveBeenCalled();
  });

  it("rejects when payload is null / undefined / non-object", async () => {
    vi.mocked(configureAutoSnapshotMock).mockClear();
    for (const bad of [null, undefined, true, "enabled", 42]) {
      const result = await handlers["diag:autoSnapshotConfigure"](
        allowedEvent,
        bad,
      );
      expect(result).toEqual({ ok: false, error: "invalid args" });
    }
    expect(configureAutoSnapshotMock).not.toHaveBeenCalled();
  });
});

// ─── 10. Iter 37 — versionCheck:state / clipboard / shell:openExternal ──────
//
// New IPC channels added in iter 37 to power the Settings/About panel's
// "Updates" section. Coverage:
//   • versionCheck:state    — returns the live VersionCheckState
//   • versionCheck:recheck  — forwards to the manager's checkOnce
//   • clipboard:writeText   — length-cap + typeof check, delegate to clipboard
//   • shell:openExternal    — http/https allowlist + delegate to shell

import { clipboard as clipboardMock, shell as shellMock } from "electron";
const { isOpenExternalUrlAllowed, MAX_CLIPBOARD_TEXT_LENGTH } = __test;

describe("isOpenExternalUrlAllowed (iter 37 allowlist)", () => {
  it("accepts http and https URLs", () => {
    expect(isOpenExternalUrlAllowed("https://rud1.es/changelog")).toBe(true);
    expect(isOpenExternalUrlAllowed("http://example.test/page")).toBe(true);
  });

  it("rejects javascript:, data:, file:, mailto: schemes", () => {
    expect(isOpenExternalUrlAllowed("javascript:alert(1)")).toBe(false);
    expect(isOpenExternalUrlAllowed("data:text/html,<h1>x</h1>")).toBe(false);
    expect(isOpenExternalUrlAllowed("file:///etc/passwd")).toBe(false);
    expect(isOpenExternalUrlAllowed("mailto:foo@bar.test")).toBe(false);
  });

  it("rejects URLs with userinfo (credential smuggling)", () => {
    expect(isOpenExternalUrlAllowed("https://user:pass@rud1.es/")).toBe(false);
    expect(isOpenExternalUrlAllowed("https://user@rud1.es/")).toBe(false);
  });

  it("rejects URLs with control characters / whitespace (CRLF injection)", () => {
    expect(isOpenExternalUrlAllowed("https://rud1.es/\r\nX:1")).toBe(false);
    expect(isOpenExternalUrlAllowed("https://rud1.es /space")).toBe(false);
  });

  it("rejects non-string and oversize input", () => {
    expect(isOpenExternalUrlAllowed(undefined)).toBe(false);
    expect(isOpenExternalUrlAllowed(null)).toBe(false);
    expect(isOpenExternalUrlAllowed(42)).toBe(false);
    expect(isOpenExternalUrlAllowed("https://" + "a".repeat(3000))).toBe(false);
  });

  it("rejects unparseable inputs", () => {
    expect(isOpenExternalUrlAllowed("")).toBe(false);
    expect(isOpenExternalUrlAllowed("not a url")).toBe(false);
  });
});

describe("clipboard:writeText handler (iter 37)", () => {
  it("delegates to electron.clipboard.writeText on a valid payload", async () => {
    vi.mocked(clipboardMock.writeText).mockClear();
    const result = await handlers["clipboard:writeText"](
      allowedEvent,
      "https://rud1.es/desktop/download?version=1.2.0",
    );
    expect(result).toEqual({ ok: true });
    expect(clipboardMock.writeText).toHaveBeenCalledWith(
      "https://rud1.es/desktop/download?version=1.2.0",
    );
  });

  it("rejects non-string payload", async () => {
    vi.mocked(clipboardMock.writeText).mockClear();
    const result = await handlers["clipboard:writeText"](allowedEvent, 42);
    expect(result).toEqual({ ok: false, error: "invalid text" });
    expect(clipboardMock.writeText).not.toHaveBeenCalled();
  });

  it("rejects empty string", async () => {
    vi.mocked(clipboardMock.writeText).mockClear();
    const result = await handlers["clipboard:writeText"](allowedEvent, "");
    expect(result).toEqual({ ok: false, error: "empty text" });
    expect(clipboardMock.writeText).not.toHaveBeenCalled();
  });

  it("rejects payload exceeding MAX_CLIPBOARD_TEXT_LENGTH", async () => {
    vi.mocked(clipboardMock.writeText).mockClear();
    const big = "x".repeat(MAX_CLIPBOARD_TEXT_LENGTH + 1);
    const result = await handlers["clipboard:writeText"](allowedEvent, big);
    expect(result).toEqual({ ok: false, error: "text exceeds size cap" });
    expect(clipboardMock.writeText).not.toHaveBeenCalled();
  });

  it("rejects when sender origin is unauthorized", async () => {
    vi.mocked(clipboardMock.writeText).mockClear();
    const evilEvent = {
      senderFrame: { url: "https://evil.example/" },
      sender: {},
    } as unknown as Electron.IpcMainInvokeEvent;
    const result = await handlers["clipboard:writeText"](evilEvent, "hello");
    expect(result).toEqual({ ok: false, error: "Unauthorized origin" });
    expect(clipboardMock.writeText).not.toHaveBeenCalled();
  });
});

describe("shell:openExternal handler (iter 37)", () => {
  it("delegates to electron.shell.openExternal on an allowlisted URL", async () => {
    vi.mocked(shellMock.openExternal).mockClear();
    const result = await handlers["shell:openExternal"](
      allowedEvent,
      "https://rud1.es/changelog/v1.5.0",
    );
    expect(result).toEqual({ ok: true });
    expect(shellMock.openExternal).toHaveBeenCalledWith(
      "https://rud1.es/changelog/v1.5.0",
    );
  });

  it("rejects javascript: scheme without invoking shell.openExternal", async () => {
    vi.mocked(shellMock.openExternal).mockClear();
    const result = await handlers["shell:openExternal"](
      allowedEvent,
      "javascript:alert(1)",
    );
    expect(result).toEqual({ ok: false, error: "URL rejected by allowlist" });
    expect(shellMock.openExternal).not.toHaveBeenCalled();
  });

  it("rejects non-string payload", async () => {
    vi.mocked(shellMock.openExternal).mockClear();
    const result = await handlers["shell:openExternal"](allowedEvent, 42);
    expect(result).toEqual({ ok: false, error: "URL rejected by allowlist" });
    expect(shellMock.openExternal).not.toHaveBeenCalled();
  });
});

describe("versionCheck:state / versionCheck:recheck (iter 37)", () => {
  // These channels only register when the registrar is given a
  // VersionCheckAccessor. The shared `beforeAll` calls
  // `registerIpcHandlers()` with no opts, so the `handlers` table built
  // there does NOT include the version-check channels — testing the
  // registration gate is the point. We re-register here with a stub
  // accessor and a fresh ipcMain.handle call list.

  let vcHandlers: Record<string, Handler> = {};

  beforeAll(() => {
    // Snapshot the call count so we can isolate the iter-37 calls.
    const handleSpy = electronMock.ipcMain.handle as unknown as {
      mock: { calls: unknown[][] };
    };
    const before = handleSpy.mock.calls.length;
    registerIpcHandlers({
      versionCheck: {
        getState: () => ({
          kind: "update-blocked-by-min-bootstrap",
          requiredMinVersion: "1.2.0",
          currentVersion: "1.0.0",
          targetVersion: "1.5.0",
          releaseNotesUrl: null,
          checkedAt: 1_700_000_000_000,
        }),
        recheck: vi.fn(),
      },
    });
    for (const [channel, callback] of handleSpy.mock.calls.slice(before)) {
      vcHandlers[channel as string] = callback as Handler;
    }
  });

  it("versionCheck:state returns a JSON-cloned snapshot of the live state", async () => {
    const result = await vcHandlers["versionCheck:state"](allowedEvent);
    expect(result).toEqual({
      ok: true,
      result: {
        kind: "update-blocked-by-min-bootstrap",
        requiredMinVersion: "1.2.0",
        currentVersion: "1.0.0",
        targetVersion: "1.5.0",
        releaseNotesUrl: null,
        checkedAt: 1_700_000_000_000,
      },
    });
  });

  it("versionCheck:state rejects an unauthorized origin", async () => {
    const evilEvent = {
      senderFrame: { url: "https://evil.example/" },
      sender: {},
    } as unknown as Electron.IpcMainInvokeEvent;
    const result = await vcHandlers["versionCheck:state"](evilEvent);
    expect(result).toEqual({ ok: false, error: "Unauthorized origin" });
  });

  it("versionCheck:recheck is registered (channel present in dispatch table)", () => {
    expect(typeof vcHandlers["versionCheck:recheck"]).toBe("function");
  });

  it("versionCheck:recheck delegates to accessor.recheck and returns ok", async () => {
    const result = await vcHandlers["versionCheck:recheck"](allowedEvent);
    expect(result).toEqual({ ok: true });
  });
});
