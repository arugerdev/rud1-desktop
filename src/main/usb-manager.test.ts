/**
 * Unit tests for usb-manager (iter 19).
 *
 * Scope:
 *   • validateHost / validateBusId / validatePort — shape checks.
 *   • assertHost / assertBusId / assertPort — throw-on-invalid guards.
 *     These are the security invariants: usbip is invoked via execFile
 *     with argv, but execFile still treats leading-dash values as flags,
 *     so a renderer sending `busId="-h attacker.com"` could redirect the
 *     attach if guards weren't in place. The assertions MUST throw
 *     synchronously before any spawn.
 *   • parseAttachPort — scrape `Port N imported` from `usbip attach`.
 *   • parseUsbipPort — scrape attached-device rows from `usbip port`.
 *   • usbAttach / usbDetach — guards run before spawn (no child_process
 *     mock needed; the guard throws synchronously and we never reach
 *     execFile). Happy paths with a mocked usbip binary are `it.todo`
 *     with honest justification — same spawn-mock brittleness argument
 *     as net-diag-manager.test.ts (iter 18).
 *
 * Mocking strategy (mirrors iter 18 / net-diag-manager.test.ts):
 *   • No child_process mock. The validators throw before spawn, so we
 *     only need to assert the rejection — no subprocess is ever launched
 *     for the security tests.
 *   • No electron mock either; usb-manager imports binary-helper which
 *     imports electron, but we never actually invoke any electron APIs
 *     in the test paths we touch (validators + parsers are pure).
 */

import { describe, expect, it, vi } from "vitest";

// binary-helper pulls in electron at import time; stub it so vitest can
// load usb-manager without a running Electron runtime. We only need a
// no-op shape — usbipPath() is never called in these tests (the happy
// paths are it.todo'd).
vi.mock("electron", () => ({
  app: {
    isPackaged: false,
    getAppPath: () => process.cwd(),
  },
}));

import {
  validateHost,
  validateBusId,
  validatePort,
  usbAttach,
  usbDetach,
  __test,
} from "./usb-manager";

const {
  assertHost,
  assertBusId,
  assertPort,
  parseAttachPort,
  parseUsbipPort,
  HOST_REGEX,
  BUS_ID_REGEX,
} = __test;

// ─── 1. validateHost ────────────────────────────────────────────────────────

describe("validateHost", () => {
  it("accepts hostnames, IPv4 and IPv6 literals", () => {
    for (const ok of [
      "example.com",
      "192.168.1.1",
      "10.77.5.1",
      "sub.domain.co.uk",
      "localhost",
      "rud1",
      "fd00::1",
      "2001:db8::1",
    ]) {
      expect(validateHost(ok)).toBe(true);
    }
  });

  it("rejects leading-dash values (flag-injection defence)", () => {
    // This is the primary attack usbip is vulnerable to: a `host` that
    // starts with `-` would be parsed by usbip as a flag (`-r`, `-h`, etc.)
    // instead of a positional host argument. The guard MUST reject these
    // even though they contain no shell metacharacters.
    for (const bad of ["-r", "-h", "--help", "-x", "-attacker.com"]) {
      expect(validateHost(bad)).toBe(false);
    }
  });

  it("rejects shell metacharacters and injection attempts", () => {
    for (const bad of [
      "host;whoami",
      "host|nc evil 4444",
      "host&&id",
      "host`id`",
      "host$(id)",
      "host\nrm",
      "host with space",
      "../etc/passwd",
      "host/path",
      "host'quote",
      'host"quote',
      "host\\slash",
      "host?q=1",
      "host*wild",
      "http://host",
    ]) {
      expect(validateHost(bad)).toBe(false);
    }
  });

  it("rejects empty and non-string values", () => {
    expect(validateHost("")).toBe(false);
    expect(validateHost(undefined)).toBe(false);
    expect(validateHost(null)).toBe(false);
    expect(validateHost(42)).toBe(false);
    expect(validateHost({})).toBe(false);
  });

  it("rejects strings longer than 253 chars (HOST_REGEX upper bound)", () => {
    expect(validateHost("a".repeat(253))).toBe(true);
    expect(validateHost("a".repeat(254))).toBe(false);
  });
});

// ─── 2. validateBusId ───────────────────────────────────────────────────────

describe("validateBusId", () => {
  it("accepts well-formed usbip bus IDs", () => {
    for (const ok of [
      "1-1",
      "1-1.2",
      "2-3",
      "2-3.4.5",
      "10-12.3",
      "0-0",
    ]) {
      expect(validateBusId(ok)).toBe(true);
    }
  });

  it("rejects shell metacharacters, flags, and path separators", () => {
    for (const bad of [
      "-h evil.com",   // leading dash — would be parsed as a flag
      "--b",
      "1-1;whoami",
      "1-1|nc",
      "1-1 && id",
      "1-1`id`",
      "1-1$(id)",
      "1-1\nfoo",
      "1-1 ../etc",
      "1-1/path",
      "1-1\\path",
      "1-a",            // non-numeric segment
      "a-1",
      "1",              // missing dash
      "1-",             // dangling dash
      "-1",
      "1..2",
      "1-1.",
    ]) {
      expect(validateBusId(bad)).toBe(false);
    }
  });

  it("rejects empty and non-string values", () => {
    expect(validateBusId("")).toBe(false);
    expect(validateBusId(undefined)).toBe(false);
    expect(validateBusId(null)).toBe(false);
    expect(validateBusId(5)).toBe(false);
  });
});

// ─── 3. validatePort ────────────────────────────────────────────────────────

describe("validatePort", () => {
  it("accepts integers in [0, 65535]", () => {
    for (const ok of [0, 1, 3240, 8080, 65535]) {
      expect(validatePort(ok)).toBe(true);
    }
  });

  it("rejects out-of-range numbers", () => {
    expect(validatePort(-1)).toBe(false);
    expect(validatePort(65536)).toBe(false);
    expect(validatePort(Number.MAX_SAFE_INTEGER)).toBe(false);
  });

  it("rejects non-integer, non-finite, and non-number inputs", () => {
    expect(validatePort(1.5)).toBe(false);
    expect(validatePort(NaN)).toBe(false);
    expect(validatePort(Infinity)).toBe(false);
    expect(validatePort("3240")).toBe(false);
    expect(validatePort(null)).toBe(false);
    expect(validatePort(undefined)).toBe(false);
  });
});

// ─── 4. assertHost / assertBusId / assertPort ───────────────────────────────

describe("assertHost", () => {
  it("is a no-op for valid hosts", () => {
    expect(() => assertHost("10.0.0.1")).not.toThrow();
    expect(() => assertHost("example.com")).not.toThrow();
  });

  it("throws `invalid host` before any spawn could happen", () => {
    // The core security contract: if this throws, no usbip subprocess
    // is ever launched. We verify via usbAttach below that the guard
    // actually fires at the public-API boundary — here we only pin the
    // message shape so callers can pattern-match on it.
    expect(() => assertHost("-r attacker.com")).toThrow(/invalid host/);
    expect(() => assertHost("foo;rm -rf /")).toThrow(/invalid host/);
    expect(() => assertHost("")).toThrow(/invalid host/);
  });
});

describe("assertBusId", () => {
  it("is a no-op for valid bus IDs", () => {
    expect(() => assertBusId("1-1")).not.toThrow();
    expect(() => assertBusId("2-3.4.5")).not.toThrow();
  });

  it("throws `invalid busId` for any malformed input", () => {
    expect(() => assertBusId("-h evil")).toThrow(/invalid busId/);
    expect(() => assertBusId("1-1;id")).toThrow(/invalid busId/);
    expect(() => assertBusId("")).toThrow(/invalid busId/);
  });
});

describe("assertPort", () => {
  it("is a no-op for valid ports", () => {
    expect(() => assertPort(3240)).not.toThrow();
    expect(() => assertPort(0)).not.toThrow();
  });

  it("throws `invalid port` for negatives, out-of-range, or non-int", () => {
    expect(() => assertPort(-1)).toThrow(/invalid port/);
    expect(() => assertPort(99999)).toThrow(/invalid port/);
    expect(() => assertPort(1.5)).toThrow(/invalid port/);
    expect(() => (assertPort as (p: unknown) => void)("3240")).toThrow(
      /invalid port/,
    );
  });
});

// ─── 5. Public-API security invariants (reject BEFORE spawn) ────────────────

describe("usbAttach / usbDetach — guards run before any spawn", () => {
  // These tests confirm the guard is wired at the public boundary. No
  // child_process mock is needed: the assertion throws synchronously, so
  // execFile is never invoked. If the guard were ever removed, this test
  // would fail because usbAttach would instead try to spawn a real
  // usbip and either hang or error with a spawn ENOENT — neither of
  // which matches the /invalid host/ pattern.

  it("usbAttach rejects an invalid host without spawning", async () => {
    await expect(usbAttach("-r evil.com", "1-1")).rejects.toThrow(
      /invalid host/,
    );
    await expect(usbAttach("host;whoami", "1-1")).rejects.toThrow(
      /invalid host/,
    );
  });

  it("usbAttach rejects an invalid busId without spawning", async () => {
    await expect(usbAttach("10.0.0.1", "-h evil")).rejects.toThrow(
      /invalid busId/,
    );
    await expect(usbAttach("10.0.0.1", "1-1;id")).rejects.toThrow(
      /invalid busId/,
    );
    await expect(usbAttach("10.0.0.1", "")).rejects.toThrow(/invalid busId/);
  });

  it("usbDetach rejects a non-integer / out-of-range port", async () => {
    await expect(usbDetach(-1)).rejects.toThrow(/invalid port/);
    await expect(usbDetach(99999)).rejects.toThrow(/invalid port/);
    await expect(usbDetach(1.5)).rejects.toThrow(/invalid port/);
    await expect(
      (usbDetach as (p: unknown) => Promise<void>)("3"),
    ).rejects.toThrow(/invalid port/);
  });

  it("HOST_REGEX rejects the full shell-metacharacter attack set", () => {
    // Redundant with validateHost() tests above, but pins the raw regex
    // so future tightening is a deliberate change (mirrors net-diag-manager).
    const attacks = [
      "host;id",
      "host|nc evil 4444",
      "host&&whoami",
      "host`id`",
      "host$(id)",
      "host\nrm",
      "host with space",
      "../../etc/passwd",
      "host/../etc/passwd",
    ];
    for (const a of attacks) expect(HOST_REGEX.test(a)).toBe(false);
  });

  it("BUS_ID_REGEX only matches `N-N[.N...]` shape", () => {
    expect(BUS_ID_REGEX.test("1-1")).toBe(true);
    expect(BUS_ID_REGEX.test("1-1.2.3")).toBe(true);
    expect(BUS_ID_REGEX.test("1-")).toBe(false);
    expect(BUS_ID_REGEX.test("-1")).toBe(false);
    expect(BUS_ID_REGEX.test("1_1")).toBe(false);
    expect(BUS_ID_REGEX.test("1.1")).toBe(false);
  });
});

// ─── 6. parseAttachPort ─────────────────────────────────────────────────────

describe("parseAttachPort", () => {
  it("extracts the port number from a typical usbip-attach stdout", () => {
    expect(parseAttachPort("usbip: info: Port 0 imported\n")).toBe(0);
    expect(parseAttachPort("usbip: info: Port 7 imported\n")).toBe(7);
    expect(parseAttachPort("Port 12 imported\n")).toBe(12);
  });

  it("returns 0 when no port is mentioned (parse-miss fallback)", () => {
    expect(parseAttachPort("")).toBe(0);
    expect(parseAttachPort("usbip: error: something\n")).toBe(0);
  });

  it("is case-insensitive on the `Port` keyword", () => {
    expect(parseAttachPort("port 3 imported")).toBe(3);
    expect(parseAttachPort("PORT 4 imported")).toBe(4);
  });
});

// ─── 7. parseUsbipPort ──────────────────────────────────────────────────────

describe("parseUsbipPort", () => {
  // Two wire formats, both shipped under the `usbip` name and both
  // targeted by the desktop manager: kernel.org usbip-utils on Linux
  // (host + busId on the line after the `Port N:` header) and
  // usbip-win2 on Windows (host + busId in a `-> usbip://host:port/busId`
  // line). Coverage hits both plus a couple of edge cases the old
  // single-regex parser silently dropped.

  it("parses the kernel.org Linux format (lowercase 'speed')", () => {
    const stdout = [
      "Imported USB devices",
      "====================",
      "Port 00: <Port in Use> at High speed(480Mbps)",
      "       vendor/product : product desc (10.0.0.5) 1-1.2",
    ].join("\n");
    const devices = parseUsbipPort(stdout);
    expect(devices).toHaveLength(1);
    expect(devices[0]).toEqual({ port: 0, host: "10.0.0.5", busId: "1-1.2" });
  });

  it("parses the modern Linux format with capital-S 'Speed'", () => {
    // Old single-regex parser silently dropped this; line-based scan
    // doesn't care about the speed-line wording.
    const stdout = [
      "Port 00: <Port in Use> at High Speed(480Mbps)",
      "       descA (10.0.0.5) 1-1",
    ].join("\n");
    expect(parseUsbipPort(stdout)).toEqual([
      { port: 0, host: "10.0.0.5", busId: "1-1" },
    ]);
  });

  it("parses the usbip-win2 format with `-> usbip://host:port/busId`", () => {
    const stdout = [
      "Imported USB devices",
      "====================",
      "Port 01: device in use at Full Speed(12Mbps)",
      "         dog hunter AG : Arduino Uno Rev3 (2a03:0043)",
      "           -> usbip://10.99.91.243:3240/1-1.5",
      "           -> remote bus/dev 001/004",
    ].join("\n");
    expect(parseUsbipPort(stdout)).toEqual([
      { port: 1, host: "10.99.91.243", busId: "1-1.5" },
    ]);
  });

  it("returns [] when no port-in-use block is present", () => {
    expect(parseUsbipPort("")).toEqual([]);
    expect(parseUsbipPort("Imported USB devices\n====================\n")).toEqual([]);
  });

  it("parses multiple attached devices into separate entries (mixed formats)", () => {
    const stdout = [
      "Port 00: <Port in Use> at High speed(480Mbps)",
      "       descA (10.0.0.5) 1-1",
      "Port 01: device in use at Super Speed(5000Mbps)",
      "         vendor : product (1234:5678)",
      "           -> usbip://10.0.0.6:3240/2-3.4",
    ].join("\n");
    const devices = parseUsbipPort(stdout);
    expect(devices).toHaveLength(2);
    expect(devices[0]).toEqual({ port: 0, host: "10.0.0.5", busId: "1-1" });
    expect(devices[1]).toEqual({ port: 1, host: "10.0.0.6", busId: "2-3.4" });
  });

  it("ignores `Port N:` blocks where neither host nor busId line ever arrives", () => {
    // Truncated output (process killed mid-print, partial pipe) shouldn't
    // produce a half-formed AttachedDevice — the kernel snapshot is
    // either authoritative or absent.
    expect(parseUsbipPort("Port 00: device in use at High Speed\n")).toEqual([]);
  });
});

// ─── 8. Spawn-driven happy paths — honest it.todo ───────────────────────────

describe("usbAttach / usbDetach / usbList — happy paths", () => {
  it.todo(
    "usbAttach returns the parsed port when usbip stdout reports `Port N imported` " +
      "(skipped: mocking the promisified execFile event chain is too brittle " +
      "for the value it adds — parseAttachPort is already covered via raw " +
      "fixtures above, and the security invariant that assertHost/assertBusId " +
      "precede spawn is covered by the rejection tests)",
  );

  it.todo(
    "usbDetach invokes usbip with `detach -p <port>` when the port is valid " +
      "(skipped: same execFile-mock brittleness rationale)",
  );

  it.todo(
    "usbList returns parsed AttachedDevice rows from `usbip port` stdout " +
      "(skipped: parseUsbipPort is exercised directly via raw fixtures)",
  );
});
