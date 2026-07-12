import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Controllable adapter IP + real isApipa. netsh/ping are stubbed via the
// child_process mock below so no subprocess is ever spawned.
let mockAdapterIp: string | null = null;
vi.mock("./apipa-fallback", async (importActual) => {
  const actual = await importActual<typeof import("./apipa-fallback")>();
  return {
    ...actual,
    readAdapterIpV4: vi.fn(async () => mockAdapterIp),
  };
});

// promisify(execFile)-compatible stub: ping "fails" (host free), netsh succeeds.
const execFileCalls: string[][] = [];
vi.mock("child_process", () => ({
  execFile: (
    cmd: string,
    args: string[],
    _opts: unknown,
    cb?: (err: Error | null, out?: { stdout: string; stderr: string }) => void,
  ) => {
    const done = cb ?? (_opts as typeof cb)!;
    execFileCalls.push([cmd, ...args]);
    if (cmd === "ping") done(new Error("request timed out"));
    else done(null, { stdout: "", stderr: "" });
  },
}));

import {
  parseIpv4,
  isIpv4Literal,
  sameSlash24,
  candidateClientIps,
  ensureTapReachableForHost,
} from "./tap-reachability";

describe("tap-reachability pure helpers", () => {
  describe("parseIpv4 / isIpv4Literal", () => {
    it("parses a valid dotted-quad", () => {
      expect(parseIpv4("192.168.0.42")).toEqual([192, 168, 0, 42]);
    });
    it("rejects out-of-range octets", () => {
      expect(parseIpv4("192.168.0.256")).toBeNull();
      expect(parseIpv4("300.1.1.1")).toBeNull();
    });
    it("rejects non-literals (DNS names, partials, empty)", () => {
      expect(parseIpv4("device.rud1.es")).toBeNull();
      expect(parseIpv4("192.168.0")).toBeNull();
      expect(parseIpv4("")).toBeNull();
    });
    it("isIpv4Literal narrows only true IPv4 strings", () => {
      expect(isIpv4Literal("10.0.0.1")).toBe(true);
      expect(isIpv4Literal("vps.rud1.es")).toBe(false);
      expect(isIpv4Literal(42)).toBe(false);
      expect(isIpv4Literal(null)).toBe(false);
    });
  });

  describe("sameSlash24", () => {
    it("true when the first three octets match", () => {
      expect(sameSlash24("192.168.0.5", "192.168.0.250")).toBe(true);
    });
    it("false across a /24 boundary", () => {
      expect(sameSlash24("192.168.0.5", "192.168.1.5")).toBe(false);
    });
    it("false for APIPA vs a real LAN", () => {
      expect(sameSlash24("169.254.10.1", "192.168.0.10")).toBe(false);
    });
    it("false on malformed input", () => {
      expect(sameSlash24("not-an-ip", "192.168.0.10")).toBe(false);
    });
  });

  describe("candidateClientIps", () => {
    it("returns .250 → .200 inside the device /24", () => {
      const c = candidateClientIps("192.168.0.10");
      expect(c[0]).toBe("192.168.0.250");
      expect(c[c.length - 1]).toBe("192.168.0.200");
      expect(c).toHaveLength(51);
    });
    it("never collides with the device's own octet", () => {
      const c = candidateClientIps("192.168.0.222");
      expect(c).not.toContain("192.168.0.222");
      expect(c).toHaveLength(50);
    });
    it("preserves the device's network prefix", () => {
      const c = candidateClientIps("10.44.7.9");
      expect(c.every((ip) => ip.startsWith("10.44.7."))).toBe(true);
    });
    it("empty for a non-literal host", () => {
      expect(candidateClientIps("device.rud1.es")).toEqual([]);
    });
  });
});

describe("ensureTapReachableForHost", () => {
  const ADAPTER = "rud1-tap";
  let originalPlatform: PropertyDescriptor | undefined;

  beforeEach(() => {
    execFileCalls.length = 0;
    mockAdapterIp = null;
    // Force the Windows path regardless of the CI/host OS.
    originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { value: "win32", configurable: true });
  });
  afterEach(() => {
    if (originalPlatform) Object.defineProperty(process, "platform", originalPlatform);
  });

  it("skips non-IPv4 hosts (can't derive a subnet from a DNS name)", async () => {
    const r = await ensureTapReachableForHost("device.rud1.es", ADAPTER);
    expect(r).toEqual({ applied: false, reason: "host-not-ipv4" });
    expect(execFileCalls).toHaveLength(0);
  });

  it("link-local host + APIPA adapter → reachable, no netsh (the no-Ethernet case)", async () => {
    mockAdapterIp = "169.254.238.104";
    const r = await ensureTapReachableForHost("169.254.10.20", ADAPTER);
    expect(r.applied).toBe(false);
    expect(r.reason).toBe("link-local-reachable");
    // Must NOT narrow the /16 by writing a static address.
    expect(execFileCalls.some((c) => c[0] === "netsh")).toBe(false);
  });

  it("link-local host + no adapter IP → reachable (APIPA will appear)", async () => {
    mockAdapterIp = null;
    const r = await ensureTapReachableForHost("169.254.10.20", ADAPTER);
    expect(r.reason).toBe("link-local-reachable");
    expect(execFileCalls.some((c) => c[0] === "netsh")).toBe(false);
  });

  it("link-local host + routable lease → left alone (non-case on shared bridge)", async () => {
    mockAdapterIp = "192.168.0.50";
    const r = await ensureTapReachableForHost("169.254.10.20", ADAPTER);
    expect(r).toEqual({
      applied: false,
      reason: "link-local-host-routable-client",
      finalIp: "192.168.0.50",
    });
    expect(execFileCalls.some((c) => c[0] === "netsh")).toBe(false);
  });

  it("routable host + APIPA adapter → self-assigns a same-/24 static IP", async () => {
    mockAdapterIp = "169.254.238.104";
    const r = await ensureTapReachableForHost("192.168.0.10", ADAPTER);
    expect(r.applied).toBe(true);
    expect(r.reason).toBe("self-assigned");
    expect(r.finalIp?.startsWith("192.168.0.")).toBe(true);
    const netsh = execFileCalls.find((c) => c[0] === "netsh");
    expect(netsh).toBeTruthy();
    expect(netsh!.join(" ")).toContain("255.255.255.0");
  });

  it("routable host already in the same /24 → already-reachable, no netsh", async () => {
    mockAdapterIp = "192.168.0.77";
    const r = await ensureTapReachableForHost("192.168.0.10", ADAPTER);
    expect(r).toEqual({ applied: false, reason: "already-reachable", finalIp: "192.168.0.77" });
    expect(execFileCalls.some((c) => c[0] === "netsh")).toBe(false);
  });

  it("routable host + routable lease in another subnet → keeps the lease", async () => {
    mockAdapterIp = "10.0.0.5";
    const r = await ensureTapReachableForHost("192.168.0.10", ADAPTER);
    expect(r.reason).toBe("foreign-lease-kept");
    expect(execFileCalls.some((c) => c[0] === "netsh")).toBe(false);
  });

  it("non-Windows → no-op", async () => {
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    const r = await ensureTapReachableForHost("192.168.0.10", ADAPTER);
    expect(r).toEqual({ applied: false, reason: "non-windows" });
  });
});
