import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Controllable adapter IP + real isApipa. This module never spawns a
// subprocess (it only READS the adapter IP), so there's no child_process to
// stub — we only control what readAdapterIpV4 returns.
let mockAdapterIp: string | null = null;
vi.mock("./apipa-fallback", async (importActual) => {
  const actual = await importActual<typeof import("./apipa-fallback")>();
  return {
    ...actual,
    readAdapterIpV4: vi.fn(async () => mockAdapterIp),
  };
});

import {
  parseIpv4,
  isIpv4Literal,
  sameSlash24,
  diagnoseTapReachability,
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
});

describe("diagnoseTapReachability (read-only — never mutates)", () => {
  const ADAPTER = "rud1-tap";
  let originalPlatform: PropertyDescriptor | undefined;

  beforeEach(() => {
    mockAdapterIp = null;
    // Force the Windows path regardless of the CI/host OS.
    originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
    Object.defineProperty(process, "platform", { value: "win32", configurable: true });
  });
  afterEach(() => {
    if (originalPlatform) Object.defineProperty(process, "platform", originalPlatform);
  });

  it("non-IPv4 host → not assessed, not flagged", async () => {
    const d = await diagnoseTapReachability("device.rud1.es", ADAPTER);
    expect(d).toEqual({ likelyReachable: true, reason: "host-not-ipv4", adapterIp: null });
  });

  it("link-local host + APIPA adapter → reachable (the no-Ethernet case)", async () => {
    mockAdapterIp = "169.254.238.104";
    const d = await diagnoseTapReachability("169.254.10.20", ADAPTER);
    expect(d.likelyReachable).toBe(true);
    expect(d.reason).toBe("link-local-both-169254");
    expect(d.adapterIp).toBe("169.254.238.104");
  });

  it("link-local host + no adapter IP → reachable (APIPA will appear)", async () => {
    mockAdapterIp = null;
    const d = await diagnoseTapReachability("169.254.10.20", ADAPTER);
    expect(d.likelyReachable).toBe(true);
    expect(d.reason).toBe("link-local-both-169254");
  });

  it("link-local host + routable client → flagged unreachable", async () => {
    mockAdapterIp = "192.168.0.50";
    const d = await diagnoseTapReachability("169.254.10.20", ADAPTER);
    expect(d).toEqual({
      likelyReachable: false,
      reason: "link-local-host-but-routable-client",
      adapterIp: "192.168.0.50",
    });
  });

  it("routable host + same /24 adapter → reachable", async () => {
    mockAdapterIp = "192.168.0.77";
    const d = await diagnoseTapReachability("192.168.0.10", ADAPTER);
    expect(d).toEqual({ likelyReachable: true, reason: "same-subnet", adapterIp: "192.168.0.77" });
  });

  it("routable host + APIPA adapter → flagged unreachable", async () => {
    mockAdapterIp = "169.254.238.104";
    const d = await diagnoseTapReachability("192.168.0.10", ADAPTER);
    expect(d.likelyReachable).toBe(false);
    expect(d.reason).toBe("routable-host-apipa-client");
  });

  it("routable host + no adapter IP → flagged unreachable", async () => {
    mockAdapterIp = null;
    const d = await diagnoseTapReachability("192.168.0.10", ADAPTER);
    expect(d.likelyReachable).toBe(false);
    expect(d.reason).toBe("routable-host-no-adapter-ip");
  });

  it("routable host + adapter in a different subnet → flagged unreachable", async () => {
    mockAdapterIp = "10.0.0.5";
    const d = await diagnoseTapReachability("192.168.0.10", ADAPTER);
    expect(d.likelyReachable).toBe(false);
    expect(d.reason).toBe("different-subnet");
  });

  it("non-Windows → not assessed", async () => {
    Object.defineProperty(process, "platform", { value: "linux", configurable: true });
    const d = await diagnoseTapReachability("192.168.0.10", ADAPTER);
    expect(d).toEqual({ likelyReachable: true, reason: "non-windows", adapterIp: null });
  });
});
