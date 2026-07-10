import { describe, it, expect } from "vitest";

import {
  parseIpv4,
  isIpv4Literal,
  sameSlash24,
  candidateClientIps,
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
