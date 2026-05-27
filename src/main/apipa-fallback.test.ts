import { describe, it, expect } from "vitest";

import {
  isApipa,
  parseLanFallbackHint,
} from "./apipa-fallback";

describe("apipa-fallback parser", () => {
  it("returns null when no hint comments present", () => {
    const ovpn = "client\ndev tap-rud1\nremote vps.rud1.es 51820 udp\n";
    expect(parseLanFallbackHint(ovpn)).toBeNull();
  });

  it("parses subnet + gateway + fallback-ip", () => {
    const ovpn = [
      "# rud1-lan-subnet: 192.168.0.0/24",
      "# rud1-lan-gateway: 192.168.0.1",
      "# rud1-lan-fallback-ip: 192.168.0.250",
      "client",
      "dev tap-rud1",
    ].join("\n");
    expect(parseLanFallbackHint(ovpn)).toEqual({
      subnet: "192.168.0.0/24",
      gateway: "192.168.0.1",
      fallbackIp: "192.168.0.250",
    });
  });

  it("makes gateway optional", () => {
    const ovpn = [
      "# rud1-lan-subnet: 10.1.2.0/24",
      "# rud1-lan-fallback-ip: 10.1.2.250",
      "client",
    ].join("\n");
    expect(parseLanFallbackHint(ovpn)).toEqual({
      subnet: "10.1.2.0/24",
      gateway: null,
      fallbackIp: "10.1.2.250",
    });
  });

  it("returns null when subnet OR fallback-ip is missing", () => {
    const onlySubnet = "# rud1-lan-subnet: 192.168.0.0/24";
    const onlyFallback = "# rud1-lan-fallback-ip: 192.168.0.250";
    expect(parseLanFallbackHint(onlySubnet)).toBeNull();
    expect(parseLanFallbackHint(onlyFallback)).toBeNull();
  });

  it("tolerates extra whitespace + CRLF line endings", () => {
    const ovpn = "#  rud1-lan-subnet:   192.168.0.0/24  \r\n" +
      "#   rud1-lan-fallback-ip:   192.168.0.250\r\n";
    expect(parseLanFallbackHint(ovpn)).toEqual({
      subnet: "192.168.0.0/24",
      gateway: null,
      fallbackIp: "192.168.0.250",
    });
  });
});

describe("isApipa", () => {
  it("matches 169.254.0.0/16", () => {
    expect(isApipa("169.254.0.1")).toBe(true);
    expect(isApipa("169.254.152.241")).toBe(true);
    expect(isApipa("169.254.255.255")).toBe(true);
  });
  it("rejects everything else", () => {
    expect(isApipa("192.168.0.250")).toBe(false);
    expect(isApipa("10.0.0.1")).toBe(false);
    expect(isApipa("169.253.0.1")).toBe(false);
    expect(isApipa("169.255.0.1")).toBe(false);
    expect(isApipa(null)).toBe(false);
    expect(isApipa("")).toBe(false);
  });
});
