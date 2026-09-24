import { describe, expect, it } from "vitest";

import {
  buildAddRouteArgs,
  buildDeleteRouteArgs,
  isAlreadyExistsError,
  isLinkLocalIpv4,
  needsOnLinkRoute,
  routeBinary,
} from "./mgmt-route";

describe("needsOnLinkRoute", () => {
  it("pins a route only for a link-local host seen from a routable adapter", () => {
    expect(needsOnLinkRoute("169.254.0.77", "192.168.0.77")).toBe(true);
    expect(needsOnLinkRoute("169.254.0.77", "192.168.2.128")).toBe(true);
  });
  it("does nothing when the adapter is already on APIPA (on-link by itself)", () => {
    expect(needsOnLinkRoute("169.254.0.77", "169.254.238.104")).toBe(false);
  });
  it("does nothing for routable hosts, hostnames or adapters without IPv4", () => {
    expect(needsOnLinkRoute("192.168.0.10", "192.168.0.77")).toBe(false);
    expect(needsOnLinkRoute("rud1.local", "192.168.0.77")).toBe(false);
    expect(needsOnLinkRoute("169.254.0.77", null)).toBe(false);
  });
});

describe("route commands", () => {
  it("windows: netsh on-link /32 on the adapter, active store only", () => {
    expect(routeBinary("win32")).toBe("netsh");
    expect(buildAddRouteArgs("rud1-tap", "169.254.0.77", "win32")).toEqual([
      "interface", "ipv4", "add", "route", "169.254.0.77/32", "interface=rud1-tap", "store=active",
    ]);
    expect(buildDeleteRouteArgs("rud1-tap", "169.254.0.77", "win32")).toEqual([
      "interface", "ipv4", "delete", "route", "169.254.0.77/32", "interface=rud1-tap",
    ]);
  });
  it("linux: ip route replace/del dev", () => {
    expect(routeBinary("linux")).toBe("ip");
    expect(buildAddRouteArgs("tap-rud1", "169.254.0.77", "linux")).toEqual([
      "route", "replace", "169.254.0.77/32", "dev", "tap-rud1",
    ]);
    expect(buildDeleteRouteArgs("tap-rud1", "169.254.0.77", "linux")).toEqual([
      "route", "del", "169.254.0.77/32", "dev", "tap-rud1",
    ]);
  });
  it("darwin: route -host -interface", () => {
    expect(routeBinary("darwin")).toBe("route");
    expect(buildAddRouteArgs("tap0", "169.254.0.77", "darwin")).toEqual([
      "-n", "add", "-host", "169.254.0.77", "-interface", "tap0",
    ]);
  });
});

describe("isAlreadyExistsError", () => {
  it("recognises the localized 'already exists' outcomes as success", () => {
    expect(isAlreadyExistsError("The object already exists.")).toBe(true);
    expect(isAlreadyExistsError("El objeto ya existe.")).toBe(true);
    expect(isAlreadyExistsError("RTNETLINK answers: File exists")).toBe(true);
  });
  it("does not swallow real failures", () => {
    expect(isAlreadyExistsError("The requested operation requires elevation.")).toBe(false);
    expect(isAlreadyExistsError("Element not found.")).toBe(false);
  });
});

describe("isLinkLocalIpv4", () => {
  it("matches only 169.254/16", () => {
    expect(isLinkLocalIpv4("169.254.0.1")).toBe(true);
    expect(isLinkLocalIpv4("169.253.0.1")).toBe(false);
    expect(isLinkLocalIpv4("192.168.0.10")).toBe(false);
  });
});
