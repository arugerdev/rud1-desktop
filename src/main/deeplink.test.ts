import { describe, it, expect } from "vitest";
import { resolveDeepLinkTarget } from "./deeplink";

const APP = "https://www.rud1.es/dashboard";

describe("resolveDeepLinkTarget", () => {
  it("connect con device por query → página del dispositivo con autoconnect", () => {
    expect(resolveDeepLinkTarget("rud1://connect?device=abc123", APP)).toBe(
      "https://www.rud1.es/dashboard/devices/abc123/connect?autoconnect=1",
    );
  });

  it("connect con device por path → misma resolución", () => {
    expect(resolveDeepLinkTarget("rud1://connect/abc123", APP)).toBe(
      "https://www.rud1.es/dashboard/devices/abc123/connect?autoconnect=1",
    );
  });

  it("usa el origin del appUrl, no el path completo", () => {
    expect(
      resolveDeepLinkTarget("rud1://connect?device=x", "http://192.168.1.5:3000/dashboard"),
    ).toBe("http://192.168.1.5:3000/dashboard/devices/x/connect?autoconnect=1");
  });

  it("connect sin device → fallback deeplink crudo", () => {
    expect(resolveDeepLinkTarget("rud1://connect", APP)).toBe(
      `${APP}?deeplink=${encodeURIComponent("rud1://connect")}`,
    );
  });

  it("acción desconocida → fallback deeplink crudo", () => {
    const dl = "rud1://pair?token=t";
    expect(resolveDeepLinkTarget(dl, APP)).toBe(
      `${APP}?deeplink=${encodeURIComponent(dl)}`,
    );
  });

  it("url inválida → fallback", () => {
    expect(resolveDeepLinkTarget("no-es-una-url", APP)).toBe(
      `${APP}?deeplink=${encodeURIComponent("no-es-una-url")}`,
    );
  });

  it("protocolo ajeno → fallback", () => {
    const dl = "https://evil.example/connect?device=x";
    expect(resolveDeepLinkTarget(dl, APP)).toBe(
      `${APP}?deeplink=${encodeURIComponent(dl)}`,
    );
  });
});
