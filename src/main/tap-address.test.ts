import { describe, it, expect } from "vitest";

import {
  OPENVPN_TAP_WAIT_MS,
  TAP_RESCUE_GRACE_MS,
  buildSetDhcpArgs,
  buildSetStaticArgs,
  initDeadlineWithTapWait,
  isWaitingForTapLine,
  parseDhcpEnabled,
  pickLinkLocalIpv4,
  shouldRescueTapAddress,
} from "./tap-address";

describe("tap-address: detección de la espera de openvpn", () => {
  it("reconoce la línea de openvpn 2.6 con marca de tiempo", () => {
    expect(
      isWaitingForTapLine(
        "2026-10-24 21:33:14 us=171000 Route: Waiting for TUN/TAP interface to come up...",
      ),
    ).toBe(true);
  });

  it("no confunde otras líneas de rutas", () => {
    expect(isWaitingForTapLine("TEST ROUTES: 0/0 succeeded len=-1 ret=0 a=0 u/d=down")).toBe(false);
    expect(isWaitingForTapLine("Initialization Sequence Completed")).toBe(false);
  });
});

describe("tap-address: cuándo rescatar", () => {
  it("no rescata si openvpn aún no ha empezado a esperar", () => {
    expect(shouldRescueTapAddress(null, 1_000_000)).toBe(false);
  });

  it("no rescata antes de agotar el margen (el DHCP aún puede llegar)", () => {
    expect(shouldRescueTapAddress(10_000, 10_000 + TAP_RESCUE_GRACE_MS - 1)).toBe(false);
  });

  it("rescata en cuanto se agota el margen", () => {
    expect(shouldRescueTapAddress(10_000, 10_000 + TAP_RESCUE_GRACE_MS)).toBe(true);
  });

  it("el margen cabe de sobra en la espera de openvpn", () => {
    // openvpn espera 5 s antes de la primera comprobación y 30 s después.
    expect(5_000 + TAP_RESCUE_GRACE_MS).toBeLessThan(35_000);
    expect(TAP_RESCUE_GRACE_MS).toBeLessThan(OPENVPN_TAP_WAIT_MS);
  });

  it("no rescata si el relay empujó una IP (LAN STATIC)", () => {
    // openvpn espera esa IP exacta; fijar una 169.254 apagaría el DHCP del
    // driver que se la tiene que dar.
    expect(shouldRescueTapAddress(10_000, 10_000 + TAP_RESCUE_GRACE_MS, "192.168.1.240")).toBe(false);
  });

  it("sin IP empujada sí rescata", () => {
    expect(shouldRescueTapAddress(10_000, 10_000 + TAP_RESCUE_GRACE_MS, null)).toBe(true);
  });
});

describe("tap-address: plazo de arranque", () => {
  it("si openvpn no espera al adaptador, el plazo no cambia", () => {
    expect(initDeadlineWithTapWait(25_000, null)).toBe(25_000);
  });

  it("si espera, deja acabar su propia espera con margen", () => {
    const waitingSince = 8_000;
    const deadline = initDeadlineWithTapWait(25_000, waitingSince);
    expect(deadline).toBeGreaterThan(waitingSince + OPENVPN_TAP_WAIT_MS);
    expect(deadline).toBeLessThanOrEqual(waitingSince + OPENVPN_TAP_WAIT_MS + 10_000);
  });

  it("nunca acorta un plazo que ya era mayor", () => {
    expect(initDeadlineWithTapWait(100_000, 1_000)).toBe(100_000);
  });
});

describe("tap-address: dirección elegida", () => {
  it("con el azar al mínimo da 169.254.1.1", () => {
    expect(pickLinkLocalIpv4(() => 0)).toBe("169.254.1.1");
  });

  it("con el azar al máximo da 169.254.254.254", () => {
    expect(pickLinkLocalIpv4(() => 0.999999)).toBe("169.254.254.254");
  });

  it("nunca cae en los bloques del puerto de gestión ni en .0/.255", () => {
    for (let i = 0; i < 2_000; i++) {
      const ip = pickLinkLocalIpv4();
      const [a, b, c, d] = ip.split(".").map(Number);
      expect([a, b]).toEqual([169, 254]);
      expect(c).toBeGreaterThanOrEqual(1);
      expect(c).toBeLessThanOrEqual(254);
      expect(d).toBeGreaterThanOrEqual(1);
      expect(d).toBeLessThanOrEqual(254);
    }
  });
});

describe("tap-address: órdenes netsh", () => {
  it("fija la dirección con máscara /16 (on-link con el puerto de gestión)", () => {
    expect(buildSetStaticArgs("rud1-tap", "169.254.10.20")).toEqual([
      "interface", "ipv4", "set", "address", "name=rud1-tap", "static", "169.254.10.20", "255.255.0.0",
    ]);
  });

  it("vuelve a DHCP", () => {
    expect(buildSetDhcpArgs("rud1-tap")).toEqual([
      "interface", "ipv4", "set", "address", "name=rud1-tap", "dhcp",
    ]);
  });
});

describe("tap-address: lectura de DHCP en netsh", () => {
  it("Windows en español con DHCP activo (salida real del PC de un técnico)", () => {
    const out = [
      'Configuración para la interfaz "rud1-tap"',
      "    DHCP habilitado:                         Sí",
      "    Métrica de interfaz:                      35",
    ].join("\r\n");
    expect(parseDhcpEnabled(out)).toBe(true);
  });

  it("Windows en español con IP fija", () => {
    expect(parseDhcpEnabled("    DHCP habilitado:                         No\r\n")).toBe(false);
  });

  it("la í mal descodificada no cambia la lectura", () => {
    expect(parseDhcpEnabled("    DHCP habilitado:                         S�\r\n")).toBe(true);
  });

  it("sin línea de DHCP no se da por activo", () => {
    expect(parseDhcpEnabled('Configuración para la interfaz "rud1-tap"\r\n')).toBe(false);
  });

  it("Windows en inglés", () => {
    expect(parseDhcpEnabled("    DHCP enabled:                         Yes\r\n")).toBe(true);
    expect(parseDhcpEnabled("    DHCP enabled:                         No\r\n")).toBe(false);
  });
});
