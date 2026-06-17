/**
 * Tests for classifyUseResult — el mapeo de la respuesta del comando USE de
 * VirtualHere a mensajes accionables, y el flag `retryable` que decide si se
 * hace un reintento ante contención transitoria.
 *
 * Lo crítico: license / in-use NUNCA deben ser reintentables (un reintento
 * consumiría el slot o duplicaría el intento sin remedio); "Operation not
 * permitted" / FAILED genérico SÍ (ModemManager soltando el puerto serie).
 */

import { describe, expect, it, vi } from "vitest";

// binary-helper importa electron al cargar; stub no-op para que vitest pueda
// cargar el módulo sin runtime de Electron (mismo patrón que usb-manager.test).
vi.mock("electron", () => ({
  app: {
    isPackaged: false,
    getAppPath: () => process.cwd(),
  },
}));

import { __test } from "./virtualhere-manager";

const { classifyUseResult, WIN_CLIENT_SERVICE, WIN_CLIENT_SERVICE_DISPLAY } = __test;

describe("classifyUseResult", () => {
  it("OK y respuesta vacía → ok", () => {
    expect(classifyUseResult("OK")).toEqual({ ok: true });
    expect(classifyUseResult("OK,1")).toEqual({ ok: true });
    expect(classifyUseResult("")).toEqual({ ok: true });
  });

  it("límite de licencia free → no reintentable", () => {
    const r = classifyUseResult("FAILED: license limit reached");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.retryable).toBe(false);
      expect(r.error).toMatch(/free license/i);
    }
  });

  it("max devices → no reintentable", () => {
    const r = classifyUseResult("FAILED max devices in use");
    expect(r).toMatchObject({ ok: false, retryable: false });
  });

  it("device in use por otro cliente → no reintentable", () => {
    const r = classifyUseResult("FAILED device in use");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.retryable).toBe(false);
      expect(r.error).toMatch(/in use/i);
    }
  });

  it('"Operation not permitted" → reintentable con mensaje accionable', () => {
    const r = classifyUseResult('ERROR: Operation not permitted (-1)');
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.retryable).toBe(true);
      expect(r.error).toMatch(/could not claim/i);
    }
  });

  it("FAILED genérico → reintentable (causa típica = puerto ocupado)", () => {
    const r = classifyUseResult("FAILED");
    expect(r).toMatchObject({ ok: false, retryable: true });
  });

  it("respuesta desconocida → optimista (ok), igual que el comportamiento previo", () => {
    expect(classifyUseResult("Using device")).toEqual({ ok: true });
  });
});

describe("nombre del servicio cliente de VirtualHere", () => {
  it("usa la clave SCM 'vhclient' (la que entienden sc query/stop/delete)", () => {
    // sc.exe opera sobre el key name, NO el display name. vhui64.exe -i
    // registra el servicio bajo "vhclient" (display: "VirtualHere Client USB Sharing").
    expect(WIN_CLIENT_SERVICE).toBe("vhclient");
    expect(WIN_CLIENT_SERVICE_DISPLAY).toBe("VirtualHere Client USB Sharing");
  });
});
