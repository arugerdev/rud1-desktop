/**
 * Tests de setServer / manual hub — el camino que apunta el cliente
 * VirtualHere directo a la IP del Pi en vez de depender del descubrimiento
 * por broadcast/mDNS (que no cruza fiable el bridge L2 de la VPN).
 *
 * Cubre: validación host/puerto (incluido el rechazo de ':' que evitaría
 * un doble puerto, y de \r \n , que romperían el pipe), construcción del
 * comando, idempotencia (remove-then-add solo si cambia), `force`, y que
 * un banner del server se trate como ok.
 */

import { beforeEach, describe, expect, it } from "vitest";

// binary-helper importa electron al cargar; stub no-op (mismo patrón que
// virtualhere-manager.error-mapping.test.ts).
import { vi } from "vitest";
vi.mock("electron", () => ({
  app: {
    isPackaged: false,
    getAppPath: () => process.cwd(),
  },
}));

import { setServer, __test } from "./virtualhere-manager";

describe("setServer / manual hub", () => {
  let sent: string[];

  beforeEach(() => {
    sent = [];
    __test.resetHubState();
    // Pipe falso: captura el comando crudo, nunca spawnea powershell.
    __test.setPipeSender(async (cmd: string) => {
      sent.push(cmd);
      return "OK";
    });
  });

  it("acepta IPv4 válida y usa el puerto 7575 por defecto", async () => {
    const r = await setServer("192.168.0.200");
    expect(r).toEqual({ ok: true });
    expect(sent).toEqual(["MANUAL HUB ADD,192.168.0.200:7575"]);
  });

  it("acepta un puerto explícito válido", async () => {
    const r = await setServer("rud1-pi", { port: 7576 });
    expect(r).toEqual({ ok: true });
    expect(sent).toEqual(["MANUAL HUB ADD,rud1-pi:7576"]);
  });

  it("rechaza host vacío / con guion inicial / con ':' / IPv6 / demasiado largo — nunca toca el pipe", async () => {
    for (const h of ["", "-rf", "1.2.3.4:7575", "fd00::1", "a".repeat(300)]) {
      const r = await setServer(h);
      expect(r.ok).toBe(false);
    }
    expect(sent).toEqual([]);
  });

  it("rechaza host con \\r \\n o ',' — nunca toca el pipe", async () => {
    for (const h of ["1.2.3.4\n", "1.2.3.4\r", "1.2.3.4\r\n", "1.2.3.4,USE"]) {
      const r = await setServer(h);
      expect(r.ok).toBe(false);
    }
    expect(sent).toEqual([]);
  });

  it("rechaza puertos fuera de rango / no enteros / string — nunca toca el pipe", async () => {
    for (const p of [0, 70000, 1.5, Number.NaN]) {
      const r = await setServer("192.168.0.200", { port: p });
      expect(r.ok).toBe(false);
    }
    const r2 = await setServer("192.168.0.200", {
      port: "7575" as unknown as number,
    });
    expect(r2.ok).toBe(false);
    expect(sent).toEqual([]);
  });

  it("misma IP dos veces → el segundo es no-op (sin REMOVE ni ADD duplicado)", async () => {
    await setServer("192.168.0.200");
    await setServer("192.168.0.200");
    expect(sent).toEqual(["MANUAL HUB ADD,192.168.0.200:7575"]);
  });

  it("IP distinta → REMOVE del anterior y ADD del nuevo", async () => {
    await setServer("192.168.0.200");
    await setServer("192.168.0.201");
    expect(sent).toEqual([
      "MANUAL HUB ADD,192.168.0.200:7575",
      "MANUAL HUB REMOVE,192.168.0.200:7575",
      "MANUAL HUB ADD,192.168.0.201:7575",
    ]);
  });

  it("force re-dispara REMOVE+ADD aunque la IP no cambie", async () => {
    await setServer("192.168.0.200");
    await setServer("192.168.0.200", { force: true });
    expect(sent).toEqual([
      "MANUAL HUB ADD,192.168.0.200:7575",
      "MANUAL HUB REMOVE,192.168.0.200:7575",
      "MANUAL HUB ADD,192.168.0.200:7575",
    ]);
  });

  it("un banner no-OK del server se trata como éxito (respuesta no parseada)", async () => {
    __test.setPipeSender(async () => "VirtualHere Client IPC, hub added");
    const r = await setServer("10.0.0.5");
    expect(r).toEqual({ ok: true });
  });

  it("un fallo del pipe se reporta como error", async () => {
    __test.setPipeSender(async () => {
      throw new Error("pipe down");
    });
    const r = await setServer("10.0.0.5");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/pipe down/);
  });

  it("validadores expuestos: host y puerto", () => {
    expect(__test.isValidServerHost("192.168.0.200")).toBe(true);
    expect(__test.isValidServerHost("1.2.3.4:7575")).toBe(false);
    expect(__test.isValidServerHost("-x")).toBe(false);
    expect(__test.isValidServerPort(7575)).toBe(true);
    expect(__test.isValidServerPort(0)).toBe(false);
    expect(__test.isValidServerPort(65535)).toBe(true);
  });
});
