import { describe, expect, it, vi } from "vitest";

// flash-integration pulls in the shim lifecycle manager → binary-helper, which
// reads `app.isPackaged` at module load. electron is a native module absent in
// a plain Node vitest run, so stub the one field the import chain touches.
vi.mock("electron", () => ({ app: { isPackaged: true } }));

import { buildSerialFlashMenuItems, projectSessions } from "./flash-integration";
import type { ShimOrchestratorStatus } from "./shim-orchestrator";

/**
 * The flasher shim's COM→device map is a pure projection of the live USB
 * session set (single source of truth). These tests lock that contract so the
 * map can never drift from what is actually attached.
 */
describe("projectSessions", () => {
  it("maps only sessions with a captured COM, carrying host+busId", () => {
    const m = projectSessions([
      { com: "COM3", host: "10.8.0.2", busId: "2-1.4" },
      { host: "10.8.0.3", busId: "2-1.5" }, // no COM yet → not routable
    ]);
    expect([...m]).toEqual([
      ["COM3", { host: "10.8.0.2", busId: "2-1.4", mode: "auto" }],
    ]);
  });

  it("is a full rebuild: a detached device drops out of the map", () => {
    const both = projectSessions([
      { com: "COM3", host: "10.8.0.2", busId: "2-1.4" },
      { com: "COM7", host: "10.8.0.2", busId: "2-1.5" },
    ]);
    expect(both.size).toBe(2);
    // COM7 detached → only the still-attached device survives.
    const one = projectSessions([{ com: "COM3", host: "10.8.0.2", busId: "2-1.4" }]);
    expect([...one.keys()]).toEqual(["COM3"]);
    // All detached → empty map makes every wrapped flasher a passthrough.
    expect(projectSessions([]).size).toBe(0);
  });

  it("reflects a busId remap on the same COM (device swapped ports)", () => {
    const m = projectSessions([{ com: "COM3", host: "10.8.0.2", busId: "1-1.2" }]);
    expect(m.get("COM3")).toEqual({ host: "10.8.0.2", busId: "1-1.2", mode: "auto" });
  });
});

// La elección del operador se aplica en la proyección, que es el único sitio
// del que leen tanto la config del shim como resolvePort.
describe("projectSessions con modo de programador", () => {
  const session = { com: "COM7", host: "10.8.0.2", busId: "1-1" };

  it("never deja el puerto fuera del mapa: el shim pasa al flasher original", () => {
    const m = projectSessions([session], { "10.8.0.2|1-1": "never" });
    expect(m.size).toBe(0);
  });

  it("always enruta y marca el modo para que un fallo no caiga al flasher local", () => {
    const m = projectSessions([session], { "10.8.0.2|1-1": "always" });
    expect(m.get("COM7")).toEqual({ host: "10.8.0.2", busId: "1-1", mode: "always" });
  });

  it("auto (y sin elección) mantiene el comportamiento de siempre", () => {
    expect(projectSessions([session], { "10.8.0.2|1-1": "auto" }).get("COM7")?.mode).toBe("auto");
    expect(projectSessions([session], {}).get("COM7")?.mode).toBe("auto");
  });

  // Un bus id sólo es único dentro de un equipo: la clave lleva el host para
  // que apagarlo en uno no lo apague en otro.
  it("no aplica la elección de un equipo a otro con el mismo busId", () => {
    const modes = { "10.8.0.2|1-1": "never" as const };
    const m = projectSessions(
      [session, { com: "COM8", host: "10.8.0.9", busId: "1-1" }],
      modes,
    );
    expect([...m.keys()]).toEqual(["COM8"]);
  });

  it("never gana aunque la sesión tenga COM capturado", () => {
    const m = projectSessions(
      [session, { com: "COM3", host: "10.8.0.2", busId: "2-1" }],
      { "10.8.0.2|1-1": "never" },
    );
    expect([...m.keys()]).toEqual(["COM3"]);
  });
});

/**
 * Lo que se le cuenta al operador. Solo se avisa de lo actionable: si la
 * programación serie funciona (aunque sea en otro puerto) no se dice nada,
 * porque no hay nada que hacer.
 */
describe("buildSerialFlashMenuItems", () => {
  const down = (over: Partial<Extract<ShimOrchestratorStatus, { kind: "unavailable" }>> = {}) =>
    ({
      kind: "unavailable" as const,
      preferredPort: 25341,
      code: "EADDRINUSE",
      message: "listen EADDRINUSE: address already in use 127.0.0.1:25341",
      heldBy: null,
      ...over,
    });

  it("callado mientras la programación serie funcione", () => {
    expect(buildSerialFlashMenuItems({ kind: "listening", port: 25341, preferredPort: 25341 })).toEqual([]);
    // También en otro puerto: funciona, así que no hay nada que avisar.
    expect(buildSerialFlashMenuItems({ kind: "listening", port: 51234, preferredPort: 25341 })).toEqual([]);
    expect(buildSerialFlashMenuItems({ kind: "stopped" })).toEqual([]);
  });

  it("avisa sin poder pulsarse (no bloquea nada) y nombra el puerto", () => {
    const items = buildSerialFlashMenuItems(down());
    expect(items).toHaveLength(2);
    expect(items.every((i) => i.enabled === false)).toBe(true);
    expect(items[0].label).toContain("Serial programming unavailable");
    expect(items[1].label).toContain("25341");
  });

  it("dice quién tiene el puerto cuando se ha podido averiguar", () => {
    const items = buildSerialFlashMenuItems(down({ heldBy: "eCatcher" }));
    expect(items[1].label).toContain("eCatcher");
    expect(items[1].label).toContain("25341");
  });

  it("con otro tipo de fallo enseña el motivo del sistema, recortado", () => {
    const items = buildSerialFlashMenuItems(
      down({ code: "EACCES", message: "permission denied ".repeat(20) }),
    );
    expect(items[1].label).toContain("permission denied");
    expect(items[1].label.length).toBeLessThan(160);
  });
});
