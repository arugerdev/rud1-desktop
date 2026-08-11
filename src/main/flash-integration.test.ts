import { describe, expect, it, vi } from "vitest";

// flash-integration pulls in the shim lifecycle manager → binary-helper, which
// reads `app.isPackaged` at module load. electron is a native module absent in
// a plain Node vitest run, so stub the one field the import chain touches.
vi.mock("electron", () => ({ app: { isPackaged: true } }));

import { projectSessions } from "./flash-integration";

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
