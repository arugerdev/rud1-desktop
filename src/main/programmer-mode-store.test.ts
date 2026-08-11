import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

import {
  DEFAULT_PROGRAMMER_MODE,
  loadProgrammerModes,
  modeFor,
  modeKey,
  saveProgrammerModes,
  setMode,
} from "./programmer-mode-store";

let dir: string;
let file: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "rud1-progmode-"));
  file = path.join(dir, "usb-programmer-modes.json");
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe("modeFor / setMode", () => {
  it("cae a auto cuando no hay elección explícita", () => {
    expect(modeFor({}, "10.8.0.2", "1-1")).toBe(DEFAULT_PROGRAMMER_MODE);
    expect(DEFAULT_PROGRAMMER_MODE).toBe("auto");
  });

  it("distingue el mismo busId en equipos distintos", () => {
    const modes = setMode({}, "10.8.0.2", "1-1", "never");
    expect(modeFor(modes, "10.8.0.2", "1-1")).toBe("never");
    expect(modeFor(modes, "10.8.0.9", "1-1")).toBe("auto");
  });

  it("no muta el mapa recibido", () => {
    const before = {};
    const after = setMode(before, "h", "b", "always");
    expect(before).toEqual({});
    expect(after[modeKey("h", "b")]).toBe("always");
  });

  // Guardar el default como entrada haría que un cambio futuro del valor por
  // defecto no llegase a los equipos que nunca lo tocaron.
  it("volver a auto borra la entrada en lugar de guardarla", () => {
    const forced = setMode({}, "h", "b", "always");
    expect(Object.keys(forced)).toHaveLength(1);
    expect(setMode(forced, "h", "b", "auto")).toEqual({});
  });
});

describe("persistencia", () => {
  it("sobrevive a un ciclo de guardado y carga", async () => {
    const modes = setMode(setMode({}, "h1", "1-1", "never"), "h2", "2-1", "always");
    await saveProgrammerModes(file, modes);
    expect(await loadProgrammerModes(file)).toEqual(modes);
  });

  it("un fichero ausente o corrupto no bloquea la programación", async () => {
    expect(await loadProgrammerModes(path.join(dir, "nope.json"))).toEqual({});
    fs.writeFileSync(file, "{ no json");
    expect(await loadProgrammerModes(file)).toEqual({});
  });

  it("descarta modos desconocidos en vez de propagarlos", async () => {
    fs.writeFileSync(
      file,
      JSON.stringify({ version: 1, modes: { "h|b": "bogus", "h|c": "never" } }),
    );
    expect(await loadProgrammerModes(file)).toEqual({ "h|c": "never" });
  });

  it("crea el directorio si no existe", async () => {
    const nested = path.join(dir, "a", "b", "modes.json");
    await saveProgrammerModes(nested, { "h|b": "always" });
    expect(await loadProgrammerModes(nested)).toEqual({ "h|b": "always" });
  });
});
