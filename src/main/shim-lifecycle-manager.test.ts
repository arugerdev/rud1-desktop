import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

// detectFlashers y binary-helper se mockean para controlar el flasher objetivo
// y forzar que el shim esté "disponible" sin binario bundleado real.
const detectMock = vi.fn();
vi.mock("./ide-detector", () => ({ detectFlashers: () => detectMock() }));
vi.mock("./binary-helper", () => ({
  isRud1shimAvailable: () => true,
  rud1shimPath: () => "",
}));

import { ShimManager } from "./shim-lifecycle-manager";

// El shim se reconoce por contenido: cualquier fichero con este marcador cuenta
// como "nuestro shim". El real es cualquier otro contenido.
const SHIM_BYTES = Buffer.from("stub rud1shim passthrough error stub");
const REAL_BYTES = Buffer.from("REAL-AVRDUDE-BINARY-8.0.0");

let dir: string;
let toolPath: string;
let shimPath: string;
let statePath: string;

function realSibling(p: string): string {
  const ext = path.extname(p);
  return `${p.slice(0, p.length - ext.length)}-real${ext}`;
}
const read = (p: string) => fs.readFileSync(p);
const isShim = (p: string) => read(p).includes(SHIM_BYTES);
const exists = (p: string) => fs.existsSync(p);

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "shimtest-"));
  toolPath = path.join(dir, "avrdude.exe");
  shimPath = path.join(dir, "rud1shim.exe");
  statePath = path.join(dir, "state.json");
  fs.writeFileSync(shimPath, SHIM_BYTES);
  detectMock.mockReturnValue([{ tool: "avrdude", path: toolPath, source: "test" }]);
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

function mgr() {
  return new ShimManager({ statePath, endpoint: "http://127.0.0.1:9/flash", shimPath });
}

describe("ShimManager wrap/repair", () => {
  it("envuelve limpio: real→-real, shim en el tool", () => {
    fs.writeFileSync(toolPath, REAL_BYTES);
    mgr().syncPorts({});
    expect(isShim(toolPath)).toBe(true);
    expect(read(realSibling(toolPath)).equals(REAL_BYTES)).toBe(true);
  });

  it("es idempotente: dos syncs no encadenan -real-real", () => {
    fs.writeFileSync(toolPath, REAL_BYTES);
    mgr().syncPorts({});
    mgr().syncPorts({});
    expect(isShim(toolPath)).toBe(true);
    expect(read(realSibling(toolPath)).equals(REAL_BYTES)).toBe(true);
    expect(exists(realSibling(realSibling(toolPath)))).toBe(false);
  });

  it("repara una cadena apilada shim→shim→shim→REAL", () => {
    // Estado roto: el real quedó al fondo de "-real-real-real".
    fs.writeFileSync(toolPath, SHIM_BYTES);
    fs.writeFileSync(realSibling(toolPath), SHIM_BYTES);
    fs.writeFileSync(realSibling(realSibling(toolPath)), SHIM_BYTES);
    fs.writeFileSync(realSibling(realSibling(realSibling(toolPath))), REAL_BYTES);

    mgr().syncPorts({});

    expect(isShim(toolPath)).toBe(true);
    expect(read(realSibling(toolPath)).equals(REAL_BYTES)).toBe(true);
    expect(exists(realSibling(realSibling(toolPath)))).toBe(false);
    expect(exists(realSibling(realSibling(realSibling(toolPath))))).toBe(false);
  });

  it("si el real se perdió (solo shims), no toca ni registra el wrap", () => {
    fs.writeFileSync(toolPath, SHIM_BYTES);
    fs.writeFileSync(realSibling(toolPath), SHIM_BYTES);
    const m = mgr();
    m.syncPorts({});
    // No hay real recuperable → tool permanece como está, sin crear más copias.
    expect(exists(realSibling(realSibling(toolPath)))).toBe(false);
  });

  it("restoreAll deja el real en su sitio y borra shim + copias -real", () => {
    fs.writeFileSync(toolPath, REAL_BYTES);
    const m = mgr();
    m.syncPorts({});
    m.restoreAll();
    expect(read(toolPath).equals(REAL_BYTES)).toBe(true);
    expect(exists(realSibling(toolPath))).toBe(false);
  });
});
