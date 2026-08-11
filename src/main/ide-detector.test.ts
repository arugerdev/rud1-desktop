import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "fs";
import os from "os";
import path from "path";

import { detectFlashers, EXTRA_ROOTS_ENV } from "./ide-detector";

const exe = process.platform === "win32" ? "avrdude.exe" : "avrdude";

let tmp: string;
let envBackup: Record<string, string | undefined>;

function write(p: string): string {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, "binary");
  return p;
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rud1-ide-"));
  envBackup = { PATH: process.env["PATH"], [EXTRA_ROOTS_ENV]: process.env[EXTRA_ROOTS_ENV] };
  // Aísla de las rutas reales de la máquina que corre el test.
  process.env["PATH"] = "";
  delete process.env[EXTRA_ROOTS_ENV];
});

afterEach(() => {
  for (const [k, v] of Object.entries(envBackup)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  fs.rmSync(tmp, { recursive: true, force: true });
});

// Visuino trae su propia toolchain; antes solo se miraba Arduino15/PlatformIO y
// sus subidas nunca llegaban al shim.
describe("detectFlashers", () => {
  it("encuentra flashers en las raíces extra declaradas por entorno", () => {
    const target = write(path.join(tmp, "Visuino", "tools", "avr", "bin", exe));
    process.env[EXTRA_ROOTS_ENV] = path.join(tmp, "Visuino");

    const found = detectFlashers();
    expect(found.map((f) => f.path)).toContain(target);
    expect(found.find((f) => f.path === target)?.tool).toBe("avrdude");
  });

  it("acepta varias raíces extra separadas por el delimitador del sistema", () => {
    const a = write(path.join(tmp, "one", "bin", exe));
    const b = write(path.join(tmp, "two", "bin", exe));
    process.env[EXTRA_ROOTS_ENV] = [path.join(tmp, "one"), path.join(tmp, "two")].join(path.delimiter);

    const paths = detectFlashers().map((f) => f.path);
    expect(paths).toContain(a);
    expect(paths).toContain(b);
  });

  it("recoge instalaciones sueltas del PATH", () => {
    const target = write(path.join(tmp, "standalone", exe));
    process.env["PATH"] = path.join(tmp, "standalone");

    expect(detectFlashers().map((f) => f.path)).toContain(target);
  });

  // El PATH se recorre con depth 0: escanearlo recursivamente sería carísimo.
  it("no desciende por debajo de un directorio del PATH", () => {
    const nested = write(path.join(tmp, "standalone", "nested", exe));
    process.env["PATH"] = path.join(tmp, "standalone");

    expect(detectFlashers().map((f) => f.path)).not.toContain(nested);
  });

  it("ignora raíces inexistentes sin fallar", () => {
    process.env[EXTRA_ROOTS_ENV] = path.join(tmp, "no-existe");
    expect(() => detectFlashers()).not.toThrow();
  });
});
