/**
 * Tests del marcador de actualización. Se usa un directorio temporal real
 * (como en first-boot-dedupe): el tmp+rename y el ENOENT son justo lo que
 * queremos comprobar.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import {
  UPDATE_MARKER_FILENAME,
  __test,
  classifyUpdateOutcome,
  clearUpdateMarker,
  readUpdateMarker,
  writeUpdateMarker,
} from "./update-marker";

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "rud1-marker-"));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("writeUpdateMarker / readUpdateMarker", () => {
  it("ida y vuelta", () => {
    const marker = { fromVersion: "0.3.2", toVersion: "0.3.3", startedAt: 1234567 };
    const p = writeUpdateMarker(dir, marker);
    expect(p).toBe(path.join(dir, UPDATE_MARKER_FILENAME));
    expect(readUpdateMarker(dir)).toEqual(marker);
  });

  it("crea la carpeta si no está", () => {
    const nested = path.join(dir, "a", "b");
    expect(writeUpdateMarker(nested, { fromVersion: "1", toVersion: "2", startedAt: 1 })).not.toBeNull();
    expect(readUpdateMarker(nested)?.toVersion).toBe("2");
  });

  it("sin fichero devuelve null en vez de reventar", () => {
    expect(readUpdateMarker(dir)).toBeNull();
  });

  it("un marcador corrupto o incompleto se ignora", () => {
    const p = path.join(dir, UPDATE_MARKER_FILENAME);
    fs.writeFileSync(p, "{no es json");
    expect(readUpdateMarker(dir)).toBeNull();
    fs.writeFileSync(p, JSON.stringify({ fromVersion: "0.3.2" }));
    expect(readUpdateMarker(dir)).toBeNull();
    fs.writeFileSync(p, JSON.stringify({ fromVersion: "a", toVersion: "b", startedAt: "ayer" }));
    expect(readUpdateMarker(dir)).toBeNull();
    fs.writeFileSync(p, JSON.stringify({ fromVersion: "a", toVersion: "b".repeat(200), startedAt: 1 }));
    expect(readUpdateMarker(dir)).toBeNull();
    fs.writeFileSync(p, "null");
    expect(readUpdateMarker(dir)).toBeNull();
  });

  it("borrarlo es idempotente (es la señal que cierra la ventana de progreso)", () => {
    writeUpdateMarker(dir, { fromVersion: "1", toVersion: "2", startedAt: 1 });
    clearUpdateMarker(dir);
    expect(readUpdateMarker(dir)).toBeNull();
    expect(() => clearUpdateMarker(dir)).not.toThrow();
  });

  it("no deja el .tmp por medio", () => {
    writeUpdateMarker(dir, { fromVersion: "1", toVersion: "2", startedAt: 1 });
    expect(fs.readdirSync(dir)).toEqual([UPDATE_MARKER_FILENAME]);
  });
});

describe("classifyUpdateOutcome", () => {
  const now = 1_000_000_000;

  it("la versión que corre es la que se instalaba → instalada", () => {
    expect(
      classifyUpdateOutcome({ fromVersion: "0.3.2", toVersion: "0.3.3", startedAt: now }, "0.3.3", now),
    ).toEqual({ kind: "installed", version: "0.3.3" });
  });

  it("seguimos en la de antes → se quedó a medias", () => {
    expect(
      classifyUpdateOutcome({ fromVersion: "0.3.2", toVersion: "0.3.3", startedAt: now }, "0.3.2", now),
    ).toEqual({ kind: "not-completed", version: "0.3.3" });
  });

  it("sin marcador no hay nada que contar", () => {
    expect(classifyUpdateOutcome(null, "0.3.3", now)).toEqual({ kind: "none" });
  });

  it("un marcador viejo se descarta", () => {
    const old = now - __test.MARKER_MAX_AGE_MS - 1;
    expect(
      classifyUpdateOutcome({ fromVersion: "0.3.2", toVersion: "0.3.3", startedAt: old }, "0.3.2", now),
    ).toEqual({ kind: "none" });
  });

  it("si no se sabía a qué versión se iba, no se anuncia nada", () => {
    expect(
      classifyUpdateOutcome({ fromVersion: "0.3.2", toVersion: "0.3.2", startedAt: now }, "0.3.2", now),
    ).toEqual({ kind: "none" });
  });

  it("una tercera versión (alguien instaló a mano) tampoco se comenta", () => {
    expect(
      classifyUpdateOutcome({ fromVersion: "0.3.2", toVersion: "0.3.3", startedAt: now }, "0.4.0", now),
    ).toEqual({ kind: "none" });
  });
});
