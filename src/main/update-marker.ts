// Marca en disco de "hay una actualización instalándose".
//
// Sirve para dos cosas: la ventana de progreso la vigila para saber cuándo
// cerrarse, y el rud1 que arranca después sabe si la instalación acabó bien.
import * as fs from "fs";
import * as path from "path";

export const UPDATE_MARKER_FILENAME = "update-in-progress.json";

/** Pasado este tiempo la marca se considera basura de un intento antiguo. */
const MARKER_MAX_AGE_MS = 24 * 60 * 60 * 1000;

export interface UpdateMarker {
  fromVersion: string;
  toVersion: string;
  startedAt: number;
}

export type UpdateOutcome =
  | { kind: "installed"; version: string }
  | { kind: "not-completed"; version: string }
  | { kind: "none" };

function markerPath(userDataDir: string): string {
  return path.join(userDataDir, UPDATE_MARKER_FILENAME);
}

function isSaneVersion(v: unknown): v is string {
  return typeof v === "string" && v.length > 0 && v.length <= 64;
}

export function writeUpdateMarker(
  userDataDir: string,
  marker: UpdateMarker,
  fileSystem: typeof fs = fs,
): string | null {
  const p = markerPath(userDataDir);
  try {
    fileSystem.mkdirSync(userDataDir, { recursive: true });
    const tmp = `${p}.tmp`;
    fileSystem.writeFileSync(tmp, JSON.stringify(marker, null, 2), "utf8");
    fileSystem.renameSync(tmp, p);
    return p;
  } catch {
    return null;
  }
}

export function readUpdateMarker(
  userDataDir: string,
  fileSystem: typeof fs = fs,
): UpdateMarker | null {
  try {
    const parsed = JSON.parse(fileSystem.readFileSync(markerPath(userDataDir), "utf8"));
    if (parsed == null || typeof parsed !== "object") return null;
    const { fromVersion, toVersion, startedAt } = parsed as Record<string, unknown>;
    if (!isSaneVersion(fromVersion) || !isSaneVersion(toVersion)) return null;
    if (typeof startedAt !== "number" || !Number.isFinite(startedAt)) return null;
    return { fromVersion, toVersion, startedAt };
  } catch {
    return null;
  }
}

export function clearUpdateMarker(userDataDir: string, fileSystem: typeof fs = fs): void {
  try {
    fileSystem.unlinkSync(markerPath(userDataDir));
  } catch {
    /* no estaba: nada que limpiar */
  }
}

/**
 * Qué contar al usuario al arrancar: si la versión que corre es la que se
 * estaba instalando, salió bien; si no, la instalación se quedó a medias.
 * Una marca vieja se descarta en silencio.
 */
export function classifyUpdateOutcome(
  marker: UpdateMarker | null,
  currentVersion: string,
  now: number = Date.now(),
): UpdateOutcome {
  if (marker == null) return { kind: "none" };
  if (now - marker.startedAt > MARKER_MAX_AGE_MS) return { kind: "none" };
  // Sin versión destino conocida no se puede afirmar nada: mejor callar que
  // anunciar una actualización que igual no pasó.
  if (marker.fromVersion === marker.toVersion) return { kind: "none" };
  if (marker.toVersion === currentVersion) {
    return { kind: "installed", version: currentVersion };
  }
  if (marker.fromVersion === currentVersion) {
    return { kind: "not-completed", version: marker.toVersion };
  }
  // Versión distinta de las dos: alguien instaló otra cosa por su cuenta.
  return { kind: "none" };
}

export const __test = { MARKER_MAX_AGE_MS, markerPath };
