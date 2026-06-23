
import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

export interface Com0comPair {
  pairId: string;
  userPort: string;
  bridgePort: string;
  hasComAlias: boolean;
  emuBR: boolean;
}

export interface Com0comStatus {
  installed: boolean;
  setupcPath: string | null;
  pairs: Com0comPair[];
  error?: string;
}

const SETUPC_CANDIDATES = [
  "C:\\Program Files\\com0com\\setupc.exe",
  "C:\\Program Files (x86)\\com0com\\setupc.exe",
  "C:\\Program Files\\com0com\\setupg.exe",
];

export async function detectCom0com(): Promise<Com0comStatus> {
  if (process.platform !== "win32") {
    return { installed: false, setupcPath: null, pairs: [] };
  }
  const setupc = await findSetupc();
  if (!setupc) {
    return { installed: false, setupcPath: null, pairs: [] };
  }
  try {
    const { stdout } = await execFileAsync(setupc, ["list"], {
      windowsHide: true,
      timeout: 5000,
    });
    return {
      installed: true,
      setupcPath: setupc,
      pairs: parseSetupcList(stdout),
    };
  } catch (err) {
    return {
      installed: true,
      setupcPath: setupc,
      pairs: [],
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

async function findSetupc(): Promise<string | null> {
  const fs = await import("fs");
  for (const candidate of SETUPC_CANDIDATES) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch {
      /* ignore — candidate is just unreachable */
    }
  }
  return null;
}

export function parseSetupcList(stdout: string): Com0comPair[] {
  const lines = stdout.split(/\r?\n/);
  const aSide: Map<string, string> = new Map();
  const bSide: Map<string, string> = new Map();
  const aSideEmuBR: Map<string, boolean> = new Map(); 

  const re = /^\s*CNC([AB])(\d+)\s+PortName=(\S+)/i;
  for (const line of lines) {
    const m = line.match(re);
    if (!m) continue;
    const side = m[1].toUpperCase();
    const pairId = m[2];
    const [portRaw, ...options] = m[3].split(",");
    const port = portRaw === "-" ? `CNC${side}${pairId}` : portRaw;
    if (side === "A") {
      aSide.set(pairId, port);
      aSideEmuBR.set(pairId, options.some((o) => /^EmuBR=yes$/i.test(o)));
    } else {
      bSide.set(pairId, port);
    }
  }

  const out: Com0comPair[] = [];
  for (const [pairId, userPort] of aSide) {
    const bridgePort = bSide.get(pairId);
    if (!bridgePort) continue;
    const hasComAlias =
      /^COM\d+$/i.test(userPort) && /^COM\d+$/i.test(bridgePort);
    const emuBR = aSideEmuBR.get(pairId) ?? false;
    out.push({ pairId, userPort, bridgePort, hasComAlias, emuBR });
  }
  out.sort((a, b) => Number(a.pairId) - Number(b.pairId));
  return out;
}

// Lee SERIALCOMM del registro; "" en non-Win o si falla.
export async function enumerateExistingComPorts(): Promise<string[]> {
  if (process.platform !== "win32") return [];
  try {
    const { stdout } = await execFileAsync(
      "reg",
      ["query", "HKLM\\HARDWARE\\DEVICEMAP\\SERIALCOMM"],
      { windowsHide: true, timeout: 5000 },
    );
    // Líneas: `\Device\Serial0  REG_SZ  COM3` — sólo importa COM<n>.
    const out: string[] = [];
    for (const line of stdout.split(/\r?\n/)) {
      const m = line.match(/\b(COM\d+)\s*$/i);
      if (m) out.push(m[1].toUpperCase());
    }
    return out;
  } catch {
    return [];
  }
}

/**
 * Parsea HKLM\SYSTEM\CurrentControlSet\Control\COM Name Arbiter\ComDB.
 *
 * ComDB es un bitmap REG_BINARY donde el bit N (LSB-first dentro del
 * byte, byte 0 primero) representa COM(N+1). Si el bit está set, el
 * puerto está reservado — aunque el device esté desconectado.
 *
 * Esto es lo que `setupc` consulta para rechazar "PortName=COM5 is
 * already logged as in use": SERIALCOMM lista sólo lo ENCHUFADO HOY,
 * ComDB es la lista persistente. Sin leer ComDB, pickFreePair sugiere
 * COM5 y setupc rebota con el popup que vio el usuario.
 */
export function parseComDBBitmap(hex: string): string[] {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  const reserved: string[] = [];
  for (let byteIdx = 0; byteIdx < clean.length; byteIdx += 2) {
    const byte = parseInt(clean.slice(byteIdx, byteIdx + 2), 16);
    if (Number.isNaN(byte)) continue;
    for (let bit = 0; bit < 8; bit++) {
      if ((byte >> bit) & 1) {
        const comNum = byteIdx / 2 * 8 + bit + 1;
        reserved.push(`COM${comNum}`);
      }
    }
  }
  return reserved;
}

export async function enumerateReservedComPortsFromDB(): Promise<string[]> {
  if (process.platform !== "win32") return [];
  try {
    const { stdout } = await execFileAsync(
      "reg",
      [
        "query",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\COM Name Arbiter",
        "/v",
        "ComDB",
      ],
      { windowsHide: true, timeout: 5000 },
    );
    // Línea típica: `    ComDB    REG_BINARY    01000000...`
    const m = stdout.match(/REG_BINARY\s+([0-9A-Fa-f]+)/);
    if (!m) return [];
    return parseComDBBitmap(m[1]!);
  } catch {
    return [];
  }
}

// COM5-49 (skip 1-4 hardware tradicional); fallback COM200/201.
const COM_LOW_FLOOR = 5;
const COM_LOW_CEIL = 49;
const COM_LEGACY_FALLBACK_USER = "COM200";
const COM_LEGACY_FALLBACK_BRIDGE = "COM201";

export function pickFreeAliasPair(occupied: Iterable<string>): {
  user: string;
  bridge: string;
} {
  const taken = new Set<string>();
  for (const port of occupied) {
    if (/^COM\d+$/i.test(port)) taken.add(port.toUpperCase());
  }
  for (let n = COM_LOW_FLOOR; n + 1 <= COM_LOW_CEIL; n++) {
    const a = `COM${n}`;
    const b = `COM${n + 1}`;
    if (!taken.has(a) && !taken.has(b)) {
      return { user: a, bridge: b };
    }
  }
  return { user: COM_LEGACY_FALLBACK_USER, bridge: COM_LEGACY_FALLBACK_BRIDGE };
}

export async function pickFreePair(status: Com0comStatus): Promise<{
  user: string;
  bridge: string;
}> {
  const occupied: string[] = [];
  for (const p of status.pairs) {
    occupied.push(p.userPort, p.bridgePort);
  }
  // Tres fuentes: pares com0com existentes + COM enchufados ahora
  // (SERIALCOMM) + COM reservados aunque desconectados (ComDB). Sin
  // ComDB, setupc rechaza con "already logged as in use".
  const [active, reserved] = await Promise.all([
    enumerateExistingComPorts(),
    enumerateReservedComPortsFromDB(),
  ]);
  occupied.push(...active, ...reserved);
  return pickFreeAliasPair(occupied);
}

// Prioriza aliased+EmuBR (Arduino IDE 2.x sólo enumera esos).
export function pickPair(status: Com0comStatus): Com0comPair | null {
  if (!status.installed || status.pairs.length === 0) return null;
  const arduinoVisible = status.pairs.find((p) => p.hasComAlias && p.emuBR);
  if (arduinoVisible) return arduinoVisible;
  const aliased = status.pairs.find((p) => p.hasComAlias);
  if (aliased) return aliased;
  return status.pairs[0];
}
