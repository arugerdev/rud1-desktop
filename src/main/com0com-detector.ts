
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
  // Stable order: numeric pair id ascending. Lets the panel render
  // a consistent "Pair 0 / Pair 1" list across reloads.
  out.sort((a, b) => Number(a.pairId) - Number(b.pairId));
  return out;
}

/**
 * Enumerates real COM ports currently registered on the system. Used
 * by `pickFreePair` to pick low alias numbers (COM7/COM8) that won't
 * collide with the operator's existing hardware. Reads from
 * SERIALCOMM in the registry — that's where every COM driver
 * (FTDI, CH340, com0com, real UARTs) registers its allocated port,
 * and it's faster than spawning PowerShell for `[SerialPort]::GetPortNames()`.
 *
 * Returns an empty array on non-Windows or when the registry probe
 * fails (degrades gracefully — `pickFreePair` falls back to the
 * legacy COM200/COM201 default).
 */
export async function enumerateExistingComPorts(): Promise<string[]> {
  if (process.platform !== "win32") return [];
  try {
    const { stdout } = await execFileAsync(
      "reg",
      ["query", "HKLM\\HARDWARE\\DEVICEMAP\\SERIALCOMM"],
      { windowsHide: true, timeout: 5000 },
    );
    // Output lines look like: `    \Device\Serial0    REG_SZ    COM3`
    // We only care about the trailing COM<n> token. Single regex over
    // every line so a registry blob with mixed indentation still
    // parses cleanly.
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
 * Picks two unused COM numbers for a fresh com0com pair. The default
 * (COM200/COM201) is deliberately HIGH to dodge collisions, but many
 * legacy tools and embedded toolchains misbehave with three-digit COM
 * names — Arduino IDE 2.x is fine, but PuTTY's GUI strips the leading
 * "C" from "COM200" in its dropdown on some installs, and a handful
 * of vendor IDE installers refuse to enumerate above COM99. Picking
 * a low pair (e.g. COM7/COM8) avoids both classes of bug while still
 * staying clear of the canonical hardware slots (COM1=DB9 modem,
 * COM3/COM4=common USB-serial dongles).
 *
 * Strategy:
 *   1. Build the "occupied" set from the registry + any ports the
 *      existing com0com pair list already claims (so we don't pick
 *      a port that another pair owns).
 *   2. Walk COM_LOW_FLOOR..COM_LOW_CEIL looking for two free
 *      consecutive numbers. Consecutive isn't strictly required by
 *      com0com but it gives the operator something easy to remember
 *      ("COM7 and COM8" beats "COM7 and COM12").
 *   3. Fall back to COM200/COM201 when nothing fits — same value the
 *      previous implementation always returned, so a system with a
 *      huge installed-COM footprint isn't WORSE off than before.
 */
const COM_LOW_FLOOR = 5; // skip COM1..COM4 (conventional modem + common USB-serial)
const COM_LOW_CEIL = 49; // anything above 50 belongs to high-COM backstop
const COM_LEGACY_FALLBACK_USER = "COM200";
const COM_LEGACY_FALLBACK_BRIDGE = "COM201";

/**
 * Pure-logic core of `pickFreePair`. Takes the union of "occupied"
 * COM ports (registry-registered hardware + ports already claimed by
 * other com0com pairs) and returns two free consecutive COM numbers
 * in the low-floor range, or the legacy COM200/COM201 backstop if
 * the floor is full. Exported so unit tests can pin the picker without
 * mocking the registry probe.
 */
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
  occupied.push(...(await enumerateExistingComPorts()));
  return pickFreeAliasPair(occupied);
}

/**
 * Picks the first pair from a list that's currently usable. Prefers
 * pairs with a real COMx alias because the operator's tool (Arduino
 * IDE in particular) enumerates by COM name and won't show CNCAx /
 * CNCBx in its port picker. Falls back to a non-aliased pair so the
 * bridge can at least start — the manager will surface a precise
 * "run setupc to assign aliases" error in that case rather than
 * silently spawn a session the user can't actually use.
 *
 * Handle ownership ("is this port already open?") is NOT tested here:
 * Windows doesn't surface that without opening, which would race the
 * actual bridge open. We rely on rud1-bridge's own EBUSY detection.
 *
 * Returns null when the pair list is empty so the IPC handler can
 * raise a "configure a com0com pair first" hint.
 */
export function pickPair(status: Com0comStatus): Com0comPair | null {
  if (!status.installed || status.pairs.length === 0) return null;
  // First preference: an aliased pair with EmuBR=yes on the user side.
  // Those are the only ones Arduino IDE 2.x will surface in its port
  // picker — picking a non-EmuBR pair when an EmuBR one is available
  // means the operator opens a "valid but invisible to the IDE" COM,
  // which is the most-reported gotcha on hosts that have multiple
  // com0com pairs (e.g. a pre-existing COM5/COM6 from the installer
  // alongside a COM200/COM201 pair created without EmuBR). See the
  // comment on Com0comPair.emuBR for the underlying mechanism.
  const arduinoVisible = status.pairs.find((p) => p.hasComAlias && p.emuBR);
  if (arduinoVisible) return arduinoVisible;
  const aliased = status.pairs.find((p) => p.hasComAlias);
  if (aliased) return aliased;
  return status.pairs[0];
}
