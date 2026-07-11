/**
 * Installs / refreshes / restores the rud1 flasher shim across detected IDE
 * toolchains. Guarantees ("no molestar"):
 *   - Reversible: the real flasher is kept as `<tool>-real(.exe)`; restoreAll()
 *     puts it back and removes the shim + config. Tracked in a state file.
 *   - Update-safe: if an IDE update overwrites our shim with a fresh real
 *     flasher, we detect it (size != shim) and re-wrap, preserving the new real.
 *   - Passthrough: the shim itself execs `<tool>-real` for any non-rud1 port,
 *     so wrapped IDEs behave identically when rud1 isn't in use.
 *
 * The shim reroutes only COM ports present in the config `ports` map, which is
 * refreshed on every syncPorts() with the live rud1 device set — so removing a
 * device (empty map) makes every wrapped flasher a pure passthrough.
 */

import fs from "fs";
import path from "path";
import { rud1shimPath, isRud1shimAvailable } from "./binary-helper";
import { detectFlashers } from "./ide-detector";

interface WrapRecord {
  tool: string;
  toolPath: string; // the path the IDE invokes (now our shim)
  realPath: string; // the backed-up real flasher
  source: string;
}

interface ShimState {
  wraps: WrapRecord[];
}

function realSibling(toolPath: string): string {
  const ext = path.extname(toolPath); // ".exe" or ""
  const base = toolPath.slice(0, toolPath.length - ext.length);
  return `${base}-real${ext}`;
}

// True para un backup nuestro "<tool>-real(.exe)". Nunca debe re-envolverse:
// hacerlo encadenaba "-real-real-real…" y perdía el flasher real.
function isRealBackupName(p: string): boolean {
  const ext = path.extname(p);
  const base = path.basename(p);
  const stem = base.slice(0, base.length - ext.length);
  return stem.toLowerCase().endsWith("-real");
}

// Firmas embebidas en el binario del shim. Detectamos por CONTENIDO (no por
// tamaño, que cambia entre builds) para reconocer nuestro shim de cualquier
// versión y no re-envolverlo/clobbering del real.
const SHIM_MARKERS: readonly Buffer[] = [
  Buffer.from("RUD1SHIM/v1 flasher-interceptor"),
  Buffer.from("rud1shim passthrough error"),
  Buffer.from("rud1: routing upload to"),
];

export class ShimManager {
  private shimPath: string;
  private statePath: string;
  private endpoint: string;
  private state: ShimState = { wraps: [] };

  constructor(opts: { statePath: string; endpoint: string; shimPath?: string }) {
    this.shimPath = opts.shimPath ?? rud1shimPath();
    this.statePath = opts.statePath;
    this.endpoint = opts.endpoint;
    try {
      this.state = JSON.parse(fs.readFileSync(this.statePath, "utf8")) as ShimState;
    } catch {
      this.state = { wraps: [] };
    }
  }

  private isOurShim(p: string): boolean {
    try {
      const buf = fs.readFileSync(p);
      return SHIM_MARKERS.some((m) => buf.includes(m));
    } catch {
      return false;
    }
  }

  // Recorre <tool>, <tool>-real, <tool>-real-real… y devuelve el PRIMER fichero
  // que NO es nuestro shim: el flasher real. null si se perdió (cadena de solo
  // shims o rota) — típico de instalaciones antiguas defectuosas.
  private findGenuine(basePath: string): { path: string; bytes: Buffer } | null {
    let p = basePath;
    for (let i = 0; i < 12; i++) {
      if (!fs.existsSync(p)) return null;
      if (!this.isOurShim(p)) {
        try {
          return { path: p, bytes: fs.readFileSync(p) };
        } catch {
          return null;
        }
      }
      p = realSibling(p);
    }
    return null;
  }

  // Borra cualquier copia sobrante más profunda que <tool>-real (los
  // "-real-real…" que dejó el bug de encadenado).
  private cleanDeeperChain(realPath: string): void {
    let p = realSibling(realPath);
    for (let i = 0; i < 12 && fs.existsSync(p); i++) {
      try {
        fs.rmSync(p, { force: true });
      } catch {
        /* ignore */
      }
      p = realSibling(p);
    }
  }

  private saveState(): void {
    try {
      fs.writeFileSync(this.statePath, JSON.stringify(this.state, null, 2));
    } catch {
      /* best-effort */
    }
  }

  private writeConfig(dir: string, ports: Record<string, string>): void {
    const cfg = {
      endpoint: this.endpoint,
      ports,
      reattach: false, // the desktop orchestrator owns attach/detach in production
    };
    try {
      fs.writeFileSync(path.join(dir, "rud1shim.json"), JSON.stringify(cfg, null, 2));
    } catch {
      /* best-effort */
    }
  }

  /**
   * Ensure every detected flasher is wrapped and its config reflects the given
   * live rud1 port→busid map. Safe to call repeatedly (on attach/detach). If
   * there are no rud1 devices, pass an empty map: shims stay installed but
   * become pure passthroughs (no user-visible change).
   */
  syncPorts(ports: Record<string, string>): void {
    if (!isRud1shimAvailable()) return; // nothing bundled → do nothing, ever
    const wraps: WrapRecord[] = [];
    for (const f of detectFlashers()) {
      if (isRealBackupName(f.path)) continue; // nunca envolver un backup -real
      const realPath = realSibling(f.path);
      try {
        // Localiza el flasher real recorriendo la cadena (maneja por igual: sin
        // envolver, ya envuelto, o cadena "-real-real…" apilada por el bug).
        const genuine = this.findGenuine(f.path);
        if (!genuine) {
          // El flasher real se perdió (instalación antigua defectuosa). No se
          // puede recrear: se deja intacto y el usuario debe reinstalar el core
          // del IDE; el próximo sync lo re-envolverá bien. No lo registramos
          // como wrap para no intentar restaurarlo desde una copia inexistente.
          continue;
        }
        // Estado objetivo, idempotente: <tool>-real = real, <tool> = shim,
        // sin copias "-real-real…" sobrantes.
        fs.writeFileSync(realPath, genuine.bytes);
        fs.copyFileSync(this.shimPath, f.path);
        this.cleanDeeperChain(realPath);
        this.writeConfig(path.dirname(f.path), ports);
        wraps.push({ tool: f.tool, toolPath: f.path, realPath, source: f.source });
      } catch {
        /* skip this flasher (permissions, in-use) — never abort the batch */
      }
    }
    // keep any previously-wrapped entries we didn't re-see this pass
    for (const prev of this.state.wraps) {
      if (!wraps.find((w) => w.toolPath === prev.toolPath) && fs.existsSync(prev.realPath)) {
        this.writeConfig(path.dirname(prev.toolPath), ports);
        wraps.push(prev);
      }
    }
    this.state.wraps = wraps;
    this.saveState();
  }

  /** Restore every wrapped flasher to its original binary and drop configs. */
  restoreAll(): void {
    for (const w of this.state.wraps) {
      try {
        // Recupera el flasher real de la cadena y déjalo en su ruta original,
        // eliminando el shim y todas las copias "-real…".
        const genuine = this.findGenuine(w.toolPath);
        if (genuine) {
          fs.writeFileSync(w.toolPath, genuine.bytes);
          this.cleanDeeperChain(w.toolPath);
        }
        fs.rmSync(path.join(path.dirname(w.toolPath), "rud1shim.json"), { force: true });
        fs.rmSync(path.join(path.dirname(w.toolPath), "rud1shim.log"), { force: true });
      } catch {
        /* best-effort */
      }
    }
    this.state.wraps = [];
    this.saveState();
  }
}
