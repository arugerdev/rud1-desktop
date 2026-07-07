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

export class ShimManager {
  private shimPath: string;
  private statePath: string;
  private endpoint: string;
  private state: ShimState = { wraps: [] };
  private shimSize = -1;

  constructor(opts: { statePath: string; endpoint: string; shimPath?: string }) {
    this.shimPath = opts.shimPath ?? rud1shimPath();
    this.statePath = opts.statePath;
    this.endpoint = opts.endpoint;
    try {
      this.state = JSON.parse(fs.readFileSync(this.statePath, "utf8")) as ShimState;
    } catch {
      this.state = { wraps: [] };
    }
    try {
      this.shimSize = fs.statSync(this.shimPath).size;
    } catch {
      this.shimSize = -1;
    }
  }

  private isOurShim(p: string): boolean {
    if (this.shimSize < 0) return false;
    try {
      return fs.statSync(p).size === this.shimSize;
    } catch {
      return false;
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
      const realPath = realSibling(f.path);
      try {
        if (this.isOurShim(f.path)) {
          // already wrapped (or an IDE reinstall left our shim in place)
        } else if (fs.existsSync(realPath)) {
          // IDE updated the real flasher over our shim → adopt the new real
          fs.copyFileSync(f.path, realPath);
          fs.copyFileSync(this.shimPath, f.path);
        } else {
          // fresh wrap: back up real, drop shim in its place
          fs.copyFileSync(f.path, realPath);
          fs.copyFileSync(this.shimPath, f.path);
        }
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
        if (fs.existsSync(w.realPath)) {
          fs.copyFileSync(w.realPath, w.toolPath);
          fs.rmSync(w.realPath, { force: true });
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
