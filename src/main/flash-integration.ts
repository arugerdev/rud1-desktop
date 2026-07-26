/**
 * Glue that ties the flasher shim + orchestrator + lifecycle manager to the
 * app's USB session state. index.ts wires this in with a few calls:
 *
 *   const flash = initFlashIntegration({ detach, attach });
 *   // on every change to the persisted USB session set (attach, detach,
 *   // COM capture, post-VPN reattach):
 *   flash.syncSessions(usbSessions);
 *   // on quit:
 *   flash.shutdown();
 *
 * The persisted USB session list is the single source of truth. syncSessions()
 * projects it into the live COM→device map that both the orchestrator
 * (resolvePort) and the shim config (portsMap) read from — so the shim only
 * reroutes COM ports backed by a currently-attached rud1 device, and the
 * port/address can never drift from what is actually attached.
 */

import { execFile } from "child_process";
import path from "path";
import { app } from "electron";
import {
  startShimOrchestrator,
  SHIM_ORCHESTRATOR_PORT,
  ResolvedDevice,
  OrchestratorDeps,
} from "./shim-orchestrator";
import { ShimManager } from "./shim-lifecycle-manager";

export interface FlashIntegrationDeps {
  statePath?: string;
  detach: (busId: string) => Promise<void>;
  attach: (host: string, busId: string) => Promise<void>;
}

/** Minimal shape syncSessions needs from a persisted USB session entry. */
export interface FlashSession {
  com?: string;
  host: string;
  busId: string;
}

/**
 * Pure projection: the live COM→device map is derived from the USB session set
 * (single source of truth). Sessions without a captured COM are skipped — they
 * aren't routable yet. A full rebuild each call means a detached device simply
 * disappears, so the map can never drift from what is attached. Exported for
 * unit testing without standing up the orchestrator/shim.
 */
export function projectSessions(
  sessions: ReadonlyArray<FlashSession>,
): Map<string, ResolvedDevice> {
  const m = new Map<string, ResolvedDevice>();
  for (const s of sessions) {
    if (s.com) m.set(s.com, { host: s.host, busId: s.busId });
  }
  return m;
}

export class FlashIntegration {
  private registry = new Map<string, ResolvedDevice>(); // comPort -> device
  private shim: ShimManager;
  private server: ReturnType<typeof startShimOrchestrator>;

  constructor(deps: FlashIntegrationDeps) {
    const statePath =
      deps.statePath ?? path.join(app.getPath("userData"), "rud1-shim-wraps.json");
    const endpoint = `http://127.0.0.1:${SHIM_ORCHESTRATOR_PORT}/flash`;
    this.shim = new ShimManager({ statePath, endpoint });

    const orchestratorDeps: OrchestratorDeps = {
      resolvePort: (comPort) => this.registry.get(comPort) ?? null,
      detach: deps.detach,
      attach: deps.attach,
    };
    this.server = startShimOrchestrator(orchestratorDeps);
    this.refreshShims();
  }

  /**
   * Rebuild the live COM→device map from the authoritative USB session list.
   * The persisted sessions are the single source of truth; the shim config is
   * a pure projection of them, so ports/addresses can never drift from what is
   * actually attached. Sessions without a captured COM are skipped (nothing to
   * reroute yet). Safe to call on every session change.
   */
  syncSessions(sessions: ReadonlyArray<FlashSession>): void {
    this.registry = projectSessions(sessions);
    this.refreshShims();
  }

  /** Current COM→busId map for the shim config. */
  portsMap(): Record<string, string> {
    const m: Record<string, string> = {};
    for (const [com, dev] of this.registry) m[com] = dev.busId;
    return m;
  }

  private refreshShims(): void {
    try {
      this.shim.syncPorts(this.portsMap());
    } catch {
      /* best-effort */
    }
  }

  /** Restore all wrapped flashers and stop the orchestrator. Call on quit. */
  shutdown(): void {
    try {
      this.server.close();
    } catch {
      /* ignore */
    }
    this.shim.restoreAll();
  }
}

export function initFlashIntegration(deps: FlashIntegrationDeps): FlashIntegration {
  return new FlashIntegration(deps);
}

/**
 * List current serial port names (COM3, …). Snapshot before and after a usbip
 * attach and diff to learn which COM the freshly-attached device got. Windows
 * via PowerShell; other platforms return [] (COM capture is Windows-specific).
 */
export function listComPorts(): Promise<string[]> {
  if (process.platform !== "win32") return Promise.resolve([]);
  return new Promise((resolve) => {
    execFile(
      "powershell.exe",
      ["-NoProfile", "-Command", "[System.IO.Ports.SerialPort]::GetPortNames() -join ','"],
      { timeout: 8000 },
      (err, stdout) => {
        if (err) return resolve([]);
        resolve(
          stdout
            .trim()
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
        );
      },
    );
  });
}

/**
 * Capture the COM port a usbip attach created, by diffing the port list around
 * the attach. Returns the single new COM, or null if none/ambiguous.
 *
 *   const before = await listComPorts();
 *   await usbAttach(host, busId);
 *   const com = await captureComPort(before);
 */
export async function captureComPort(before: string[], settleMs = 4000): Promise<string | null> {
  await new Promise((r) => setTimeout(r, settleMs));
  const after = await listComPorts();
  const added = after.filter((p) => !before.includes(p));
  return added.length === 1 ? added[0] : null;
}
