/**
 * Glue that ties the flasher shim + orchestrator + lifecycle manager to the
 * app's USB session state. index.ts wires this in with a few calls:
 *
 *   const flash = initFlashIntegration({ statePath });
 *   // when a rud1 serial device is attached (comPort captured via
 *   // captureComPort() bracketing the usbip attach):
 *   flash.registerDevice(comPort, { host, busId, vhciPort });
 *   // when detached:
 *   flash.unregisterByBusId(busId);
 *   // on quit:
 *   flash.shutdown();
 *
 * registerDevice/unregister keep the live COM→device map that both the
 * orchestrator (resolvePort) and the shim config (portsMap) read from, so the
 * shim only ever reroutes ports backed by a currently-attached rud1 device.
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
  detach: (vhciPort: number) => Promise<void>;
  attach: (host: string, busId: string) => Promise<void>;
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

  /** Register (or update) a live rud1 serial device by its Windows COM port. */
  registerDevice(comPort: string, dev: ResolvedDevice): void {
    if (!comPort) return;
    this.registry.set(comPort, dev);
    this.refreshShims();
  }

  unregisterByBusId(busId: string): void {
    for (const [com, dev] of this.registry) {
      if (dev.busId === busId) this.registry.delete(com);
    }
    this.refreshShims();
  }

  unregisterByComPort(comPort: string): void {
    this.registry.delete(comPort);
    this.refreshShims();
  }

  clear(): void {
    this.registry.clear();
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
