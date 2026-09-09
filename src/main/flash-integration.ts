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
  ResolvedDevice,
  OrchestratorDeps,
  type ShimOrchestrator,
  type ShimOrchestratorStatus,
} from "./shim-orchestrator";
import { ShimManager } from "./shim-lifecycle-manager";
import { t } from "./i18n";
import {
  DEFAULT_PROGRAMMER_MODE,
  ProgrammerMode,
  ProgrammerModeMap,
  modeFor,
} from "./programmer-mode-store";

export interface FlashIntegrationDeps {
  statePath?: string;
  detach: (busId: string) => Promise<void>;
  attach: (host: string, busId: string) => Promise<void>;
  /** Cambios en el extremo local, para poder avisar en la bandeja. */
  onSerialStatus?: (status: ShimOrchestratorStatus) => void;
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
 *
 * The operator's per-device programmer choice is applied here, at the single
 * point both the shim config and resolvePort read from, so "never" cannot be
 * bypassed by one path while the other honours it.
 */
export function projectSessions(
  sessions: ReadonlyArray<FlashSession>,
  modes: ProgrammerModeMap = {},
): Map<string, ResolvedDevice> {
  const m = new Map<string, ResolvedDevice>();
  for (const s of sessions) {
    if (!s.com) continue;
    const mode = modeFor(modes, s.host, s.busId);
    if (mode === "never") continue; // uses the IDE's original flasher
    m.set(s.com, { host: s.host, busId: s.busId, mode });
  }
  return m;
}

export class FlashIntegration {
  private registry = new Map<string, ResolvedDevice>(); // comPort -> device
  private shim: ShimManager;
  private server: ShimOrchestrator;
  private sessions: ReadonlyArray<FlashSession> = [];
  private modes: ProgrammerModeMap = {};

  constructor(deps: FlashIntegrationDeps) {
    const statePath =
      deps.statePath ?? path.join(app.getPath("userData"), "rud1-shim-wraps.json");
    // El endpoint real llega con el primer estado del orquestador: puede
    // acabar en otro puerto, o no abrir ninguno.
    this.shim = new ShimManager({ statePath, endpoint: "" });

    const orchestratorDeps: OrchestratorDeps = {
      resolvePort: (comPort) => this.registry.get(comPort) ?? null,
      detach: deps.detach,
      attach: deps.attach,
    };
    this.server = startShimOrchestrator(orchestratorDeps, {
      onStatus: (status) => {
        // Reescribir la config de los shims es lo que hace efectivo el cambio
        // de puerto (o el passthrough cuando no hay extremo).
        this.shim.setEndpoint(this.server?.endpoint() ?? "");
        this.refreshShims();
        try {
          deps.onSerialStatus?.(status);
        } catch {
          /* la bandeja no puede tumbar esto */
        }
      },
    });
  }

  /** Estado del extremo local, para la bandeja y el diagnóstico. */
  serialStatus(): ShimOrchestratorStatus {
    return this.server.status();
  }

  /**
   * Rebuild the live COM→device map from the authoritative USB session list.
   * The persisted sessions are the single source of truth; the shim config is
   * a pure projection of them, so ports/addresses can never drift from what is
   * actually attached. Sessions without a captured COM are skipped (nothing to
   * reroute yet). Safe to call on every session change.
   */
  syncSessions(sessions: ReadonlyArray<FlashSession>): void {
    this.sessions = sessions;
    this.registry = projectSessions(sessions, this.modes);
    this.refreshShims();
  }

  /** Adopt the persisted per-device programmer choices (startup) and re-project. */
  setModes(modes: ProgrammerModeMap): void {
    this.modes = modes;
    this.registry = projectSessions(this.sessions, this.modes);
    this.refreshShims();
  }

  modeOf(host: string, busId: string): ProgrammerMode {
    return modeFor(this.modes, host, busId);
  }

  /** Current COM→busId map for the shim config. */
  portsMap(): Record<string, string> {
    const m: Record<string, string> = {};
    for (const [com, dev] of this.registry) m[com] = dev.busId;
    return m;
  }

  private refreshShims(): void {
    // Sin extremo local no se enruta nada: mapa vacío = passthrough puro.
    const routing = this.server?.status().kind === "listening";
    try {
      this.shim.syncPorts(routing ? this.portsMap() : {});
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

/** Fila de bandeja, en el formato mínimo que consume index.ts. */
export interface SerialFlashMenuItem {
  label: string;
  enabled: boolean;
}

/** Longitud a la que se recorta el mensaje del sistema en la bandeja. */
const REASON_MAX = 90;

/**
 * Solo se dice algo cuando la programación serie NO está disponible: es lo
 * único sobre lo que el operador puede actuar. Funcionando en otro puerto no
 * se cuenta en la bandeja (queda en el log), porque no hay nada que hacer.
 */
export function buildSerialFlashMenuItems(
  status: ShimOrchestratorStatus,
): SerialFlashMenuItem[] {
  if (status.kind !== "unavailable") return [];
  const port = status.preferredPort;
  let reason: string;
  if (status.code === "EADDRINUSE") {
    reason = status.heldBy
      ? t("serialFlash.reasonBusyBy", { port, process: status.heldBy })
      : t("serialFlash.reasonBusy", { port });
  } else {
    const message = status.message.slice(0, REASON_MAX);
    reason = t("serialFlash.reasonError", { port, message });
  }
  return [
    { label: t("serialFlash.unavailable"), enabled: false },
    { label: reason, enabled: false },
  ];
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
