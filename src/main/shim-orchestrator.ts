/**
 * Local HTTP endpoint the rud1 flasher shim POSTs to. It maps the Windows COM
 * port to a live rud1 device, then orchestrates a latency-immune flash:
 *   detach the usbip COM → POST the job to the device's rud1-fw (/api/flash,
 *   which runs the real flasher locally next to the hardware) → re-attach the
 *   COM so the serial monitor / next upload find it again.
 *
 * Bound to 127.0.0.1 only. Decoupled from the app internals via injected deps
 * (the resolver + attach/detach come from usb-manager + the session store).
 *
 * Abrir el puerto no puede tumbar la app: si el preferido está ocupado se usa
 * cualquiera libre (el shim lee el endpoint de su config, que se reescribe), y
 * si no se puede abrir ninguno la programación serie se desactiva sola y los
 * IDE siguen usando su propio flasher.
 */

import { execFile } from "child_process";
import http from "http";
import { AddressInfo } from "net";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

export const SHIM_ORCHESTRATOR_PORT = 25341;
const FW_PORT = 7070;
/** Reintento cuando no se pudo abrir ningún puerto. */
const DEFAULT_RETRY_MS = 60_000;
const HOLDER_PROBE_TIMEOUT_MS = 5_000;

export interface ResolvedDevice {
  host: string; // VPN-reachable device address
  busId: string; // e.g. "1-1.4"
  /** Operator's programmer choice. "never" never reaches here (it is filtered
   *  out of the map), so this is "auto" or "always". */
  mode?: "auto" | "always";
}

export interface OrchestratorDeps {
  /** Map a Windows COM port to a live rud1 device, or null if not ours. */
  resolvePort(comPort: string): ResolvedDevice | null;
  /** Release the Windows COM by detaching the live usbip attachment for this
   *  bus id (resolved fresh — no cached vhci port that could go stale). */
  detach(busId: string): Promise<void>;
  attach(host: string, busId: string): Promise<void>;
}

interface ShimJob {
  comPort: string;
  busid?: string;
  tool?: string;
  argv: string[];
  files: Record<string, string>;
}

function readBody(req: http.IncomingMessage, maxBytes = 64 * 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > maxBytes) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function fwFlash(
  host: string,
  body: { busid: string; argv: string[]; files: Record<string, string> },
): Promise<{ rc: number; log: string }> {
  const res = await fetch(`http://${host}:${FW_PORT}/api/flash`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(5 * 60 * 1000),
  });
  const data = (await res.json()) as { rc?: number; log?: string; error?: string };
  if (!res.ok) {
    return { rc: 1, log: data.error ?? `fw /api/flash HTTP ${res.status}` };
  }
  return { rc: data.rc ?? 1, log: data.log ?? "" };
}

/** Exported for unit tests: the passthrough-vs-fail decision is the contract
 *  the operator's "always" choice depends on. */
export async function handleFlash(deps: OrchestratorDeps, job: ShimJob): Promise<{ handled: boolean; rc: number; log: string }> {
  const dev = deps.resolvePort(job.comPort);
  if (!dev) {
    return { handled: false, rc: 0, log: "" }; // not a rud1 device → shim passes through
  }
  try {
    // Release the Windows COM so the device leaves usbip and the Pi's kernel
    // serial driver can reclaim its local tty. Idempotent: a bus id with no
    // live attachment is a silent no-op.
    await deps.detach(dev.busId);
    const { rc, log } = await fwFlash(dev.host, {
      busid: dev.busId,
      argv: job.argv,
      files: job.files ?? {},
    });
    return { handled: true, rc, log };
  } catch (err) {
    // "always" = el operador ha pedido que este equipo se programe SIEMPRE
    // junto al hardware. Devolver handled:false aquí haría que el shim cayera
    // al flasher local, que es justo lo que pidió evitar: se reporta el fallo.
    if (dev.mode === "always") {
      return { handled: true, rc: 1, log: `rud1: flash remoto fallido: ${String(err)}` };
    }
    return { handled: false, rc: 0, log: "" };
  } finally {
    // Always restore the COM for the serial monitor / next upload.
    try {
      await deps.attach(dev.host, dev.busId);
    } catch {
      /* best-effort */
    }
  }
}

/** Estado del extremo local que atiende al shim. */
export type ShimOrchestratorStatus =
  | { kind: "listening"; port: number; preferredPort: number }
  | {
      kind: "unavailable";
      preferredPort: number;
      code: string | null;
      message: string;
      /** Proceso que tiene el puerto, cuando se puede averiguar. */
      heldBy: string | null;
    }
  | { kind: "stopped" };

export interface ShimOrchestratorOptions {
  preferredPort?: number;
  /** Con el puerto preferido ocupado, vale cualquiera libre. */
  allowFallbackPort?: boolean;
  /** Reintento cuando no se pudo abrir ninguno. 0 = sin reintentos. */
  retryMs?: number;
  onStatus?: (status: ShimOrchestratorStatus) => void;
  /** Solo diagnóstico: quién tiene el puerto. */
  probeHolder?: (port: number) => Promise<string | null>;
}

export interface ShimOrchestrator {
  status(): ShimOrchestratorStatus;
  /** URL para el shim; cadena vacía si no escucha (el shim pasa de largo). */
  endpoint(): string;
  close(): void;
}

/**
 * Quién tiene tomado el puerto. Solo para poder contarlo; si no se puede
 * averiguar, devuelve null y ya está.
 */
export async function probePortHolder(port: number): Promise<string | null> {
  if (process.platform !== "win32") return null;
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
  try {
    const { stdout } = await execFileAsync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        `$c = Get-NetTCPConnection -LocalPort ${port} -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1; if ($c) { (Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue).ProcessName }`,
      ],
      { timeout: HOLDER_PROBE_TIMEOUT_MS, windowsHide: true },
    );
    const name = stdout.trim().split(/\r?\n/)[0]?.trim() ?? "";
    return name.length > 0 && name.length <= 64 ? name : null;
  } catch {
    return null;
  }
}

export function startShimOrchestrator(
  deps: OrchestratorDeps,
  options: ShimOrchestratorOptions = {},
): ShimOrchestrator {
  const handler: http.RequestListener = (req, res) => {
    const send = (code: number, obj: unknown) => {
      const b = Buffer.from(JSON.stringify(obj));
      res.writeHead(code, { "Content-Type": "application/json", "Content-Length": b.length });
      res.end(b);
    };
    if (req.method !== "POST" || (req.url ?? "") !== "/flash") {
      send(404, { error: "not found" });
      return;
    }
    void (async () => {
      try {
        const raw = await readBody(req);
        const job = JSON.parse(raw.toString("utf8")) as ShimJob;
        const out = await handleFlash(deps, job);
        send(200, out);
      } catch (err) {
        send(200, { handled: false, rc: 1, log: `orchestrator error: ${String(err)}` });
      }
    })();
  };

  const preferredPort = options.preferredPort ?? SHIM_ORCHESTRATOR_PORT;
  const allowFallbackPort = options.allowFallbackPort ?? true;
  const retryMs = options.retryMs ?? DEFAULT_RETRY_MS;
  const probeHolder = options.probeHolder ?? probePortHolder;

  let status: ShimOrchestratorStatus = { kind: "stopped" };
  let server: http.Server | null = null;
  let retryTimer: NodeJS.Timeout | null = null;
  let closed = false;

  const setStatus = (next: ShimOrchestratorStatus): void => {
    status = next;
    try {
      options.onStatus?.(next);
    } catch {
      /* quien escucha no puede tumbar el arranque */
    }
  };

  const scheduleRetry = (): void => {
    if (closed || retryMs <= 0 || retryTimer != null) return;
    retryTimer = setTimeout(() => {
      retryTimer = null;
      listenOn(preferredPort, false);
    }, retryMs);
    // Un reintento pendiente no debe mantener vivo el proceso.
    retryTimer.unref?.();
  };

  /**
   * Único punto donde un fallo al abrir el puerto se convierte en ESTADO y no
   * en excepción del proceso principal: sin esto, un EADDRINUSE (otro rud1,
   * un zombi, otro programa) impedía arrancar la app entera.
   */
  function listenOn(port: number, isFallback: boolean): void {
    if (closed) return;
    const srv = http.createServer(handler);
    server = srv;
    let bound = false;

    srv.on("error", (err: NodeJS.ErrnoException) => {
      if (closed) return;
      const code = err?.code ?? null;
      try {
        srv.close();
      } catch {
        /* nunca llegó a abrir */
      }
      if (!bound && code === "EADDRINUSE" && !isFallback && allowFallbackPort) {
        // Puerto tomado: se sigue funcionando en uno libre, y el shim se
        // enterará porque su configuración se reescribe con el nuevo endpoint.
        // eslint-disable-next-line no-console
        console.warn(
          `[shim-orchestrator] puerto ${port} ocupado; probando con uno libre`,
        );
        listenOn(0, true);
        return;
      }
      const message = err?.message ?? String(err);
      // eslint-disable-next-line no-console
      console.warn(
        `[shim-orchestrator] sin extremo local (${code ?? "error"}): ${message}. La programación serie queda desactivada; los IDE usan su propio flasher.`,
      );
      setStatus({
        kind: "unavailable",
        preferredPort,
        code,
        message,
        heldBy: null,
      });
      if (code === "EADDRINUSE") {
        // El nombre del proceso llega después: es solo para poder contarlo.
        void probeHolder(preferredPort)
          .then((heldBy) => {
            const current = status;
            if (heldBy == null || closed || current.kind !== "unavailable") return;
            setStatus({ ...current, heldBy });
          })
          // Es un dato para el mensaje, no parte del flujo: si falla, se queda
          // sin nombre. Sin este catch sería una promesa rechazada suelta.
          .catch(() => undefined);
      }
      scheduleRetry();
    });

    srv.on("listening", () => {
      bound = true;
      // Cerrado mientras abría: no se anuncia un extremo que ya no queremos.
      if (closed) {
        try {
          srv.close();
        } catch {
          /* ignore */
        }
        return;
      }
      const addr = srv.address() as AddressInfo | null;
      const actual = addr?.port ?? port;
      // eslint-disable-next-line no-console
      console.log(`[shim-orchestrator] listening on 127.0.0.1:${actual}`);
      setStatus({ kind: "listening", port: actual, preferredPort });
    });

    srv.listen(port, "127.0.0.1");
  }

  listenOn(preferredPort, false);

  return {
    status: () => status,
    endpoint: () =>
      status.kind === "listening" ? `http://127.0.0.1:${status.port}/flash` : "",
    close: () => {
      closed = true;
      if (retryTimer != null) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
      try {
        server?.close();
      } catch {
        /* ignore */
      }
      server = null;
      status = { kind: "stopped" };
    },
  };
}
