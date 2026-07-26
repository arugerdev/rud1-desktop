/**
 * Local HTTP endpoint the rud1 flasher shim POSTs to. It maps the Windows COM
 * port to a live rud1 device, then orchestrates a latency-immune flash:
 *   detach the usbip COM → POST the job to the device's rud1-fw (/api/flash,
 *   which runs the real flasher locally next to the hardware) → re-attach the
 *   COM so the serial monitor / next upload find it again.
 *
 * Bound to 127.0.0.1 only. Decoupled from the app internals via injected deps
 * (the resolver + attach/detach come from usb-manager + the session store).
 */

import http from "http";
import { AddressInfo } from "net";

export const SHIM_ORCHESTRATOR_PORT = 25341;
const FW_PORT = 7070;

export interface ResolvedDevice {
  host: string; // VPN-reachable device address
  busId: string; // e.g. "1-1.4"
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

async function handleFlash(deps: OrchestratorDeps, job: ShimJob): Promise<{ handled: boolean; rc: number; log: string }> {
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
  } finally {
    // Always restore the COM for the serial monitor / next upload.
    try {
      await deps.attach(dev.host, dev.busId);
    } catch {
      /* best-effort */
    }
  }
}

export function startShimOrchestrator(deps: OrchestratorDeps): http.Server {
  const server = http.createServer((req, res) => {
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
  });
  server.listen(SHIM_ORCHESTRATOR_PORT, "127.0.0.1", () => {
    const addr = server.address() as AddressInfo | null;
    // eslint-disable-next-line no-console
    console.log(`[shim-orchestrator] listening on 127.0.0.1:${addr?.port ?? SHIM_ORCHESTRATOR_PORT}`);
  });
  return server;
}
