/**
 * WireGuard tunnel diagnostics manager.
 *
 * Exposes two read-only diagnostic probes that the rud1.es dashboard can
 * invoke through the Electron bridge to help investigate "why is my tunnel
 * not working". The probes are intentionally side-effect free — they never
 * mutate kernel state, never touch /etc/wireguard/, and never request
 * elevation; they only observe.
 *
 * Exposed probes:
 *   wgStatus(tunnelName?)     — runs `wg show [tunnelName]` and parses the
 *                               result into a typed peer list. If the
 *                               wg binary is not installed, returns
 *                               {available: false, reason}.
 *   tunnelHealth(opts)        — runs ping(wgHost), ping(publicHost) and a
 *                               TCP portCheck(publicHost, publicPort) in
 *                               parallel and derives a verdict + actionable
 *                               hints for the UI.
 */

import { execFile } from "child_process";
import { promisify } from "util";
import { ping, portCheck, validateHost } from "./net-diag-manager";

const execFileAsync = promisify(execFile);

const TUNNEL_NAME_REGEX = /^[a-zA-Z0-9_-]{1,32}$/;
const WG_WINDOWS_PATH = "C:\\Program Files\\WireGuard\\wg.exe";

// ─── wgStatus ────────────────────────────────────────────────────────────────

export interface WgPeer {
  publicKey: string;
  endpoint: string | null;
  allowedIps: string[];
  /** Unix seconds. 0 means never handshaken. */
  latestHandshake: number;
  transferRx: number;
  transferTx: number;
  persistentKeepalive: number | null;
}

export interface WgTunnel {
  interface: string;
  publicKey: string | null;
  listenPort: number | null;
  peers: WgPeer[];
}

export type WgStatusResult =
  | { available: true; tunnels: WgTunnel[] }
  | { available: false; reason: string };

function wgBinary(): string {
  return process.platform === "win32" ? WG_WINDOWS_PATH : "wg";
}

/**
 * Parse `wg show` (non-dump) output. The format is a blank-line separated
 * list of interface blocks; each block starts with `interface: <name>` and
 * contains indented `peer: <key>` sub-blocks. We pick up the fields we care
 * about; anything we don't recognise is silently skipped so future wg
 * versions don't break the parser.
 */
function parseWgShow(raw: string): WgTunnel[] {
  const tunnels: WgTunnel[] = [];
  const blocks = raw.split(/\r?\n\r?\n/);

  let current: WgTunnel | null = null;
  let currentPeer: WgPeer | null = null;

  const flushPeer = () => {
    if (current && currentPeer) {
      current.peers.push(currentPeer);
    }
    currentPeer = null;
  };

  const flushTunnel = () => {
    flushPeer();
    if (current) tunnels.push(current);
    current = null;
  };

  for (const block of blocks) {
    const lines = block.split(/\r?\n/);
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line) continue;

      const mIface = line.match(/^interface:\s*(\S+)/i);
      if (mIface) {
        flushTunnel();
        current = {
          interface: mIface[1]!,
          publicKey: null,
          listenPort: null,
          peers: [],
        };
        continue;
      }

      const mPeer = line.match(/^peer:\s*(\S+)/i);
      if (mPeer && current) {
        flushPeer();
        currentPeer = {
          publicKey: mPeer[1]!,
          endpoint: null,
          allowedIps: [],
          latestHandshake: 0,
          transferRx: 0,
          transferTx: 0,
          persistentKeepalive: null,
        };
        continue;
      }

      const kv = line.match(/^([a-zA-Z ]+):\s*(.+)$/);
      if (!kv) continue;
      const key = kv[1]!.trim().toLowerCase();
      const value = kv[2]!.trim();

      if (currentPeer) {
        switch (key) {
          case "endpoint":
            currentPeer.endpoint = value;
            break;
          case "allowed ips":
            currentPeer.allowedIps = value
              .split(",")
              .map((s) => s.trim())
              .filter((s) => s.length > 0 && s !== "(none)");
            break;
          case "latest handshake":
            currentPeer.latestHandshake = parseHandshake(value);
            break;
          case "transfer":
            {
              const t = parseTransfer(value);
              currentPeer.transferRx = t.rx;
              currentPeer.transferTx = t.tx;
            }
            break;
          case "persistent keepalive":
            currentPeer.persistentKeepalive = parseKeepalive(value);
            break;
        }
      } else if (current) {
        switch (key) {
          case "public key":
            current.publicKey = value;
            break;
          case "listening port":
            {
              const n = parseInt(value, 10);
              current.listenPort = Number.isFinite(n) ? n : null;
            }
            break;
        }
      }
    }
  }

  flushTunnel();
  return tunnels;
}

/**
 * `wg show` prints "latest handshake: 2 minutes, 3 seconds ago" — not a
 * timestamp. We derive an approximate unix seconds value by subtracting the
 * parsed duration from `now`. "(none)" / empty means never handshaken ⇒ 0.
 */
function parseHandshake(value: string): number {
  const v = value.toLowerCase();
  if (v.includes("never") || v.includes("(none)") || v.length === 0) return 0;

  let totalSeconds = 0;
  const units: Record<string, number> = {
    year: 365 * 24 * 3600,
    years: 365 * 24 * 3600,
    day: 24 * 3600,
    days: 24 * 3600,
    hour: 3600,
    hours: 3600,
    minute: 60,
    minutes: 60,
    second: 1,
    seconds: 1,
  };
  const re = /(\d+)\s*(year|years|day|days|hour|hours|minute|minutes|second|seconds)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(v)) !== null) {
    const n = parseInt(m[1]!, 10);
    const mult = units[m[2]!] ?? 0;
    totalSeconds += n * mult;
  }
  if (totalSeconds === 0) return 0;
  return Math.floor(Date.now() / 1000) - totalSeconds;
}

/** `transfer: 1.23 MiB received, 4.56 KiB sent` → { rx, tx } in bytes. */
function parseTransfer(value: string): { rx: number; tx: number } {
  const rx = parseSize(value.match(/([\d.]+)\s*([KMGTP]?i?B)\s*received/i));
  const tx = parseSize(value.match(/([\d.]+)\s*([KMGTP]?i?B)\s*sent/i));
  return { rx, tx };
}

function parseSize(m: RegExpMatchArray | null): number {
  if (!m) return 0;
  const n = parseFloat(m[1]!);
  if (!Number.isFinite(n)) return 0;
  const unit = (m[2] ?? "B").toUpperCase();
  const base = unit.includes("I") ? 1024 : 1000;
  const factor =
    unit.startsWith("K") ? base :
    unit.startsWith("M") ? base ** 2 :
    unit.startsWith("G") ? base ** 3 :
    unit.startsWith("T") ? base ** 4 :
    unit.startsWith("P") ? base ** 5 : 1;
  return Math.round(n * factor);
}

/** `persistent keepalive: every 25 seconds` → 25, or "off" → null. */
function parseKeepalive(value: string): number | null {
  if (/off/i.test(value)) return null;
  const m = value.match(/(\d+)/);
  if (!m) return null;
  const n = parseInt(m[1]!, 10);
  return Number.isFinite(n) ? n : null;
}

export async function wgStatus(tunnelName?: string): Promise<WgStatusResult> {
  if (tunnelName !== undefined) {
    if (typeof tunnelName !== "string" || !TUNNEL_NAME_REGEX.test(tunnelName)) {
      return { available: false, reason: "invalid tunnel name" };
    }
  }

  const bin = wgBinary();
  const args = tunnelName ? ["show", tunnelName] : ["show"];

  try {
    const { stdout } = await execFileAsync(bin, args, {
      timeout: 5_000,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    });
    const tunnels = parseWgShow(stdout || "");
    return { available: true, tunnels };
  } catch (err: unknown) {
    const e = err as NodeJS.ErrnoException & { stdout?: string; stderr?: string };
    const code = e?.code;
    if (code === "ENOENT") {
      return { available: false, reason: "WireGuard tools not installed (wg not found in PATH)" };
    }
    if (code === "ETIMEDOUT" || code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
      return { available: false, reason: `wg show timed out (${String(code)})` };
    }
    // wg may exit non-zero if the tunnel doesn't exist; partial stdout is
    // still useful. If we have any stdout, try parsing it.
    if (e?.stdout && e.stdout.trim().length > 0) {
      try {
        const tunnels = parseWgShow(e.stdout);
        return { available: true, tunnels };
      } catch {
        // fall through
      }
    }
    const stderr = (e?.stderr || "").trim();
    const msg = stderr || (err instanceof Error ? err.message : String(err));
    return { available: false, reason: msg.slice(0, 400) };
  }
}

// ─── tunnelHealth ────────────────────────────────────────────────────────────

export interface TunnelHealthOptions {
  wgHost: string;
  publicHost: string;
  publicPort: number;
  timeoutMs?: number;
}

export type PingProbe = { reachable: boolean; rttMs: number | null } | { error: string };
export type TcpProbe =
  | { open: boolean; errorCode: string | null; latencyMs: number | null }
  | { error: string };

export interface TunnelHealthResult {
  wgPing: PingProbe;
  publicPing: PingProbe;
  tcpProbe: TcpProbe;
  verdict: "healthy" | "degraded" | "broken";
  hints: string[];
}

function toPingProbe(result: { alive: boolean; avgRttMs: number | null }): PingProbe {
  return { reachable: result.alive, rttMs: result.avgRttMs };
}

export async function tunnelHealth(
  opts: TunnelHealthOptions,
): Promise<TunnelHealthResult> {
  if (!opts || typeof opts !== "object") {
    throw new Error("invalid options");
  }
  const { wgHost, publicHost, publicPort } = opts;
  if (!validateHost(wgHost)) throw new Error("invalid wgHost");
  if (!validateHost(publicHost)) throw new Error("invalid publicHost");
  if (
    typeof publicPort !== "number" ||
    !Number.isInteger(publicPort) ||
    publicPort < 1 ||
    publicPort > 65535
  ) {
    throw new Error("invalid publicPort");
  }
  const rawTimeout =
    typeof opts.timeoutMs === "number" && Number.isFinite(opts.timeoutMs)
      ? opts.timeoutMs
      : 4_000;
  const timeoutMs = Math.max(500, Math.min(20_000, Math.floor(rawTimeout)));

  // Each probe is wrapped so a thrown exception surfaces as {error} rather
  // than short-circuiting Promise.all.
  const safe = async <T>(fn: () => Promise<T>, mapErr: (e: unknown) => string): Promise<T | { error: string }> => {
    try {
      return await fn();
    } catch (e) {
      return { error: mapErr(e) };
    }
  };

  // NOTE: WireGuard runs over UDP, so this TCP handshake against the public
  // endpoint only verifies the *host* is reachable on some TCP port — it
  // does NOT validate that the WG listen port is actually receiving UDP.
  // The verdict and hints reflect this limitation.
  const [wgPingResult, publicPingResult, tcpResult] = await Promise.all([
    safe(
      async () => toPingProbe(await ping(wgHost)),
      (e) => (e instanceof Error ? e.message : String(e)),
    ),
    safe(
      async () => toPingProbe(await ping(publicHost)),
      (e) => (e instanceof Error ? e.message : String(e)),
    ),
    safe(
      async () => await portCheck({ host: publicHost, port: publicPort, timeoutMs }),
      (e) => (e instanceof Error ? e.message : String(e)),
    ),
  ]);

  // Derive verdict strictly from the WG ping (the authoritative signal for
  // "is the tunnel carrying traffic right now").
  const wgReachable =
    !("error" in wgPingResult) && wgPingResult.reachable === true;
  const wgRtt =
    !("error" in wgPingResult) && wgPingResult.rttMs !== null
      ? wgPingResult.rttMs
      : null;

  let verdict: "healthy" | "degraded" | "broken";
  if (!wgReachable) {
    verdict = "broken";
  } else if (wgRtt !== null && wgRtt >= 500) {
    verdict = "degraded";
  } else if ("error" in publicPingResult || !publicPingResult.reachable) {
    // WG works, but we can't ping the public endpoint — usually ICMP is
    // filtered in the path. Not a real failure, but worth surfacing.
    verdict = wgReachable ? "degraded" : "broken";
  } else {
    verdict = "healthy";
  }

  const hints: string[] = [];

  if (!wgReachable) {
    hints.push(
      "El túnel WG no responde — verifica que el device esté online desde rud1.es",
    );
  }
  if (wgReachable && wgRtt !== null && wgRtt >= 500) {
    hints.push(
      `Latencia alta (${Math.round(wgRtt)}ms, >500ms) — posible congestión o ruta subóptima`,
    );
  }

  const publicPingFailed =
    "error" in publicPingResult || !publicPingResult.reachable;
  const tcpOpen = !("error" in tcpResult) && tcpResult.open === true;

  if (publicPingFailed && tcpOpen) {
    hints.push(
      `El host público no responde a ping pero el TCP handshake al puerto ${publicPort} sí — ICMP bloqueado en el path, no es necesariamente un problema`,
    );
  }
  if (tcpOpen) {
    hints.push(
      `TCP al puerto WG ${publicPort} abierto — el host está encendido (nota: WG usa UDP, el test real requiere \`wg-quick up\` + handshake)`,
    );
  }
  if (!tcpOpen && !("error" in tcpResult)) {
    const code = tcpResult.errorCode ? ` (${tcpResult.errorCode})` : "";
    hints.push(
      `TCP al puerto ${publicPort} cerrado${code} — normal si WG escucha sólo UDP; úsalo como indicio de "host apagado" si además el ping público también falla`,
    );
  }
  if ("error" in tcpResult) {
    hints.push(`No se pudo ejecutar el TCP probe: ${tcpResult.error}`);
  }
  if (verdict === "healthy") {
    hints.push("Túnel WG responde correctamente — latencia normal y handshake activo");
  }

  return {
    wgPing: wgPingResult,
    publicPing: publicPingResult,
    tcpProbe: tcpResult,
    verdict,
    hints,
  };
}
