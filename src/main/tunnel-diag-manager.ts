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
import { createHash } from "crypto";
import { promises as fsp } from "fs";
import * as os from "os";
import * as path from "path";
import { app } from "electron";
import { ping, portCheck, validateHost } from "./net-diag-manager";
import { getStats as getSystemStats, type SystemStats } from "./system-manager";

const execFileAsync = promisify(execFile);

// IPv4 header (20) + ICMP header (8) = 28 bytes of overhead that the OS
// adds on top of the `-s <payloadSize>` / `-l <payloadSize>` argument.
const ICMP_IP_OVERHEAD = 28;

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
  /**
   * When true, and the computed verdict is `degraded` or `broken`, run an
   * extra MTU bisect probe against `wgHost` and attach the discovered value
   * (plus a matching hint) to the result. Default: false — keeps the call
   * cheap and backwards-compatible.
   */
  autoMtuProbe?: boolean;
  /** Outer budget for the auxiliary MTU probe, in ms. Default 12000. */
  mtuProbeTimeoutMs?: number;
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
  /**
   * Populated only when `autoMtuProbe` was requested AND the probe ran to
   * completion with a discovered value. `simulated` is true when the result
   * came from the RUD1_SIMULATE short-circuit inside `mtuProbe`.
   */
  mtu?: { discovered: number; simulated?: boolean };
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

  // Optional auxiliary probe: when the caller opted in and the tunnel is
  // looking sick, run an MTU bisect so the caller gets an actionable value
  // in a single IPC round-trip. Any failure is caught and surfaced as a
  // hint — it must never fail the whole tunnelHealth call.
  let mtuInfo: { discovered: number; simulated?: boolean } | undefined;
  if (
    opts.autoMtuProbe === true &&
    (verdict === "degraded" || verdict === "broken") &&
    typeof wgHost === "string" &&
    wgHost.length > 0
  ) {
    const rawMtuTimeout =
      typeof opts.mtuProbeTimeoutMs === "number" &&
      Number.isFinite(opts.mtuProbeTimeoutMs)
        ? Math.floor(opts.mtuProbeTimeoutMs)
        : 12_000;
    try {
      const probeRes = await mtuProbe(wgHost, { timeoutMs: rawMtuTimeout });
      if (probeRes && typeof probeRes.mtu === "number" && probeRes.mtu > 0) {
        const simulated = process.env.RUD1_SIMULATE === "1" ? true : undefined;
        mtuInfo = simulated
          ? { discovered: probeRes.mtu, simulated: true }
          : { discovered: probeRes.mtu };
        hints.push(
          `MTU sugerido para el túnel: ${probeRes.mtu} (añade MTU = ${probeRes.mtu} en la sección [Interface] del .conf)`,
        );
      } else {
        const why = probeRes?.errorMsg ? `: ${probeRes.errorMsg}` : "";
        hints.push(`Auto-MTU probe no pudo determinar un valor${why}`);
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      hints.push(`Auto-MTU probe falló: ${msg}`);
    }
  }

  return {
    wgPing: wgPingResult,
    publicPing: publicPingResult,
    tcpProbe: tcpResult,
    verdict,
    hints,
    ...(mtuInfo ? { mtu: mtuInfo } : {}),
  };
}

// ─── mtuProbe ────────────────────────────────────────────────────────────────

export type MtuProbePlatform = "linux" | "darwin" | "win32" | "other";

export interface MtuProbeOptions {
  start?: number;
  min?: number;
  /** Outer budget for the whole bisect, in ms. */
  timeoutMs?: number;
}

export interface MtuProbeAttempt {
  size: number;
  ok: boolean;
  errorMsg?: string;
}

export interface MtuProbeResult {
  host: string;
  /** Highest confirmed-passing size, or null if even `min` failed / platform unsupported. */
  mtu: number | null;
  attempts: MtuProbeAttempt[];
  durationMs: number;
  platform: MtuProbePlatform;
  /** Populated on platform=other or when the outer timeout triggers. */
  errorMsg?: string;
}

function detectPlatform(): MtuProbePlatform {
  switch (process.platform) {
    case "linux":
      return "linux";
    case "darwin":
      return "darwin";
    case "win32":
      return "win32";
    default:
      return "other";
  }
}

/**
 * Cross-platform indicators that the packet was dropped because DF was set
 * AND the payload exceeded a link's MTU on the path. We check these *in
 * addition* to exit code — some platforms return 0 even when the packet
 * was fragmented-needed-and-DF-set.
 */
const MTU_FAIL_PATTERNS = [
  /message too long/i,
  /frag(?:mentation)?\s*needed/i,
  /packet needs to be fragmented/i,
  /needs? to be fragmented/i,
  /pmtu/i,
];

function looksLikeMtuFailure(output: string): boolean {
  return MTU_FAIL_PATTERNS.some((re) => re.test(output));
}

interface PingOneShotArgs {
  host: string;
  size: number;
  platform: MtuProbePlatform;
  signal: AbortSignal;
}

/**
 * Issue a single DF-flagged ping with the requested *total* IP packet size.
 * Resolves `{ok: true}` if the packet made it through, `{ok: false, errorMsg}`
 * if the path dropped it (MTU too small), the binary exited non-zero, or the
 * outer AbortController fired.
 */
async function pingOneShot(args: PingOneShotArgs): Promise<{ ok: boolean; errorMsg?: string }> {
  const { host, size, platform, signal } = args;
  const payload = size - ICMP_IP_OVERHEAD;
  if (payload <= 0) {
    return { ok: false, errorMsg: `size ${size} below ICMP overhead` };
  }

  let cmd: string;
  let argv: string[];
  switch (platform) {
    case "linux":
      cmd = "ping";
      argv = ["-M", "do", "-c", "1", "-W", "2", "-s", String(payload), host];
      break;
    case "darwin":
      cmd = "ping";
      argv = ["-D", "-c", "1", "-t", "2", "-s", String(payload), host];
      break;
    case "win32":
      cmd = "ping";
      argv = ["-f", "-n", "1", "-w", "2000", "-l", String(payload), host];
      break;
    default:
      return { ok: false, errorMsg: "platform not supported" };
  }

  try {
    const { stdout, stderr } = await execFileAsync(cmd, argv, {
      timeout: 4_000,
      windowsHide: true,
      signal,
    });
    const out = (stdout || "") + (stderr || "");
    if (looksLikeMtuFailure(out)) {
      return { ok: false, errorMsg: "mtu exceeded (df set)" };
    }
    // Windows `ping -f` can exit 0 even when every probe was dropped — rely
    // on "Received = 0" / "Lost = 1 (100% loss)" as a secondary signal.
    if (platform === "win32") {
      const lostAll = /Lost\s*=\s*1\s*\(100%\s*loss\)/i.test(out);
      const receivedZero = /Received\s*=\s*0/i.test(out);
      if (lostAll || receivedZero) {
        return { ok: false, errorMsg: "no reply (likely mtu exceeded)" };
      }
    }
    return { ok: true };
  } catch (err: unknown) {
    if (signal.aborted) {
      return { ok: false, errorMsg: "aborted" };
    }
    const e = err as NodeJS.ErrnoException & { stdout?: string; stderr?: string; code?: string | number };
    const combined = (e?.stdout || "") + (e?.stderr || "");
    if (looksLikeMtuFailure(combined)) {
      return { ok: false, errorMsg: "mtu exceeded (df set)" };
    }
    if (e?.code === "ENOENT") {
      return { ok: false, errorMsg: "ping binary not found" };
    }
    const msg = combined.trim() || (err instanceof Error ? err.message : String(err));
    return { ok: false, errorMsg: msg.slice(0, 200) };
  }
}

/**
 * Discover the effective MTU to `host` by DF-flagged ping bisection between
 * `min` and `start`. Returns the highest size that produced a reply; null if
 * even `min` failed, the platform is unsupported, or the outer budget ran out
 * before anything was confirmed.
 *
 * Strategy:
 *   1. Probe `start`. If it passes, we're done — that's the MTU.
 *   2. Otherwise probe `min`. If that also fails, give up (mtu=null).
 *   3. Bisect: probe (lo+hi)/2 where lo is the highest known-pass and hi the
 *      lowest known-fail. Each iteration halves the window. Capped at 8
 *      iterations — sufficient to narrow 576..1500 down to ~4-byte precision.
 */
export async function mtuProbe(
  host: string,
  opts?: MtuProbeOptions,
): Promise<MtuProbeResult> {
  const started = Date.now();
  const platform = detectPlatform();

  if (!validateHost(host)) {
    throw new Error("invalid host");
  }

  // Defaults + bounds-sanity. We accept the caller's `start`/`min` only if
  // they're finite integers within a sensible IPv4 MTU envelope.
  const rawStart = typeof opts?.start === "number" && Number.isFinite(opts.start) ? Math.floor(opts.start) : 1500;
  const rawMin = typeof opts?.min === "number" && Number.isFinite(opts.min) ? Math.floor(opts.min) : 576;
  const rawTimeout =
    typeof opts?.timeoutMs === "number" && Number.isFinite(opts.timeoutMs) ? Math.floor(opts.timeoutMs) : 15_000;

  const start = Math.max(ICMP_IP_OVERHEAD + 1, Math.min(9_000, rawStart));
  const min = Math.max(ICMP_IP_OVERHEAD + 1, Math.min(start, rawMin));
  const timeoutMs = Math.max(1_000, Math.min(60_000, rawTimeout));

  // Simulation mode — deterministic output for UI tests & CI, never shells out.
  if (process.env.RUD1_SIMULATE === "1") {
    return {
      host,
      mtu: 1420,
      attempts: [
        { size: 1500, ok: false, errorMsg: "mtu exceeded (df set)" },
        { size: 1420, ok: true },
      ],
      durationMs: 12,
      platform: platform === "win32" ? "win32" : "linux",
    };
  }

  if (platform === "other") {
    return {
      host,
      mtu: null,
      attempts: [],
      durationMs: Date.now() - started,
      platform: "other",
      errorMsg: "platform not supported",
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const attempts: MtuProbeAttempt[] = [];
  let mtu: number | null = null;
  let outerErr: string | undefined;

  const probe = async (size: number): Promise<boolean> => {
    const clamped = Math.max(min, Math.min(start, Math.floor(size)));
    const r = await pingOneShot({ host, size: clamped, platform, signal: controller.signal });
    attempts.push(r.ok ? { size: clamped, ok: true } : { size: clamped, ok: false, errorMsg: r.errorMsg });
    return r.ok;
  };

  try {
    // Step 1 — try the upper bound first. Common case: path MTU == link MTU
    // and we finish in a single ping.
    if (await probe(start)) {
      mtu = start;
    } else if (controller.signal.aborted) {
      outerErr = "timeout";
    } else {
      // Step 2 — floor check. If the minimum viable MTU also fails, the link
      // is broken at layers below IP; we cannot recover a number.
      const minOk = await probe(min);
      if (!minOk) {
        mtu = null;
      } else {
        // Step 3 — bisect between the known-good floor and the known-bad ceiling.
        mtu = min;
        let lo = min;
        let hi = start;
        let iterations = 0;
        const MAX_ITER = 8;
        while (iterations < MAX_ITER && hi - lo > 1 && !controller.signal.aborted) {
          const mid = Math.floor((lo + hi) / 2);
          if (mid === lo || mid === hi) break;
          const ok = await probe(mid);
          if (ok) {
            mtu = mid;
            lo = mid;
          } else {
            hi = mid;
          }
          iterations++;
        }
        if (controller.signal.aborted) outerErr = "timeout";
      }
    }
  } finally {
    clearTimeout(timer);
  }

  return {
    host,
    mtu,
    attempts,
    durationMs: Date.now() - started,
    platform,
    ...(outerErr ? { errorMsg: outerErr } : {}),
  };
}

// ─── fullDiagnosis ───────────────────────────────────────────────────────────

/**
 * Consolidated one-call probe: runs `wgStatus` + `tunnelHealth` (with
 * `autoMtuProbe` defaulted to true) + `systemStats` in parallel and returns
 * a single report. Each sub-call is isolated with `Promise.allSettled` so a
 * single failure never blocks the other signals from arriving.
 *
 * Why: the rud1.es dashboard wants to render a "device diagnosis" panel in
 * one IPC round-trip rather than orchestrating three calls itself. Under the
 * hood it's still the same probes — we just consolidate the plumbing.
 *
 * NOTE on inputs: `tunnelHealth` also needs `publicHost`/`publicPort`; when
 * callers don't supply them here we reuse `wgHost` as the public host and
 * default the port to 51820 (WireGuard's well-known listen port). If
 * `wgHost` isn't provided, `tunnelHealth` will throw and the error surfaces
 * in `tunnelHealthError` while the other two probes still populate.
 *
 * Outer budget: 30s. MTU bisect alone can use up to 15s, plus tunnelHealth's
 * parallel pings (≤4s each) and the CPU sampling window (250ms) in
 * systemStats. 30s gives a comfortable headroom.
 */
export interface FullDiagnosisOptions {
  wgInterface?: string;
  wgHost?: string;
  publicHost?: string;
  publicPort?: number;
  autoMtuProbe?: boolean;
  mtuProbeTimeoutMs?: number;
}

export interface FullDiagnosisResult {
  timestamp: number;
  wgStatus: WgStatusResult | null;
  wgStatusError: string | null;
  tunnelHealth: TunnelHealthResult | null;
  tunnelHealthError: string | null;
  systemStats: SystemStats | null;
  systemStatsError: string | null;
}

const FULL_DIAGNOSIS_OUTER_TIMEOUT_MS = 30_000;
const WG_DEFAULT_LISTEN_PORT = 51820;

function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  try {
    return String(e);
  } catch {
    return "unknown error";
  }
}

export async function fullDiagnosis(
  opts?: FullDiagnosisOptions,
): Promise<FullDiagnosisResult> {
  const o = opts && typeof opts === "object" ? opts : {};
  const wgInterface = typeof o.wgInterface === "string" ? o.wgInterface : undefined;
  const wgHost = typeof o.wgHost === "string" ? o.wgHost : undefined;
  const publicHost =
    typeof o.publicHost === "string" && o.publicHost.length > 0 ? o.publicHost : wgHost;
  const publicPort =
    typeof o.publicPort === "number" &&
    Number.isInteger(o.publicPort) &&
    o.publicPort >= 1 &&
    o.publicPort <= 65535
      ? o.publicPort
      : WG_DEFAULT_LISTEN_PORT;
  const autoMtuProbe = o.autoMtuProbe ?? true;
  const mtuProbeTimeoutMs =
    typeof o.mtuProbeTimeoutMs === "number" && Number.isFinite(o.mtuProbeTimeoutMs)
      ? o.mtuProbeTimeoutMs
      : undefined;

  // Per-call wrapper: captures thrown errors into a sibling `*Error` field
  // while letting the successful value flow through unchanged.
  const safeRun = <T>(fn: () => Promise<T>): Promise<T> => fn();

  const wgStatusTask = safeRun(() => wgStatus(wgInterface));
  const tunnelHealthTask = safeRun(() =>
    tunnelHealth({
      wgHost: wgHost ?? "",
      publicHost: publicHost ?? "",
      publicPort,
      autoMtuProbe,
      ...(mtuProbeTimeoutMs !== undefined ? { mtuProbeTimeoutMs } : {}),
    }),
  );
  const systemStatsTask = safeRun(() => getSystemStats());

  // Outer timeout: racing Promise.allSettled against a sentinel ensures we
  // never exceed the budget even if an individual probe misbehaves.
  let timer: NodeJS.Timeout | null = null;
  const timeoutSentinel = Symbol("fullDiagnosisTimeout");
  const timeoutPromise = new Promise<typeof timeoutSentinel>((resolve) => {
    timer = setTimeout(() => resolve(timeoutSentinel), FULL_DIAGNOSIS_OUTER_TIMEOUT_MS);
  });

  const settledPromise = Promise.allSettled([wgStatusTask, tunnelHealthTask, systemStatsTask]);

  const raced = await Promise.race([settledPromise, timeoutPromise]);
  if (timer) clearTimeout(timer);

  const timestamp = Date.now();

  if (raced === timeoutSentinel) {
    const timeoutMsg = `fullDiagnosis outer timeout (${FULL_DIAGNOSIS_OUTER_TIMEOUT_MS}ms)`;
    return {
      timestamp,
      wgStatus: null,
      wgStatusError: timeoutMsg,
      tunnelHealth: null,
      tunnelHealthError: timeoutMsg,
      systemStats: null,
      systemStatsError: timeoutMsg,
    };
  }

  const [wgStatusSettled, tunnelHealthSettled, systemStatsSettled] = raced;

  return {
    timestamp,
    wgStatus: wgStatusSettled.status === "fulfilled" ? wgStatusSettled.value : null,
    wgStatusError: wgStatusSettled.status === "rejected" ? errMsg(wgStatusSettled.reason) : null,
    tunnelHealth: tunnelHealthSettled.status === "fulfilled" ? tunnelHealthSettled.value : null,
    tunnelHealthError:
      tunnelHealthSettled.status === "rejected" ? errMsg(tunnelHealthSettled.reason) : null,
    systemStats: systemStatsSettled.status === "fulfilled" ? systemStatsSettled.value : null,
    systemStatsError:
      systemStatsSettled.status === "rejected" ? errMsg(systemStatsSettled.reason) : null,
  };
}

// ─── exportReport ────────────────────────────────────────────────────────────

/**
 * Serialize a `fullDiagnosis` run to a timestamped JSON file under
 * `~/.rud1/diag/` and return the final path plus integrity metadata so the
 * renderer can display it (and, if it wants, verify it).
 *
 * The payload wraps the raw diagnosis with app/runtime metadata that is useful
 * when the report is shared via support email. We write atomically (write to
 * `*.tmp` then rename) so a crash mid-write never leaves a half-written file
 * behind.
 *
 * Filename format: `rud1-diag-<YYYYMMDD-HHmmss>.json` in local timezone, all
 * components zero-padded. The second-level resolution is intentional — a user
 * running multiple reports in the same second will see an overwrite, which we
 * consider preferable to polluting the directory with millisecond-precision
 * names that are hard to scan.
 *
 * Sub-call failures inside `fullDiagnosis` are NOT thrown — they're already
 * isolated into `*Error` fields inside the diagnosis result, so the exported
 * report always represents whatever state the probes reached. Only
 * mkdir/write failures surface as thrown errors; the IPC caller wraps those
 * in the `{ok:false, error}` envelope.
 */
export interface ExportReportResult {
  path: string;
  bytes: number;
  sha256: string;
  diagnosis: FullDiagnosisResult;
}

function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

function formatLocalTimestamp(d: Date): string {
  const y = d.getFullYear();
  const mo = pad2(d.getMonth() + 1);
  const da = pad2(d.getDate());
  const h = pad2(d.getHours());
  const mi = pad2(d.getMinutes());
  const s = pad2(d.getSeconds());
  return `${y}${mo}${da}-${h}${mi}${s}`;
}

// ─── report inventory (list / read / delete) ────────────────────────────────

/**
 * Shared guard: resolves a renderer-supplied path and confirms it lives under
 * `~/.rud1/diag/` AND matches the `rud1-diag-*.json` filename shape. The
 * renderer is untrusted, so we treat the input strictly — any mismatch throws.
 * Returns the resolved absolute path, the diag directory, and the filename.
 */
const REPORT_FILENAME_REGEX = /^rud1-diag-[0-9]{8}-[0-9]{6}\.json$/;

function resolveDiagDir(): string {
  const home = os.homedir();
  if (!home || typeof home !== "string" || home.length === 0) {
    throw new Error("Cannot determine user home directory (os.homedir() empty)");
  }
  return path.join(home, ".rud1", "diag");
}

function validateReportPath(reportPath: unknown): { abs: string; dir: string; filename: string } {
  if (typeof reportPath !== "string" || reportPath.length === 0) {
    throw new Error("invalid path");
  }
  const dir = resolveDiagDir();
  const dirWithSep = dir.endsWith(path.sep) ? dir : dir + path.sep;
  const abs = path.resolve(reportPath);
  if (!abs.startsWith(dirWithSep)) {
    throw new Error("path outside allowed directory");
  }
  const filename = path.basename(abs);
  if (!REPORT_FILENAME_REGEX.test(filename)) {
    throw new Error("invalid report filename");
  }
  return { abs, dir, filename };
}

export interface ReportSummary {
  path: string;
  filename: string;
  bytes: number;
  createdAt: string;
}

export async function listReports(): Promise<ReportSummary[]> {
  const dir = resolveDiagDir();
  let entries: string[];
  try {
    entries = await fsp.readdir(dir);
  } catch (err: unknown) {
    const e = err as NodeJS.ErrnoException;
    if (e?.code === "ENOENT") return [];
    throw err;
  }

  const summaries: ReportSummary[] = [];
  for (const name of entries) {
    if (!REPORT_FILENAME_REGEX.test(name)) continue;
    const abs = path.join(dir, name);
    try {
      const st = await fsp.stat(abs);
      if (!st.isFile()) continue;
      const createdMs = st.birthtimeMs && st.birthtimeMs > 0 ? st.birthtimeMs : st.mtimeMs;
      summaries.push({
        path: abs,
        filename: name,
        bytes: st.size,
        createdAt: new Date(createdMs).toISOString(),
      });
    } catch {
      // Skip files that vanished between readdir and stat.
    }
  }
  summaries.sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0));
  return summaries;
}

export interface ReadReportResult {
  path: string;
  bytes: number;
  sha256: string;
  content: unknown;
}

export async function readReport(reportPath: string): Promise<ReadReportResult> {
  const { abs } = validateReportPath(reportPath);
  const buf = await fsp.readFile(abs);
  const sha256 = createHash("sha256").update(buf).digest("hex");
  let content: unknown;
  try {
    content = JSON.parse(buf.toString("utf8"));
  } catch (err) {
    throw new Error(`invalid JSON in report: ${err instanceof Error ? err.message : String(err)}`);
  }
  return { path: abs, bytes: buf.byteLength, sha256, content };
}

export interface DeleteReportResult {
  path: string;
  deleted: true;
}

export async function deleteReport(reportPath: string): Promise<DeleteReportResult> {
  const { abs } = validateReportPath(reportPath);
  try {
    await fsp.unlink(abs);
  } catch (err: unknown) {
    const e = err as NodeJS.ErrnoException;
    if (e?.code === "ENOENT") {
      throw new Error("report not found");
    }
    throw err;
  }
  return { path: abs, deleted: true };
}

export async function exportReport(
  opts: FullDiagnosisOptions,
): Promise<ExportReportResult> {
  // Step 1 — run the diagnosis. fullDiagnosis isolates sub-call failures into
  // its own `*Error` fields, so we never throw here on probe failure.
  const diagnosis = await fullDiagnosis(opts);

  // Step 2 — build the wrapping payload with runtime metadata.
  const payload = {
    exportedAt: new Date().toISOString(),
    appVersion: app.getVersion(),
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.versions.node,
    electronVersion: process.versions.electron,
    diagnosis,
  };
  const content = JSON.stringify(payload, null, 2);

  // Step 3 — resolve the target directory. os.homedir() is typed as `string`
  // but can return an empty string on very unusual systems; guard anyway.
  const home = os.homedir();
  if (!home || typeof home !== "string" || home.length === 0) {
    throw new Error("Cannot determine user home directory (os.homedir() empty)");
  }
  const dir = path.join(home, ".rud1", "diag");
  await fsp.mkdir(dir, { recursive: true });

  // Step 4 — atomic write: file.tmp then rename to final. This avoids readers
  // seeing a partial JSON if the process dies mid-write.
  const filename = `rud1-diag-${formatLocalTimestamp(new Date())}.json`;
  const finalPath = path.join(dir, filename);
  const tmpPath = `${finalPath}.tmp`;
  await fsp.writeFile(tmpPath, content);
  await fsp.rename(tmpPath, finalPath);

  // Step 5 — integrity hash over the exact bytes we just wrote. Hex-encoded
  // SHA-256 so the UI can show it verbatim and support can verify locally.
  const sha256 = createHash("sha256").update(content).digest("hex");

  return {
    path: finalPath,
    bytes: Buffer.byteLength(content),
    sha256,
    diagnosis,
  };
}
