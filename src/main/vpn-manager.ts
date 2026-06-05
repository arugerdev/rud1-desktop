/**
 * OpenVPN client manager.
 *
 * Spawns a bundled `openvpn.exe` (Windows) / `openvpn` (Unix) as a child
 * process and tracks its lifecycle via stdout / stderr scraping AND the
 * `--management` TCP control socket. The management socket gives us
 * structured access to the bytes-in/out counters, the assigned IP, and a
 * clean shutdown channel ("signal SIGTERM"); stdout parsing handles the
 * coarse-grained state ("Initialization Sequence Completed", "AUTH_FAILED",
 * "TLS Error").
 *
 * The replaced WireGuard manager exposed `wgConfig` as a string blob to
 * IPC callers. We keep the same shape but the blob is now `.ovpn` content
 * (OpenVPN inline-config). The caller (rud1-es panel) writes it once via
 * `vpnConnect(ovpnConfig)` and the manager handles persistence to
 * `%APPDATA%/rud1-desktop/ovpn/rud1-client.ovpn`, child-process spawn,
 * and elevation prompting for TAP driver install.
 */

import { spawn, ChildProcess, execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);
import fs from "fs/promises";
import net from "net";
import os from "os";
import path from "path";
import { app } from "electron";
import { openvpnPath, isBinaryAvailable, openvpnBundledDir } from "./binary-helper";
import {
  detectOpenVpnRuntime,
  ensureTapDriverInstalled,
  ensureRud1TapEnabled,
  renameTapAdapterToRud1,
  type OpenVpnRuntimeStatus,
} from "./openvpn-installer";
import { writeOvpnConfig, defaultOvpnConfigPath } from "./ovpn-config-store";
import {
  maybeApplyApipaFallback,
  parseLanFallbackHint,
} from "./apipa-fallback";

// ─── Constants ────────────────────────────────────────────────────────────────

const OPENVPN_DOWNLOAD_URL = "https://openvpn.net/community-downloads/";

// Local TCP port the openvpn `--management` socket listens on. Loopback
// only, no password — we're the only consumer and the renderer never
// gets a port number.
const MANAGEMENT_HOST = "127.0.0.1";
const MANAGEMENT_PORT_BASE = 25340;
const MANAGEMENT_PORT_RANGE = 200;

// Stable tunnel name used as the TAP adapter alias hint. The TAP driver
// auto-names adapters "rud1-tap" via `tapctl create --hwid root\tap0901
// --name rud1-tap`; openvpn.exe matches by name with `--dev-node rud1-tap`.
const TUNNEL_NAME = "rud1-tap";

// IFNAMSIZ guard (15 chars + NUL) — same regex as the WG manager.
const TUNNEL_NAME_REGEX = /^[a-zA-Z0-9_.\-]{1,15}$/;

// ─── Errors ───────────────────────────────────────────────────────────────────

export class OpenVpnMissingError extends Error {
  constructor() {
    super(
      `OpenVPN binary not found. Re-run the rud1 installer or download ` +
        `OpenVPN Community from ${OPENVPN_DOWNLOAD_URL} and try again.`,
    );
    this.name = "OpenVpnMissingError";
  }
}

export class TapDriverMissingError extends Error {
  constructor(reason: string) {
    super(
      `TAP-Windows V9 driver is required but is not installed. ${reason}`,
    );
    this.name = "TapDriverMissingError";
  }
}

/**
 * Backwards-compatible alias so callers that still throw / catch the WG
 * "missing" error keep working without a churn-only rename. The IPC layer
 * still surfaces a generic message; the type tag is just for instanceof.
 */
export const WireguardMissingError = OpenVpnMissingError;

// ─── Public types ─────────────────────────────────────────────────────────────

export type VpnHandshakeStatus =
  | "no-tunnel"
  | "no-handshake-yet"
  | "fresh"
  | "stale";

export interface VpnStatusResult {
  connected: boolean;
  ip?: string;
  /** ISO timestamp of the last successful `vpnConnect` (null until first run). */
  lastConnectedAt: string | null;
  /** ISO timestamp of the last successful `vpnDisconnect` (null until first run). */
  lastDisconnectedAt: string | null;
  /** ms the tunnel has been up, or null when down / no in-session stamp. */
  tunnelUptimeMs: number | null;
  /** Real-time handshake classification — see {@link VpnHandshakeStatus}. */
  handshakeStatus: VpnHandshakeStatus | null;
  /** ms since the last successful handshake (or last keepalive ping). */
  handshakeAgeMs: number | null;
}

export interface VpnDisconnectResult {
  /** ms the tunnel was up before the disconnect succeeded, or null when
   *  we don't have a live connect stamp from this session. */
  uptimeMs: number | null;
}

export interface ConfigPreflight {
  /** Parsed first `remote <host> <port>` directive, or null when absent. */
  endpoint: string | null;
  /** True when `endpoint` could be parsed. */
  hasEndpoint: boolean;
  /** Reserved: OpenVPN clients sit behind the server, so client-side
   *  CGNAT on the device's ISP is detected at the cloud level. We
   *  preserve the field for IPC contract stability — always false. */
  cgnat: boolean;
}

// ─── Module state ─────────────────────────────────────────────────────────────

interface RunningProc {
  proc: ChildProcess;
  managementPort: number;
  /** Parsed assigned IP, populated once the management socket reports it. */
  assignedIp: string | null;
  /** ms timestamp of the last received management heartbeat / keepalive. */
  lastHeartbeatAt: number;
  /** True once "Initialization Sequence Completed" is observed on stdout. */
  initialized: boolean;
  /** Captures the most recent error line for diagnostics. */
  lastErrorLine: string | null;
  /** Ring buffer of the last LOG_RING_SIZE stdout/stderr lines. Surfaced
   *  on timeout/early-exit so the operator can see what openvpn was
   *  actually doing without having to crack open the log file. */
  logRing: string[];
}

const LOG_RING_SIZE = 80;

let running: RunningProc | null = null;
let lastConnectedAt: number | null = null;
let lastDisconnectedAt: number | null = null;
let lastOvpnConfig: string | null = null;

// ─── Validators ───────────────────────────────────────────────────────────────

export function validateTunnelName(name: unknown): name is string {
  return typeof name === "string" && TUNNEL_NAME_REGEX.test(name);
}

function assertTunnelName(name: unknown): asserts name is string {
  if (!validateTunnelName(name)) {
    throw new Error("invalid tunnel name");
  }
}

/**
 * Resolves the temp path the WG manager used. Preserved for test parity;
 * the OpenVPN manager writes to `%APPDATA%/rud1-desktop/ovpn/` instead.
 */
export function resolveConfigPath(name: string): string {
  assertTunnelName(name);
  return path.join(os.tmpdir(), `${name}.conf`);
}

// ─── Pre-flight (config inspection) ───────────────────────────────────────────

/**
 * Pull the first `remote <host> <port>` directive out of an `.ovpn`. Used
 * by the IPC layer to surface the endpoint in the connect ack without
 * spawning openvpn first.
 */
export function parseEndpointFromConfig(ovpnConfig: string): string | null {
  if (typeof ovpnConfig !== "string" || ovpnConfig.length === 0) return null;
  for (const raw of ovpnConfig.split(/\r?\n/)) {
    // Strip trailing comments and surrounding whitespace.
    const trimmed = raw.replace(/[#;].*$/, "").trim();
    if (trimmed.length === 0) continue;
    // OpenVPN's `remote` directive: `remote <host> [port] [proto]`.
    const m = trimmed.match(/^remote\s+(\S+)(?:\s+(\d+))?/i);
    if (!m) continue;
    const host = m[1]!;
    const port = m[2];
    return port ? `${host}:${port}` : host;
  }
  return null;
}

/**
 * OpenVPN's client connects OUTBOUND to the server, so a CGNAT'd client
 * isn't an obstacle for the TLS handshake — the connect always works.
 * We keep the signature for IPC contract stability and always return
 * false here.
 */
export function isCGNATEndpoint(_endpoint: string | null | undefined): boolean {
  return false;
}

export function inspectConfig(ovpnConfig: string): ConfigPreflight {
  const endpoint = parseEndpointFromConfig(ovpnConfig);
  return {
    endpoint,
    hasEndpoint: !!endpoint,
    cgnat: false,
  };
}

// ─── Uptime / formatting helpers ──────────────────────────────────────────────

export function computeTunnelUptimeMs(
  connected: boolean,
  lastConnectedAtMs: number | null,
  nowMs: number,
): number | null {
  if (!connected) return null;
  if (lastConnectedAtMs == null) return null;
  const delta = nowMs - lastConnectedAtMs;
  if (delta < 0) return null;
  return delta;
}

export function formatUptimeMs(ms: number | null | undefined): string | null {
  if (ms == null || !Number.isFinite(ms) || ms < 0) return null;
  const totalSec = Math.floor(ms / 1000);
  if (totalSec < 60) return `${totalSec}s`;
  const min = Math.floor(totalSec / 60);
  if (min < 60) return `${min}m ${totalSec % 60}s`;
  const hr = Math.floor(min / 60);
  if (hr < 48) return `${hr}h ${min % 60}m`;
  const days = Math.floor(hr / 24);
  return `${days}d ${hr % 24}h`;
}

// ─── Test-only handshake classifier (preserved for vpn-health-monitor parity) ─

/**
 * Wraps the (now OpenVPN-specific) handshake classification so the
 * health monitor's pure tests still see the same shape they were written
 * against. The OpenVPN management interface gives us continuous "ping"
 * timestamps instead of WG's discrete handshake event, so we derive a
 * synthetic `fresh|stale` from the last-heartbeat delta.
 */
export interface HandshakeSnapshot {
  kind: "no-tunnel" | "no-handshake-yet" | "fresh" | "stale";
  handshakeAgeMs?: number;
}

export function classifyHandshakeSnapshot(
  snapshot: HandshakeSnapshot | null,
): { handshakeStatus: VpnHandshakeStatus | null; handshakeAgeMs: number | null } {
  if (snapshot == null) return { handshakeStatus: null, handshakeAgeMs: null };
  switch (snapshot.kind) {
    case "no-tunnel":
      return { handshakeStatus: "no-tunnel", handshakeAgeMs: null };
    case "no-handshake-yet":
      return { handshakeStatus: "no-handshake-yet", handshakeAgeMs: null };
    case "fresh":
      return { handshakeStatus: "fresh", handshakeAgeMs: snapshot.handshakeAgeMs ?? null };
    case "stale":
      return { handshakeStatus: "stale", handshakeAgeMs: snapshot.handshakeAgeMs ?? null };
  }
}

const STALE_THRESHOLD_MS = 75_000; // 3x default keepalive (25s).

function snapshotFromState(now: number): HandshakeSnapshot {
  if (!running) return { kind: "no-tunnel" };
  if (!running.initialized || running.lastHeartbeatAt === 0) {
    return { kind: "no-handshake-yet" };
  }
  const age = now - running.lastHeartbeatAt;
  if (age >= STALE_THRESHOLD_MS) {
    return { kind: "stale", handshakeAgeMs: age };
  }
  return { kind: "fresh", handshakeAgeMs: Math.max(0, age) };
}

/**
 * Stub used by the legacy auto-reconnect loop. Returns a synthesized
 * stdout that {@link parseHandshakeSnapshot} in `vpn-health-monitor.ts`
 * can still parse — keeping the iter-8 monitor unchanged.
 */
export async function fetchHandshakeStdout(): Promise<string> {
  if (!running) return "";
  const ageSec = Math.max(0, Math.floor((Date.now() - running.lastHeartbeatAt) / 1000));
  // The wg-format parser looks for "ts" at end-of-line.
  const ts = running.lastHeartbeatAt > 0
    ? Math.floor(running.lastHeartbeatAt / 1000)
    : 0;
  void ageSec;
  return `peer\t${ts}\n`;
}

export async function fetchHandshakeSnapshot(
  nowMs: number = Date.now(),
): Promise<HandshakeSnapshot | null> {
  try {
    return snapshotFromState(nowMs);
  } catch {
    return null;
  }
}

// ─── Lifecycle ────────────────────────────────────────────────────────────────

/**
 * Test-only helper: reset the lifecycle freshness signals + cached
 * config back to their initial nulls.
 */
export function __resetVpnLifecycleStateForTests(): void {
  lastConnectedAt = null;
  lastDisconnectedAt = null;
  lastOvpnConfig = null;
  if (running) {
    try { running.proc.kill(); } catch { /* ignore */ }
  }
  running = null;
}

/**
 * Iter 8 — returns the most recent `.ovpn` config the renderer issued to
 * vpnConnect. Used by the auto-reconnect monitor.
 */
export function getLastWgConfig(): string | null {
  return lastOvpnConfig;
}

/**
 * Picks a loopback port the openvpn `--management` listener binds to.
 * Tries the base, then bumps by 1 up to MANAGEMENT_PORT_RANGE to dodge a
 * port that might already be held by a leftover openvpn process from a
 * previous run.
 */
async function pickManagementPort(): Promise<number> {
  for (let i = 0; i < MANAGEMENT_PORT_RANGE; i++) {
    const port = MANAGEMENT_PORT_BASE + i;
    const free = await new Promise<boolean>((resolve) => {
      const probe = net.createServer();
      probe.once("error", () => resolve(false));
      probe.listen(port, MANAGEMENT_HOST, () => {
        probe.close(() => resolve(true));
      });
    });
    if (free) return port;
  }
  throw new Error("Could not allocate a loopback management port for openvpn");
}

/**
 * Connect to the openvpn `--management` socket and subscribe to state +
 * bytecount notifications. We do this AFTER spawn so openvpn has time to
 * bind the socket; the connect attempt retries for up to 5s. Returns the
 * socket so the manager can keep it open for the lifetime of the process.
 *
 * Best-effort: management socket failures don't tear down the tunnel —
 * stdout scraping is enough for the connected / disconnected coarse
 * states.
 */
async function attachManagementSocket(port: number): Promise<net.Socket | null> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try {
      const sock = await new Promise<net.Socket>((resolve, reject) => {
        const s = net.createConnection({ host: MANAGEMENT_HOST, port });
        s.once("connect", () => resolve(s));
        s.once("error", (err) => reject(err));
      });
      return sock;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  return null;
}

function wireManagementSocket(sock: net.Socket): void {
  if (!running) return;
  const live = running;
  // Subscribe to state + byte counts so we can keep `assignedIp` and
  // `lastHeartbeatAt` up to date without polling.
  sock.setEncoding("utf8");
  try {
    sock.write("state on\nbytecount 5\n");
  } catch {
    /* socket already gone */
  }
  let buf = "";
  sock.on("data", (chunk: string) => {
    buf += chunk;
    let nl: number;
    while ((nl = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, nl).replace(/\r$/, "");
      buf = buf.slice(nl + 1);
      parseManagementLine(line, live);
    }
  });
  sock.on("error", () => { /* swallow — child-process death is the source of truth */ });
  sock.on("close", () => { /* connection lost; we'll fall back to stdout scraping */ });
}

/**
 * Parse one line from the openvpn `--management` channel.
 *
 * Two notification shapes we care about:
 *   `>STATE:<ts>,CONNECTED,SUCCESS,<vpn-ip>,<remote-ip>,<remote-port>,<local-ip>,<local-port>`
 *   `>BYTECOUNT:<rx>,<tx>`
 */
function parseManagementLine(line: string, live: RunningProc): void {
  if (line.startsWith(">STATE:")) {
    const parts = line.slice(7).split(",");
    // parts: [ts, state, detail, local-ip-on-vpn, ...]
    const state = parts[1] ?? "";
    const vpnIp = parts[3] ?? "";
    if (state === "CONNECTED") {
      live.initialized = true;
      live.lastHeartbeatAt = Date.now();
      if (vpnIp && /^\d{1,3}(\.\d{1,3}){3}$/.test(vpnIp)) {
        live.assignedIp = vpnIp;
      }
    } else if (state === "RECONNECTING" || state === "EXITING") {
      live.initialized = false;
    }
    return;
  }
  if (line.startsWith(">BYTECOUNT:")) {
    // Every bytecount tick (5s above) counts as a live keepalive.
    live.lastHeartbeatAt = Date.now();
    return;
  }
}

/**
 * Spawn openvpn.exe with the .ovpn at `configPath`. Returns once the
 * child process has launched (does NOT wait for the tunnel to come up —
 * the caller polls `vpnStatus()` for that). Throws if spawn fails
 * synchronously (ENOENT, EACCES).
 */
async function spawnOpenvpn(configPath: string): Promise<RunningProc> {
  const exe = openvpnPath();
  const managementPort = await pickManagementPort();
  // Tee openvpn's full stdout/stderr to a rotating log file under
  // APPDATA so the operator (and we, in error messages) can inspect
  // exactly what the daemon saw — TLS handshake details, push pull,
  // route negotiation, etc. The file is also surfaced in the timeout
  // error message so non-technical users can find it without us
  // describing the path.
  const logPath = openvpnLogPath();
  try {
    await fs.mkdir(path.dirname(logPath), { recursive: true });
    // Truncate on each connect so the file always shows the LATEST
    // session — keeps it small and avoids "wait, which run was this?".
    await fs.writeFile(logPath, `# rud1-desktop openvpn log — ${new Date().toISOString()}\n`, { encoding: "utf8" });
  } catch {
    /* best-effort — a missing log file isn't fatal, the in-memory ring still serves */
  }
  const args = [
    "--config", configPath,
    "--dev-node", TUNNEL_NAME,
    "--management", MANAGEMENT_HOST, String(managementPort),
    // No --management-hold: it gates startup on a "hold release" reply
    // from our side, and an intermittent timing bug where the reply
    // didn't reach openvpn left the tunnel wedged in "waiting…" state
    // indefinitely. Without hold, openvpn proceeds directly to the TLS
    // handshake; we still attach the management socket in the background
    // for state + bytecount notifications (we just don't gate on it).
    //
    // No --management-query-passwords either: our .ovpn ships inline
    // certs with an unencrypted private key, so there's never a password
    // to query. The flag is a no-op for us and removing it shrinks the
    // surface area for management-socket weirdness.
    // verb 4 gives us TLS handshake detail without the cleartext key
    // material that verb 6+ leaks. Useful when diagnosing connect timeouts.
    "--verb", "4",
  ];
  // The bundled DLLs live next to openvpn.exe; spawn with that directory
  // as cwd so libssl / libcrypto resolve via the binary's import table
  // search order (the EXE's own directory wins over PATH).
  const cwd = process.platform === "win32" ? openvpnBundledDir() : undefined;
  let proc: ChildProcess;
  try {
    proc = spawn(exe, args, {
      windowsHide: true,
      cwd: cwd && require("fs").existsSync(cwd) ? cwd : undefined,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new OpenVpnMissingError();
    }
    throw err;
  }
  const live: RunningProc = {
    proc,
    managementPort,
    assignedIp: null,
    lastHeartbeatAt: 0,
    initialized: false,
    lastErrorLine: null,
    logRing: [],
  };

  function recordLine(line: string): void {
    if (!line) return;
    live.logRing.push(line);
    if (live.logRing.length > LOG_RING_SIZE) {
      live.logRing.splice(0, live.logRing.length - LOG_RING_SIZE);
    }
    // Tee to disk. Best-effort — disk failure shouldn't kill the tunnel.
    void fs.appendFile(logPath, line + "\n", { encoding: "utf8" }).catch(() => { /* ignore */ });
  }

  // stdout scraping for the coarse-grained "initialization completed" /
  // "auth failed" events plus the full ring + log file teeing. We don't
  // tear down on AUTH_FAILED here — the child process exits non-zero on
  // its own and our exit handler picks up the failure.
  if (proc.stdout) {
    proc.stdout.setEncoding("utf8");
    proc.stdout.on("data", (chunk: string) => {
      for (const rawLine of chunk.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line) continue;
        recordLine(line);
        if (line.includes("Initialization Sequence Completed")) {
          live.initialized = true;
          live.lastHeartbeatAt = Date.now();
        } else if (/(AUTH_FAILED|TLS Error|Cannot resolve host|All TAP-Win32 adapters)/i.test(line)) {
          live.lastErrorLine = line.slice(0, 240);
        } else if (line.includes("Inactivity timeout")) {
          live.initialized = false;
        } else if (line.startsWith("PUSH:")) {
          // First push from the server lands the assigned IP. We also
          // pick it up from the management socket — duplicate work is
          // fine, whichever lands first wins.
          const m = line.match(/ifconfig\s+(\d{1,3}(?:\.\d{1,3}){3})/);
          if (m) live.assignedIp = m[1] ?? null;
        }
      }
    });
  }
  if (proc.stderr) {
    proc.stderr.setEncoding("utf8");
    proc.stderr.on("data", (chunk: string) => {
      for (const rawLine of chunk.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line) continue;
        recordLine("[stderr] " + line);
        live.lastErrorLine = line.slice(0, 240);
      }
    });
  }
  proc.on("exit", () => {
    // Record the disconnect timestamp so vpnStatus() reports an accurate
    // "Last disconnected at" instead of a stale value from a prior session.
    if (running === live) {
      running = null;
      lastDisconnectedAt = Date.now();
    }
  });
  return live;
}

/**
 * Path to the rotating openvpn session log. Lives under APPDATA so the
 * user can open it with Notepad without us having to surface a chooser.
 */
export function openvpnLogPath(): string {
  return path.join(app.getPath("userData"), "logs", "openvpn.log");
}

/**
 * Tear down the current openvpn process (if any). Sends SIGTERM (clean
 * exit on Unix; on Windows `--management-signal SIGTERM` would be cleaner
 * but `proc.kill()` translates to a `TerminateProcess` which the child's
 * `service-wrapper` handler treats as a hard stop — the TAP adapter is
 * released either way).
 */
async function killRunning(): Promise<void> {
  if (!running) return;
  const live = running;
  const pid = live.proc.pid;
  try {
    live.proc.kill();
  } catch {
    /* already dead */
  }
  // Wait up to 3s for the child to exit. If it hangs, escalate to
  // SIGKILL — leaving an orphan openvpn around holds the TAP adapter
  // hostage and prevents the next install.
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      try { live.proc.kill("SIGKILL"); } catch { /* ignore */ }
      resolve();
    }, 3_000);
    live.proc.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
  });
  // Defense-in-depth: on Windows, openvpn.exe sometimes survives the
  // parent's SIGTERM/SIGKILL when it's mid-TLS-renegotiation. Force a
  // taskkill of the actual PID if it's still alive. Safe to call when
  // it's already gone (taskkill returns non-zero, we ignore).
  if (process.platform === "win32" && typeof pid === "number") {
    try {
      await execFileAsync("taskkill.exe", ["/F", "/T", "/PID", String(pid)], {
        timeout: 5_000,
        windowsHide: true,
      });
    } catch {
      /* already gone or never existed */
    }
  }
  running = null;
}

/**
 * Synchronous best-effort tear-down for `app.on("exit", ...)`. The exit
 * event fires LAST in Electron's lifecycle and cannot run async code —
 * if the user hits Quit from the tray and openvpn is still alive, this
 * is the final hook that prevents an orphan.
 *
 * Best-effort: we don't wait for the child to actually die, just send the
 * signal so the OS reaps it on our process exit. Use the async
 * `killRunning()` from before-quit for the proper teardown — this is the
 * "I missed before-quit somehow" safety net.
 */
export function killRunningSync(): void {
  if (!running) return;
  const live = running;
  try { live.proc.kill("SIGKILL"); } catch { /* already gone */ }
  if (process.platform === "win32" && typeof live.proc.pid === "number") {
    try {
      // Synchronous spawn — execFileSync would block forever if taskkill
      // hangs, so use spawnSync with a short timeout instead.
      const { spawnSync } = require("child_process") as typeof import("child_process");
      spawnSync("taskkill.exe", ["/F", "/T", "/PID", String(live.proc.pid)], {
        timeout: 2_000,
        windowsHide: true,
      });
    } catch {
      /* ignore */
    }
  }
  running = null;
}

/**
 * Public introspector — `true` when a tracked openvpn child is still in
 * the process table. UI uses this to disambiguate "connected" from "we
 * just sent connect and openvpn died silently".
 */
export function isOpenvpnAlive(): boolean {
  return running !== null;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Bring the tunnel up using the supplied `.ovpn` config blob. Persists the
 * config to `%APPDATA%/rud1-desktop/ovpn/` so a desktop restart can re-arm
 * the tunnel without bouncing through the cloud, then spawns openvpn.exe.
 *
 * On Windows: if the TAP-Windows V9 driver isn't installed, this throws
 * `TapDriverMissingError`. The IPC layer routes the throw into the iter-71
 * "TAP driver missing" CTA which prompts the user for elevation via a
 * Liquid Glass modal.
 */
export async function vpnConnect(ovpnConfig: string): Promise<void> {
  if (typeof ovpnConfig !== "string" || ovpnConfig.length === 0) {
    throw new Error("invalid .ovpn config");
  }
  if (!isBinaryAvailable("openvpn")) {
    throw new OpenVpnMissingError();
  }
  // Idempotent connect: tear down whatever's currently up before bringing
  // up the new config. The renderer always re-issues the freshest .ovpn,
  // and the server may have rotated certs.
  await killRunning();

  // Ensure both the TAP-Windows V9 kernel driver AND the actual rud1-tap
  // network adapter exist before spawning openvpn. Checking only the
  // driver is not enough — users can uninstall the adapter from Device
  // Manager (or another OpenVPN client can call `tapctl delete`) while
  // leaving the driver registered. Without this guard, openvpn.exe
  // launches, fails to open the device, and the management socket
  // emits a CONNECTED state from a stale push, so the UI claims
  // success while no real tunnel exists.
  const runtime: OpenVpnRuntimeStatus = await detectOpenVpnRuntime();
  if (!runtime.openvpnAvailable) {
    throw new OpenVpnMissingError();
  }
  if (process.platform === "win32" && !runtime.rud1TapAdapterPresent) {
    // ensureTapDriverInstalled triggers a UAC prompt and is idempotent
    // at both layers: it runs the driver MSI (no-op if already loaded)
    // and then `tapctl create --name rud1-tap` (no-op if the adapter
    // already exists). Either way it leaves a working rud1-tap on exit.
    try {
      await ensureTapDriverInstalled();
    } catch (err) {
      throw new TapDriverMissingError(
        err instanceof Error ? err.message : String(err),
      );
    }
    // Re-verify. If the adapter STILL isn't present we refuse to
    // spawn rather than reporting a phantom "connected" state.
    const post = await detectOpenVpnRuntime();
    if (!post.rud1TapAdapterPresent) {
      throw new TapDriverMissingError(
        "The rud1-tap network adapter could not be created. Open Device " +
          "Manager and verify the TAP-Windows V9 driver is installed, " +
          "then click Connect again.",
      );
    }
  }

  // Self-heal the adapter's user-visible description on every Connect.
  // An adapter created by an older rud1-desktop build (or by a manual
  // `tapctl create` from the user) carries the upstream default
  // "TAP-Windows Adapter V9" string, which is what TIA Portal / Codesys
  // / Set PG/PC Interface display. The rename script is a no-op when
  // DriverDesc is already "rud1", so calling it unconditionally only
  // costs a sub-second when there's actually work to do.
  if (process.platform === "win32") {
    try {
      await renameTapAdapterToRud1();
    } catch (err) {
      // Non-fatal — the VPN still works with the ugly name, so we never
      // block a Connect on rename failure.
      console.warn(
        "[vpn] adapter rename failed (non-fatal):",
        err instanceof Error ? err.message : err,
      );
    }
    // openvpn can't open a disabled adapter (CreateFile errno=2) even though
    // it still enumerates as present — ensure it's enabled before we spawn.
    // Fatal: a clear message here beats openvpn's cryptic open_tun failure.
    await ensureRud1TapEnabled();
  }

  const configPath = await writeOvpnConfig(ovpnConfig);

  const live = await spawnOpenvpn(configPath);
  running = live;
  lastOvpnConfig = ovpnConfig;

  // Attach to the management socket synchronously so we have state +
  // bytecount notifications by the time the renderer asks for status.
  // Without --management-hold there's no critical command we MUST send;
  // the wire-up is purely observability and failure to attach degrades
  // gracefully to stdout-only scraping.
  const sock = await attachManagementSocket(live.managementPort);
  if (sock && running === live) {
    wireManagementSocket(sock);
  }

  // Wait for the rising-edge `initialized` signal (set on stdout's
  // "Initialization Sequence Completed" line OR on a >STATE:CONNECTED
  // notification from the management socket). 25s covers a slow TLS
  // handshake over a marginal cellular uplink; failure beyond that is
  // almost always a configuration error worth surfacing.
  //
  // If the child process exits before we see init, that's also a
  // failure — propagate the captured last error line so the renderer
  // can show what openvpn complained about.
  const INIT_TIMEOUT_MS = 25_000;
  const startedAt = Date.now();
  const logPath = openvpnLogPath();
  const tailLog = (n = 12): string => {
    const ring = live.logRing.slice(-n);
    return ring.length ? "\n  " + ring.join("\n  ") : "";
  };
  await new Promise<void>((resolve, reject) => {
    const onExit = (code: number | null) => {
      const head = live.lastErrorLine
        ? `OpenVPN exited before initialization: ${live.lastErrorLine}`
        : `OpenVPN exited before initialization (code ${code ?? "?"})`;
      cleanup();
      reject(new Error(`${head}\n\nLast OpenVPN output:${tailLog()}\n\nFull log: ${logPath}`));
    };
    const onTick = () => {
      if (running !== live) {
        cleanup();
        reject(new Error("VPN connection was torn down before initialization"));
        return;
      }
      if (live.initialized) {
        cleanup();
        resolve();
        return;
      }
      if (Date.now() - startedAt >= INIT_TIMEOUT_MS) {
        cleanup();
        const head = live.lastErrorLine
          ? `Tunnel did not initialize within ${INIT_TIMEOUT_MS / 1000}s: ${live.lastErrorLine}`
          : `Tunnel did not initialize within ${INIT_TIMEOUT_MS / 1000}s. ` +
            `Most likely the OpenVPN server is unreachable, the .ovpn config is stale, ` +
            `or another process is holding the rud1-tap adapter.`;
        reject(new Error(`${head}\n\nLast OpenVPN output:${tailLog()}\n\nFull log: ${logPath}`));
        return;
      }
    };
    const timer = setInterval(onTick, 250);
    function cleanup() {
      clearInterval(timer);
      try { live.proc.off("exit", onExit); } catch { /* ignore */ }
    }
    live.proc.on("exit", onExit);
    // Run one immediate tick so we don't add 250ms latency when
    // initialization completes very fast (rare but possible on warm
    // sockets / local tests).
    onTick();
  }).catch(async (err) => {
    // Tear down the child so we don't leave an orphan openvpn.exe
    // owning the TAP adapter after a failed connect.
    await killRunning();
    throw err;
  });

  lastConnectedAt = Date.now();

  // APIPA fallback — fire-and-forget so the connect resolver returns now.
  void (async () => {
    try {
      const hint = parseLanFallbackHint(ovpnConfig);
      const result = await maybeApplyApipaFallback("rud1-tap", hint);
      if (result.applied) {
        console.info(
          `[vpn] APIPA fallback applied: ${result.finalIp} (reason: ${result.reason})`,
        );
      } else if (
        result.reason !== "dhcp-succeeded" &&
        result.reason !== "no-hint" &&
        result.reason !== "non-windows"
      ) {
        console.warn(`[vpn] APIPA fallback skipped: ${result.reason}`);
      }
    } catch (err) {
      console.warn(
        "[vpn] APIPA fallback errored (non-fatal):",
        err instanceof Error ? err.message : err,
      );
    }
  })();
}

export async function vpnDisconnect(): Promise<VpnDisconnectResult> {
  const uptimeMs = computeTunnelUptimeMs(
    running !== null,
    lastConnectedAt,
    Date.now(),
  );
  await killRunning();
  lastDisconnectedAt = Date.now();
  lastOvpnConfig = null;
  return { uptimeMs };
}

export async function vpnStatus(): Promise<VpnStatusResult> {
  const now = Date.now();
  const connected = running !== null && running.initialized;
  const ip = running?.assignedIp ?? undefined;
  const snapshot = snapshotFromState(now);
  const { handshakeStatus, handshakeAgeMs } = classifyHandshakeSnapshot(snapshot);
  return {
    connected,
    ...(ip ? { ip } : {}),
    lastConnectedAt: lastConnectedAt ? new Date(lastConnectedAt).toISOString() : null,
    lastDisconnectedAt: lastDisconnectedAt ? new Date(lastDisconnectedAt).toISOString() : null,
    tunnelUptimeMs: computeTunnelUptimeMs(connected, lastConnectedAt, now),
    handshakeStatus,
    handshakeAgeMs,
  };
}

/**
 * Returns a list of platform-relevant key-generation instructions. The
 * panel surfaces this as a hint when the operator wants to inspect the
 * cert chain. For OpenVPN this is informational only — certs come from
 * the cloud's CA via the `.ovpn` push.
 */
export function generateKeyPairInstructions(): string {
  return 'The desktop fetches a signed .ovpn from rud1.es; no local key generation is required.';
}

/**
 * Test-only hatch — exposes the tunnel-name validator + config parsers
 * so unit tests can exercise them directly without spawning a real
 * OpenVPN child. Keep this narrow: only pure helpers belong here.
 */
export const __test = {
  assertTunnelName,
  resolveConfigPath,
  parseWgShow: (stdout: string) => {
    // Compatibility shim used by the legacy unit tests — scrape
    // OpenVPN's stdout for the "Initialization Sequence Completed"
    // signal we report as `connected`.
    const connected = /Initialization Sequence Completed/i.test(stdout);
    const ipMatch = stdout.match(/ifconfig\s+(\d{1,3}(?:\.\d{1,3}){3})/);
    return ipMatch?.[1]
      ? { connected, ip: ipMatch[1] }
      : { connected };
  },
  parseNetshInterface: (stdout: string) => ({
    connected: /Connected/i.test(stdout),
  }),
  TUNNEL_NAME,
  TUNNEL_NAME_REGEX,
  parseManagementLine,
  snapshotFromState,
  defaultOvpnConfigPath,
};

void app; // silence unused-import lint when isPackaged path is unused.
