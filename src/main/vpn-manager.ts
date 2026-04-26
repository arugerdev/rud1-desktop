/**
 * WireGuard VPN manager.
 *
 * Abstracts platform differences:
 *   Windows  — uses the WireGuard tunnel service via wireguard.exe /installtunnelservice
 *   Linux    — uses wg-quick up/down (requires CAP_NET_ADMIN or sudo)
 *   macOS    — uses wg-quick (from Homebrew or bundled wireguard-go)
 *
 * The private key is generated on the client, never sent to the server.
 * The WireGuard config supplied here should have PrivateKey filled in.
 *
 * Security: the tunnel name forwarded to wg-quick/wireguard.exe/netsh is
 * validated against a strict regex (alphanumeric+underscore+dash, 1..15
 * chars — the Linux IFNAMSIZ limit minus NUL). The temp config file name
 * is derived from the tunnel name only, so path-traversal via `../..` is
 * impossible. `netsh` no longer runs through cmd.exe — we invoke it via
 * execFile with argv, not exec with a string.
 */

import { execFile } from "child_process";
import { promisify } from "util";
import fs from "fs/promises";
import os from "os";
import path from "path";
import { isBinaryAvailable, wgPath, wgQuickPath } from "./binary-helper";

const WIREGUARD_INSTALL_URL = "https://www.wireguard.com/install/";

/**
 * Stable error class so callers (the IPC handler in particular) can
 * recognise the "WireGuard isn't installed" failure mode without having
 * to string-match on the message. The message itself is what we
 * surface to the user — keep it actionable: name the missing component
 * AND the URL to install it from.
 */
export class WireguardMissingError extends Error {
  constructor(platform: NodeJS.Platform) {
    const installer =
      platform === "win32"
        ? "WireGuard for Windows"
        : platform === "darwin"
        ? "WireGuard for macOS"
        : "wireguard-tools";
    super(
      `${installer} is required but was not found. Install it from ${WIREGUARD_INSTALL_URL} and try again.`,
    );
    this.name = "WireguardMissingError";
  }
}

/**
 * Preflight: refuse to spawn anything when the platform's WireGuard
 * binary is missing. Without this, the spawn fails with the opaque
 * `spawn wireguard ENOENT` Node default — which is what the operator
 * was hitting in the first place. We resolve the binary path via the
 * same lookup the actual spawn uses, so this is the canonical "does
 * the binary exist" signal.
 */
function ensureWireguardAvailable(): void {
  if (process.platform === "win32") {
    if (!isBinaryAvailable("wireguard")) {
      throw new WireguardMissingError(process.platform);
    }
    return;
  }
  // Unix: wg-quick is the entrypoint for connect/disconnect, wg for status.
  if (!isBinaryAvailable("wg-quick") || !isBinaryAvailable("wg")) {
    throw new WireguardMissingError(process.platform);
  }
}

const execFileAsync = promisify(execFile);

// Linux IFNAMSIZ is 16 (15 chars + NUL). WireGuard interface names must
// match `^[a-zA-Z0-9_=+.-]{1,15}$` per the kernel module; we keep a
// stricter subset (no `=`/`+`) for safety — none of those are needed for
// the rud1-generated default `rud1` or any user-chosen name we'd ship.
const TUNNEL_NAME_REGEX = /^[a-zA-Z0-9_.\-]{1,15}$/;

const TUNNEL_NAME = "rud1";
let configFilePath: string | null = null;

export function validateTunnelName(name: unknown): name is string {
  return typeof name === "string" && TUNNEL_NAME_REGEX.test(name);
}

function assertTunnelName(name: unknown): asserts name is string {
  if (!validateTunnelName(name)) {
    throw new Error("invalid tunnel name");
  }
}

/**
 * Resolve the on-disk path for a tunnel's temp WireGuard config. Uses
 * only `os.tmpdir()` + the validated tunnel name — never accepts a
 * caller-supplied path, so traversal (`../etc/passwd.conf`) cannot
 * reach writeFile.
 */
export function resolveConfigPath(name: string): string {
  assertTunnelName(name);
  return path.join(os.tmpdir(), `${name}.conf`);
}

async function writeTempConfig(wgConfig: string): Promise<string> {
  const file = resolveConfigPath(TUNNEL_NAME);
  await fs.writeFile(file, wgConfig, { mode: 0o600 });
  configFilePath = file;
  return file;
}

async function removeTempConfig(): Promise<void> {
  if (configFilePath) {
    try { await fs.unlink(configFilePath); } catch { /* ignore */ }
    configFilePath = null;
  }
}

// ─── Parsers ──────────────────────────────────────────────────────────────────

/**
 * Parse `wg show <iface>` stdout. Returns `{connected, ip?}`. A tunnel is
 * considered connected only when a "latest handshake" line is present;
 * the optional `address: X.X.X.X` line (wg-quick wrappers on some distros)
 * is extracted when available.
 */
export function parseWgShow(stdout: string): { connected: boolean; ip?: string } {
  const connected = stdout.includes("latest handshake");
  const ipMatch = stdout.match(/address:\s+([\d.]+)/i);
  return ipMatch?.[1]
    ? { connected, ip: ipMatch[1] }
    : { connected };
}

/**
 * Parse `netsh interface show interface <name>` stdout. On Windows, a
 * value of "Connected" in the Connect state column signals the tunnel
 * is up; anything else counts as disconnected.
 */
export function parseNetshInterface(stdout: string): { connected: boolean } {
  return { connected: stdout.includes("Connected") };
}

// ─── Platform implementations ─────────────────────────────────────────────────

async function connectWindows(wgConfig: string): Promise<void> {
  const file = await writeTempConfig(wgConfig);
  const wireguard = wgQuickPath();
  // WireGuard for Windows registers the tunnel as a Windows service.
  // The flag is `/installtunnelservice <conf-path>` (NOT `/installtunnel` —
  // that's a phantom from older docs; `wireguard.exe` rejects it and
  // prints the help text). The tunnel name is derived from the config
  // filename (rud1.conf -> service name "WireGuardTunnel$rud1"), which
  // is why writeTempConfig pins the filename to TUNNEL_NAME.
  await execFileAsync(wireguard, ["/installtunnelservice", file]);
}

async function disconnectWindows(): Promise<void> {
  assertTunnelName(TUNNEL_NAME);
  const wireguard = wgQuickPath();
  // `/uninstalltunnelservice <tunnel-name>` — same pairing rule as install.
  await execFileAsync(wireguard, ["/uninstalltunnelservice", TUNNEL_NAME]);
  await removeTempConfig();
}

/** Probe whether the WireGuard tunnel is currently registered with the
 *  Service Control Manager. Locale-immune: relies on `sc.exe`'s exit
 *  code (0 = service exists, 1060 = ERROR_SERVICE_DOES_NOT_EXIST). The
 *  previous implementation lower-cased the error message and grepped
 *  for English substrings — Spanish Windows ships
 *  "El servicio especificado no existe como servicio instalado", which
 *  matched none of them, so a fresh install always blew up the connect
 *  flow with an "uninstall failed" error before the install ever ran. */
async function tunnelServiceExistsWindows(): Promise<boolean> {
  const serviceName = `WireGuardTunnel$${TUNNEL_NAME}`;
  try {
    await execFileAsync("sc.exe", ["query", serviceName], { windowsHide: true });
    return true;
  } catch {
    // execFileAsync rejects on any non-zero exit. The expected case here
    // is 1060 (service not installed); any other failure (SCM down,
    // sc.exe missing) is surfaced through the subsequent install path
    // which has its own error handling.
    return false;
  }
}

/** Best-effort teardown used by the idempotent connect path. On Windows
 *  we positively probe for the service before issuing the uninstall;
 *  on Unix wg-quick is already idempotent enough that we just swallow
 *  the well-known "is not a wireguard interface" string.
 *
 *  Windows-specific subtlety: `wireguard.exe /uninstalltunnelservice`
 *  returns synchronously, but the Service Control Manager keeps the
 *  service in DELETE_PENDING state for a short window while in-flight
 *  handles release. If the subsequent `/installtunnelservice` runs
 *  during that window, WireGuard rejects it with "Tunnel already
 *  installed and running" and the user gets no tunnel — exactly the
 *  bug the operator was hitting in the panel: click Connect, the
 *  status said "fresh install" because the panel hadn't surfaced the
 *  prior service, idempotent connect calls teardown → install in
 *  series, and the install crashed into the trailing handle. We poll
 *  `tunnelServiceExistsWindows` for up to 3 s after the uninstall so
 *  the install path sees a fully-flushed SCM state.
 */
async function teardownIfPresent(): Promise<void> {
  if (process.platform === "win32") {
    if (!(await tunnelServiceExistsWindows())) return;
    await disconnectWindows();
    // Wait for SCM to drop the DELETE_PENDING marker. 3s is generous
    // (typical case is <500ms) but bounded so a stuck service surfaces
    // as a clear timeout rather than a hang. After the budget elapses
    // we fall through and let `/installtunnelservice` fail loudly with
    // its own diagnostic — better than swallowing the timeout.
    const deadline = Date.now() + 3000;
    while (Date.now() < deadline) {
      if (!(await tunnelServiceExistsWindows())) return;
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    return;
  }
  try {
    await disconnectUnix();
  } catch (err) {
    const msg = err instanceof Error ? err.message.toLowerCase() : String(err);
    if (msg.includes("not a wireguard interface") || msg.includes("does not exist")) {
      return;
    }
    throw err;
  }
}

async function statusWindows(): Promise<{ connected: boolean; ip?: string }> {
  assertTunnelName(TUNNEL_NAME);
  // Two distinct questions the renderer mixes into one boolean:
  //
  //   (a) Does a tunnel SERVICE currently exist on this machine? The panel
  //       needs to know this on entry so it can offer Disconnect instead
  //       of Connect when the user lands on a session that already has a
  //       tunnel installed (e.g. the app was closed while the service
  //       stayed running, or the install succeeded but the page reloaded).
  //   (b) Has WireGuard handshaked successfully? Useful for diagnostics
  //       chips ("Tunnel up 12s") but NOT load-bearing for the disconnect
  //       button — a tunnel installed but never handshaked still needs
  //       to be uninstalled before a fresh connect.
  //
  // `sc.exe query` is the locale-immune source of truth for (a) — same
  // probe `tunnelServiceExistsWindows` uses for the teardown gate. We
  // promote it here so the renderer's `vpn:status` reflects "the OS has
  // a WireGuardTunnel$rud1 service" the moment the user opens the panel,
  // without waiting for a handshake. netsh remains as a secondary IP
  // probe but we no longer require it to flip `connected`.
  if (await tunnelServiceExistsWindows()) {
    // netsh interface show doesn't carry an IP for WireGuard tunnels —
    // they're not standard netsh-managed interfaces. Returning just
    // `connected: true` is enough: the renderer paints the device's
    // VPN IP from the cloud's `VpnConfig.address` (the canonical
    // allocation) rather than relying on the desktop bridge for it.
    return { connected: true };
  }
  return { connected: false };
}

async function connectUnix(wgConfig: string): Promise<void> {
  const file = await writeTempConfig(wgConfig);
  const wgQuick = wgQuickPath();
  await execFileAsync(wgQuick, ["up", file]);
}

async function disconnectUnix(): Promise<void> {
  assertTunnelName(TUNNEL_NAME);
  const wgQuick = wgQuickPath();
  if (configFilePath) {
    await execFileAsync(wgQuick, ["down", configFilePath]);
  } else {
    await execFileAsync(wgQuick, ["down", TUNNEL_NAME]);
  }
  await removeTempConfig();
}

async function statusUnix(): Promise<{ connected: boolean; ip?: string }> {
  assertTunnelName(TUNNEL_NAME);
  try {
    const wg = wgPath();
    const { stdout } = await execFileAsync(wg, ["show", TUNNEL_NAME]);
    // Same precondition as statusWindows: when `wg show <name>` returns
    // 0 the interface exists in the kernel — that's what the renderer
    // means by "connected" for purposes of choosing Connect vs
    // Disconnect. parseWgShow used to require a "latest handshake" line
    // which made an installed-but-unhandshaked tunnel report `false`,
    // and the panel kept offering Connect over a tunnel that already
    // existed → the next install collided with "Tunnel already
    // installed" on systems that re-use the wg interface name.
    const parsed = parseWgShow(stdout);
    return parsed.ip ? { connected: true, ip: parsed.ip } : { connected: true };
  } catch {
    // Non-zero from `wg show` means the interface isn't there — that's
    // the only case where we want to offer Connect.
    return { connected: false };
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

// Iter 57: lifecycle freshness signals. The renderer surfaces these next to
// the cloud's lan.lastAppliedAt chip so the operator gets symmetric
// "synced Xs ago" feedback on both sides of the tunnel — the Pi side
// (when LAN routing was re-applied) and the user side (when the desktop
// last installed/uninstalled the WG tunnel service). Module-scoped state
// is sufficient: there is exactly one rud1 tunnel per desktop instance
// and the renderer pulls via `vpn:status`.
let lastConnectedAt: number | null = null;
let lastDisconnectedAt: number | null = null;

/**
 * Test-only helper: reset the lifecycle freshness signals back to their
 * initial nulls. The module's only mutable state is two timestamps; vitest
 * `beforeEach`s use this to avoid one test bleeding state into the next.
 */
export function __resetVpnLifecycleStateForTests(): void {
  lastConnectedAt = null;
  lastDisconnectedAt = null;
}

export async function vpnConnect(wgConfig: string): Promise<void> {
  ensureWireguardAvailable();
  // Idempotent connect. Three reasons to tear down whatever's currently
  // installed before bringing up the new config:
  //
  //   1. The panel always generates a fresh keypair on click, so any
  //      previously-installed tunnel has a stale private key that won't
  //      handshake. WireGuard for Windows otherwise refuses with
  //      "Tunnel already installed and running".
  //   2. The user may have lost panel state (page reload, app restart)
  //      while the tunnel service is still up. A second click should
  //      reconcile, not error out.
  //   3. The peer config could have been re-issued by the cloud (e.g.
  //      device endpoint changed); rolling the service picks it up.
  await teardownIfPresent();
  if (process.platform === "win32") {
    try {
      await connectWindows(wgConfig);
    } catch (err) {
      // Defence in depth against the SCM DELETE_PENDING race: even with
      // teardownIfPresent's 3s flush window, a slow machine (or an SCM
      // backed up by an unrelated install) can still surface "Tunnel
      // already installed and running" on the very next install. Single
      // retry: tear down again, then install. If THAT still fails the
      // error propagates and the renderer surfaces the toast — at that
      // point we've spent ~6s on retry budget and something genuinely
      // odd is going on.
      const msg = err instanceof Error ? err.message : String(err);
      if (/already installed/i.test(msg)) {
        await teardownIfPresent();
        await connectWindows(wgConfig);
      } else {
        throw err;
      }
    }
  } else {
    await connectUnix(wgConfig);
  }
  // Stamp AFTER the platform-specific install resolves cleanly. Failure
  // paths must not move the freshness signal — the operator should see
  // "no successful install yet" rather than a misleading "synced 12s ago".
  lastConnectedAt = Date.now();
}

/**
 * Iter 59: result envelope for `vpnDisconnect`. Carries the captured
 * tunnel uptime (in ms) so the IPC layer can render a "Tunnel dropped
 * after 2h 14m" toast — gives the user a satisfying confirmation that
 * the tunnel was actually doing useful work, not just a generic "Tunnel
 * is down" message that's indistinguishable from a never-connected
 * fall-through. Null when there was no live connect stamp from this
 * session (e.g. teardown of a leftover service from a previous run).
 */
export interface VpnDisconnectResult {
  /** ms the tunnel was up before the disconnect succeeded, or null when
   *  we don't have a live connect stamp from this session. */
  uptimeMs: number | null;
}

export async function vpnDisconnect(): Promise<VpnDisconnectResult> {
  ensureWireguardAvailable();
  // Capture uptime BEFORE clearing state — we measure against the prior
  // connect stamp, then stomp the disconnect stamp afterwards. The
  // computation reuses the same pure helper as `vpnStatus` so the
  // semantics stay identical (null on missing/negative delta).
  const uptimeMs = computeTunnelUptimeMs(true, lastConnectedAt, Date.now());
  if (process.platform === "win32") {
    await disconnectWindows();
  } else {
    await disconnectUnix();
  }
  lastDisconnectedAt = Date.now();
  return { uptimeMs };
}

/**
 * Iter 59: compact uptime formatter. Mirrors the rud1-es `formatUptimeMs`
 * in connect-panel.tsx so the desktop's notification toast and the
 * renderer's chip read identically. Returns null for unrecoverable
 * inputs so callers can suppress the trailing "after ..." segment
 * rather than print "after NaNs".
 */
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

/**
 * Result of `vpnStatus()`. The lifecycle stamps are exported as ISO 8601
 * strings (UTC) so the renderer can format them with the same Date helpers
 * it uses for `lan.lastAppliedAt` from the cloud — keeps "synced Xs ago"
 * formatting consistent across the desktop UI.
 */
export interface VpnStatusResult {
  connected: boolean;
  ip?: string;
  /** ISO timestamp of the last successful `vpnConnect` (null until first run). */
  lastConnectedAt: string | null;
  /** ISO timestamp of the last successful `vpnDisconnect` (null until first run). */
  lastDisconnectedAt: string | null;
  /**
   * Iter 58: convenience derived field — `Date.now() - lastConnectedAt`
   * when the tunnel is currently connected AND we've stamped a connect
   * this session, otherwise null. Lets the renderer show
   * "Tunnel up 12m" without parsing the ISO stamps client-side.
   *
   * Three null cases:
   *   - `connected === false` (the disconnect path matters; uptime is moot)
   *   - `lastConnectedAt === null` (no connect attempted this session, but
   *     wg/netsh reports the tunnel up — typically a leftover service
   *     from a previous app run; we don't lie about uptime we can't measure)
   *   - clock skew makes the delta negative (we coerce to null rather
   *     than emit a misleading negative number)
   */
  tunnelUptimeMs: number | null;
}

/**
 * Iter 58: pure computation of the derived `tunnelUptimeMs`. Extracted
 * so unit tests can pin the contract without spawning wg/netsh — the
 * real `vpnStatus` uses platform-dependent shell-outs that the iter-19
 * module banner explicitly chose not to mock.
 *
 * Returns null whenever the tunnel is not currently up, when there's no
 * recorded connect stamp this session, or when the clock has drifted
 * backwards between the connect stamp and `nowMs` (a desktop machine
 * recovering from sleep can briefly jump backwards before NTP resyncs).
 */
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

export async function vpnStatus(): Promise<VpnStatusResult> {
  const platformStatus =
    process.platform === "win32" ? await statusWindows() : await statusUnix();
  return {
    ...platformStatus,
    lastConnectedAt: lastConnectedAt
      ? new Date(lastConnectedAt).toISOString()
      : null,
    lastDisconnectedAt: lastDisconnectedAt
      ? new Date(lastDisconnectedAt).toISOString()
      : null,
    tunnelUptimeMs: computeTunnelUptimeMs(
      platformStatus.connected,
      lastConnectedAt,
      Date.now(),
    ),
  };
}

export function generateKeyPairInstructions(): string {
  if (process.platform === "win32") {
    return 'wg genkey | tee priv.key | wg pubkey > pub.key';
  }
  return 'wg genkey | tee priv.key | wg pubkey';
}

// ─── Endpoint pre-flight ──────────────────────────────────────────────────────

/**
 * Pulls the `Endpoint = host:port` value out of a WireGuard config blob.
 * Returns null when no `[Peer]` block carries an endpoint, when the value is
 * blank, or when the line is malformed. The parser is permissive: it tolerates
 * inline comments (`# ...`), CRLF or LF line endings, leading whitespace, and
 * mixed-case keys.
 *
 * Used by the IPC layer to pre-flight the tunnel: we want to detect a CGNAT'd
 * peer endpoint BEFORE invoking `wireguard.exe /installtunnelservice`, so the
 * renderer can surface an actionable warning instead of letting the operator
 * stare at an interface that "just doesn't connect".
 */
export function parseEndpointFromConfig(wgConfig: string): string | null {
  if (typeof wgConfig !== "string" || wgConfig.length === 0) return null;
  const lines = wgConfig.split(/\r?\n/);
  for (const raw of lines) {
    // Strip inline comments and surrounding whitespace, then split on the
    // first `=` only — host:port may contain digits but never `=`.
    const trimmed = raw.replace(/[#;].*$/, "").trim();
    if (trimmed.length === 0) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 0) continue;
    const key = trimmed.slice(0, eq).trim().toLowerCase();
    if (key !== "endpoint") continue;
    const value = trimmed.slice(eq + 1).trim();
    if (value.length === 0) return null;
    return value;
  }
  return null;
}

const CGNAT_FIRST_OCTET = 100;
const CGNAT_SECOND_LO = 64;
const CGNAT_SECOND_HI = 127; // 100.64.0.0/10 = 100.64.0.0 .. 100.127.255.255

/**
 * Reports whether `host` (or "host:port") is an IPv4 literal inside the
 * RFC 6598 carrier-grade NAT range 100.64.0.0/10. We deliberately do NOT
 * resolve hostnames here — DNS in main is opt-in and a connect call should
 * not block on it. If the agent reports a DNS name as endpoint, we trust
 * the cloud-side CGNAT signal forwarded via the heartbeat instead.
 */
export function isCGNATEndpoint(endpoint: string | null | undefined): boolean {
  if (!endpoint) return false;
  // Strip an optional `:<port>` suffix. Bracketed IPv6 literals never trigger
  // this path — CGNAT is IPv4-only by definition.
  const colonIdx = endpoint.lastIndexOf(":");
  const host = colonIdx > 0 && !endpoint.includes("]")
    ? endpoint.slice(0, colonIdx)
    : endpoint;
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  const octets = parts.map((p) => Number(p));
  if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = octets;
  return a === CGNAT_FIRST_OCTET && b >= CGNAT_SECOND_LO && b <= CGNAT_SECOND_HI;
}

/**
 * Pre-flight inspection of a wg config that the IPC handler can fold into
 * its response so the renderer gets actionable hints alongside the
 * connect ack. Pure — no side effects, no I/O.
 */
export interface ConfigPreflight {
  endpoint: string | null;
  cgnat: boolean;
  hasEndpoint: boolean;
}

export function inspectConfig(wgConfig: string): ConfigPreflight {
  const endpoint = parseEndpointFromConfig(wgConfig);
  return {
    endpoint,
    hasEndpoint: !!endpoint,
    cgnat: isCGNATEndpoint(endpoint),
  };
}

/**
 * Test-only hatch — exposes the tunnel-name validator, the
 * wg/netsh parsers, and the config-path resolver so the unit tests
 * can exercise them directly without spawning a real WireGuard
 * process. Keep this export narrow: only pure helpers belong here.
 * Production callers must use the public API above.
 */
export const __test = {
  assertTunnelName,
  resolveConfigPath,
  parseWgShow,
  parseNetshInterface,
  TUNNEL_NAME,
  TUNNEL_NAME_REGEX,
};
