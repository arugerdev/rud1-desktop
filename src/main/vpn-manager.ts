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

/** Best-effort teardown used by the idempotent connect path. Swallows
 *  the "no such tunnel" error so a fresh device (no prior install)
 *  doesn't fail the precondition. Other errors propagate. */
async function teardownIfPresent(): Promise<void> {
  try {
    if (process.platform === "win32") {
      await disconnectWindows();
    } else {
      await disconnectUnix();
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message.toLowerCase() : String(err);
    // WireGuard for Windows: "Unable to open tunnel service" / "no such service"
    // wg-quick (Linux/Mac):  "is not a wireguard interface"
    // Either shape means "nothing to tear down" — safe to ignore.
    if (
      msg.includes("no such service") ||
      msg.includes("not a wireguard interface") ||
      msg.includes("does not exist") ||
      msg.includes("unable to open tunnel service") ||
      msg.includes("unable to find")
    ) {
      return;
    }
    throw err;
  }
}

async function statusWindows(): Promise<{ connected: boolean; ip?: string }> {
  assertTunnelName(TUNNEL_NAME);
  try {
    // execFile (no shell) — previously used `exec` with a quoted string,
    // which is a shell-parsed form. TUNNEL_NAME is hardcoded today, but
    // passing it as argv keeps us safe if it ever becomes dynamic.
    const { stdout } = await execFileAsync(
      "netsh",
      ["interface", "show", "interface", TUNNEL_NAME],
      { windowsHide: true },
    );
    return parseNetshInterface(stdout);
  } catch {
    return { connected: false };
  }
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
    return parseWgShow(stdout);
  } catch {
    return { connected: false };
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

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
  if (process.platform === "win32") return connectWindows(wgConfig);
  return connectUnix(wgConfig);
}

export async function vpnDisconnect(): Promise<void> {
  ensureWireguardAvailable();
  if (process.platform === "win32") return disconnectWindows();
  return disconnectUnix();
}

export async function vpnStatus(): Promise<{ connected: boolean; ip?: string }> {
  if (process.platform === "win32") return statusWindows();
  return statusUnix();
}

export function generateKeyPairInstructions(): string {
  if (process.platform === "win32") {
    return 'wg genkey | tee priv.key | wg pubkey > pub.key';
  }
  return 'wg genkey | tee priv.key | wg pubkey';
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
