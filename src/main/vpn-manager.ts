/**
 * WireGuard VPN manager.
 *
 * Abstracts platform differences:
 *   Windows  — uses the WireGuard tunnel service via wireguard.exe /installtunnel
 *   Linux    — uses wg-quick up/down (requires CAP_NET_ADMIN or sudo)
 *   macOS    — uses wg-quick (from Homebrew or bundled wireguard-go)
 *
 * The private key is generated on the client, never sent to the server.
 * The WireGuard config supplied here should have PrivateKey filled in.
 */

import { execFile, exec } from "child_process";
import { promisify } from "util";
import fs from "fs/promises";
import os from "os";
import path from "path";
import { wgPath, wgQuickPath } from "./binary-helper";

const execFileAsync = promisify(execFile);
const execAsync = promisify(exec);

const TUNNEL_NAME = "rud1";
let configFilePath: string | null = null;

async function writeTempConfig(wgConfig: string): Promise<string> {
  const dir = os.tmpdir();
  const file = path.join(dir, `${TUNNEL_NAME}.conf`);
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

// ─── Platform implementations ─────────────────────────────────────────────────

async function connectWindows(wgConfig: string): Promise<void> {
  const file = await writeTempConfig(wgConfig);
  const wireguard = wgQuickPath();
  // WireGuard Windows: installs a named tunnel service
  await execFileAsync(wireguard, ["/installtunnel", file]);
}

async function disconnectWindows(): Promise<void> {
  const wireguard = wgQuickPath();
  await execFileAsync(wireguard, ["/removetunnel", TUNNEL_NAME]);
  await removeTempConfig();
}

async function statusWindows(): Promise<{ connected: boolean; ip?: string }> {
  try {
    const { stdout } = await execAsync(`netsh interface show interface "${TUNNEL_NAME}"`);
    const connected = stdout.includes("Connected");
    return { connected };
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
  const wgQuick = wgQuickPath();
  if (configFilePath) {
    await execFileAsync(wgQuick, ["down", configFilePath]);
  } else {
    await execFileAsync(wgQuick, ["down", TUNNEL_NAME]);
  }
  await removeTempConfig();
}

async function statusUnix(): Promise<{ connected: boolean; ip?: string }> {
  try {
    const wg = wgPath();
    const { stdout } = await execFileAsync(wg, ["show", TUNNEL_NAME]);
    const connected = stdout.includes("latest handshake");
    const ipMatch = stdout.match(/address:\s+([\d.]+)/i);
    return { connected, ip: ipMatch?.[1] };
  } catch {
    return { connected: false };
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function vpnConnect(wgConfig: string): Promise<void> {
  if (process.platform === "win32") return connectWindows(wgConfig);
  return connectUnix(wgConfig);
}

export async function vpnDisconnect(): Promise<void> {
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
