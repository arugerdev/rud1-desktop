/**
 * Network diagnostics manager.
 *
 * Runs lightweight, read-only OS probes so the remote dashboard can verify
 * that LAN subnets exposed by a Pi (via the rud1-fw LAN routing feature)
 * are actually reachable through the WireGuard tunnel from the operator's
 * machine. All commands are whitelisted and arguments are validated before
 * being passed to execFile so we never invoke a shell.
 *
 * Exposed probes:
 *   ping(host)       — 3 ICMP echoes, returns avg RTT (ms) + packet loss
 *   interfaces()     — local NIC enumeration with IPv4 addresses & CIDR
 *   resolveRoute(ip) — which local interface would egress packets to <ip>
 */

import { execFile } from "child_process";
import { promisify } from "util";
import os from "os";

const execFileAsync = promisify(execFile);

const HOST_REGEX = /^[a-zA-Z0-9.\-:]{1,253}$/;
const IP_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

export interface PingResult {
  host: string;
  alive: boolean;
  avgRttMs: number | null;
  lossPct: number;
  raw: string;
}

export interface InterfaceInfo {
  name: string;
  mac: string;
  addresses: { address: string; cidr: string | null; family: "IPv4" | "IPv6" }[];
  up: boolean;
  internal: boolean;
}

export interface RouteInfo {
  destination: string;
  iface: string | null;
  gateway: string | null;
  raw: string;
}

function assertHost(host: string): void {
  if (typeof host !== "string" || !HOST_REGEX.test(host)) {
    throw new Error("invalid host");
  }
}

function assertIp(ip: string): void {
  if (typeof ip !== "string" || !IP_REGEX.test(ip)) {
    throw new Error("invalid ip");
  }
}

export async function ping(host: string): Promise<PingResult> {
  assertHost(host);
  const isWin = process.platform === "win32";
  const args = isWin
    ? ["-n", "3", "-w", "1500", host]
    : ["-c", "3", "-W", "2", host];
  let raw = "";
  try {
    const { stdout, stderr } = await execFileAsync("ping", args, {
      timeout: 8_000,
      windowsHide: true,
    });
    raw = (stdout || "") + (stderr || "");
  } catch (err: unknown) {
    const maybe = err as { stdout?: string; stderr?: string };
    raw = (maybe?.stdout || "") + (maybe?.stderr || "");
  }
  return parsePing(host, raw);
}

function parsePing(host: string, raw: string): PingResult {
  const lossMatch = raw.match(/(\d+(?:\.\d+)?)\s*%\s*(?:packet\s*)?loss/i);
  const lossPct = lossMatch ? parseFloat(lossMatch[1]!) : 100;

  let avgRttMs: number | null = null;
  const linuxAvg = raw.match(/=\s*[\d.]+\/([\d.]+)\/[\d.]+(?:\/[\d.]+)?\s*ms/);
  if (linuxAvg) avgRttMs = parseFloat(linuxAvg[1]!);
  if (avgRttMs === null) {
    const winAvg = raw.match(/Average\s*=\s*(\d+)\s*ms/i);
    if (winAvg) avgRttMs = parseFloat(winAvg[1]!);
  }

  return {
    host,
    alive: lossPct < 100,
    avgRttMs,
    lossPct,
    raw: raw.slice(0, 4_000),
  };
}

export function interfaces(): InterfaceInfo[] {
  const raw = os.networkInterfaces();
  const out: InterfaceInfo[] = [];
  for (const [name, addrs] of Object.entries(raw)) {
    if (!addrs || addrs.length === 0) continue;
    const primary = addrs[0]!;
    out.push({
      name,
      mac: primary.mac,
      internal: primary.internal,
      up: true, // os.networkInterfaces() already filters down interfaces
      addresses: addrs.map((a) => ({
        address: a.address,
        cidr: a.cidr ?? null,
        family: a.family === "IPv4" ? "IPv4" : "IPv6",
      })),
    });
  }
  return out;
}

export async function resolveRoute(destination: string): Promise<RouteInfo> {
  assertIp(destination);
  const isWin = process.platform === "win32";
  try {
    if (isWin) {
      const { stdout } = await execFileAsync(
        "powershell.exe",
        [
          "-NoProfile",
          "-Command",
          `Find-NetRoute -RemoteIPAddress '${destination}' | ConvertTo-Json -Compress`,
        ],
        { timeout: 5_000, windowsHide: true },
      );
      return parseWinRoute(destination, stdout);
    } else {
      const { stdout } = await execFileAsync(
        "ip",
        ["route", "get", destination],
        { timeout: 5_000 },
      );
      return parseLinuxRoute(destination, stdout);
    }
  } catch (err) {
    return {
      destination,
      iface: null,
      gateway: null,
      raw: err instanceof Error ? err.message : String(err),
    };
  }
}

function parseLinuxRoute(destination: string, stdout: string): RouteInfo {
  const devMatch = stdout.match(/dev\s+(\S+)/);
  const viaMatch = stdout.match(/via\s+(\S+)/);
  return {
    destination,
    iface: devMatch?.[1] ?? null,
    gateway: viaMatch?.[1] ?? null,
    raw: stdout.slice(0, 2_000),
  };
}

function parseWinRoute(destination: string, stdout: string): RouteInfo {
  try {
    const parsed = JSON.parse(stdout.trim()) as unknown;
    // Find-NetRoute returns an array where element 0 is the IPAddress and
    // element 1 (or last) is the NetRoute. Take the first object with InterfaceAlias.
    const arr = Array.isArray(parsed) ? parsed : [parsed];
    for (const item of arr as { InterfaceAlias?: string; NextHop?: string }[]) {
      if (item?.InterfaceAlias) {
        return {
          destination,
          iface: item.InterfaceAlias,
          gateway: item.NextHop && item.NextHop !== "0.0.0.0" ? item.NextHop : null,
          raw: stdout.slice(0, 2_000),
        };
      }
    }
  } catch {
    // fall through
  }
  return { destination, iface: null, gateway: null, raw: stdout.slice(0, 2_000) };
}
