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
 *   ping(host)         — 3 ICMP echoes, returns avg RTT (ms) + packet loss
 *   interfaces()       — local NIC enumeration with IPv4 addresses & CIDR
 *   resolveRoute(ip)   — which local interface would egress packets to <ip>
 *   traceroute(host)   — hop-by-hop path with RTT per hop (max 15 hops)
 *   dnsLookup(host)    — A / AAAA / CNAME records via dns/promises
 */

import { execFile } from "child_process";
import { promisify } from "util";
import os from "os";
import { resolve4, resolve6, resolveCname } from "dns/promises";

const execFileAsync = promisify(execFile);

const HOST_REGEX = /^[a-zA-Z0-9.\-:]{1,253}$/;
const IP_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;
const HOSTNAME_REGEX = /^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const IPV6_REGEX = /^[0-9a-fA-F:]+$/;

export function validateHost(h: string): boolean {
  return typeof h === "string" && HOST_REGEX.test(h);
}

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

export interface Hop {
  index: number;
  host: string | null;
  rttMs: number | null;
}

export interface TracerouteResult {
  host: string;
  hops: Hop[];
  raw: string;
}

export interface TracerouteOptions {
  maxHops?: number;
}

export interface DnsLookupResult {
  hostname: string;
  a: string[];
  aaaa: string[];
  cname: string | null;
}

function assertHost(host: string): void {
  if (!validateHost(host)) {
    throw new Error("invalid host");
  }
}

function assertHostname(hostname: string): void {
  if (typeof hostname !== "string" || !HOSTNAME_REGEX.test(hostname)) {
    throw new Error("invalid hostname");
  }
  // Reject input that parses as an IP (v4 or v6) — dnsLookup only accepts names.
  if (IP_REGEX.test(hostname)) {
    throw new Error("invalid hostname: looks like IPv4");
  }
  if (hostname.includes(":") && IPV6_REGEX.test(hostname)) {
    throw new Error("invalid hostname: looks like IPv6");
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

export async function traceroute(
  host: string,
  _opts?: TracerouteOptions,
): Promise<TracerouteResult> {
  assertHost(host);
  const isWin = process.platform === "win32";
  const cmd = isWin ? "tracert" : "traceroute";
  const args = isWin
    ? ["-d", "-w", "2000", "-h", "15", host]
    : ["-q", "1", "-w", "2", "-m", "15", "-n", host];

  let raw = "";
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, {
      timeout: 20_000,
      windowsHide: true,
      maxBuffer: 1024 * 1024,
    });
    raw = (stdout || "") + (stderr || "");
  } catch (err: unknown) {
    const maybe = err as { stdout?: string; stderr?: string };
    raw = (maybe?.stdout || "") + (maybe?.stderr || "");
  }

  const hops = isWin ? parseWinTraceroute(raw) : parsePosixTraceroute(raw);
  return { host, hops, raw: raw.slice(0, 2_048) };
}

function parsePosixTraceroute(raw: string): Hop[] {
  const hops: Hop[] = [];
  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    // Example lines:
    //   " 1  192.168.1.1  1.234 ms"
    //   " 2  * * *"
    const m = line.match(/^\s*(\d+)\s+(.*)$/);
    if (!m) continue;
    const index = parseInt(m[1]!, 10);
    const rest = m[2]!.trim();
    if (/^\*(\s+\*)*$/.test(rest) || rest === "*") {
      hops.push({ index, host: null, rttMs: null });
      continue;
    }
    const ipMatch = rest.match(/((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*)/);
    const rttMatch = rest.match(/([\d.]+)\s*ms/);
    hops.push({
      index,
      host: ipMatch ? ipMatch[1]! : null,
      rttMs: rttMatch ? parseFloat(rttMatch[1]!) : null,
    });
  }
  return hops;
}

function parseWinTraceroute(raw: string): Hop[] {
  const hops: Hop[] = [];
  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    // Windows tracert lines look like:
    //   "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
    //   "  2     *        *        *     Request timed out."
    const m = line.match(/^\s*(\d+)\s+(.*)$/);
    if (!m) continue;
    const index = parseInt(m[1]!, 10);
    const rest = m[2]!;
    if (/Request timed out/i.test(rest) || /^(?:\s*\*\s*)+$/.test(rest.trim())) {
      hops.push({ index, host: null, rttMs: null });
      continue;
    }
    const ipMatch = rest.match(/((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+:[0-9a-fA-F:]*)\s*$/);
    // Collect RTT samples like "<1 ms", "12 ms", "123 ms"
    const rttSamples: number[] = [];
    const rttRegex = /(<\s*\d+|\d+)\s*ms/g;
    let rm: RegExpExecArray | null;
    while ((rm = rttRegex.exec(rest)) !== null) {
      const token = rm[1]!.replace(/</, "").trim();
      const v = parseFloat(token);
      if (!Number.isNaN(v)) rttSamples.push(v);
    }
    const rttMs = rttSamples.length
      ? rttSamples.reduce((a, b) => a + b, 0) / rttSamples.length
      : null;
    hops.push({
      index,
      host: ipMatch ? ipMatch[1]! : null,
      rttMs,
    });
  }
  return hops;
}

export async function dnsLookup(hostname: string): Promise<DnsLookupResult> {
  assertHostname(hostname);

  const withTimeout = <T>(p: Promise<T>, ms: number): Promise<T> => {
    return new Promise<T>((resolvePromise, rejectPromise) => {
      const timer = setTimeout(() => rejectPromise(new Error("dns timeout")), ms);
      p.then(
        (v) => {
          clearTimeout(timer);
          resolvePromise(v);
        },
        (e) => {
          clearTimeout(timer);
          rejectPromise(e);
        },
      );
    });
  };

  const safe = async <T>(p: Promise<T>, fallback: T): Promise<T> => {
    try {
      return await withTimeout(p, 5_000);
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code;
      if (code === "ENOTFOUND" || code === "ENODATA") {
        return fallback;
      }
      throw err;
    }
  };

  const [a, aaaa, cnameArr] = await Promise.all([
    safe<string[]>(resolve4(hostname), []),
    safe<string[]>(resolve6(hostname), []),
    safe<string[]>(resolveCname(hostname), []),
  ]);

  return {
    hostname,
    a,
    aaaa,
    cname: cnameArr.length > 0 ? cnameArr[0]! : null,
  };
}
