// On-link /32 route to a device's management address (rud1-fw `mgmtport`).
//
// The device carries a fixed 169.254.0.x on its bridge. A client whose rud1-tap
// is on APIPA reaches it natively (169.254/16 is on-link); a client with a
// customer-LAN lease or a STATIC-pool IP has no route to 169.254/16, so we pin
// a host route on the tap adapter. Routes only, never addresses: the adapter's
// IPv4 stays whatever DHCP / APIPA / the OpenVPN push decided.
//
// `store=active` keeps the Windows route out of the persistent store, so a
// crash or reboot leaves nothing behind. Tracked routes are removed on VPN
// disconnect and on quit anyway.

import { execFile } from "child_process";
import { promisify } from "util";

import { readAdapterIpV4, isApipa } from "./apipa-fallback";
import { isIpv4Literal } from "./tap-reachability";

const execFileAsync = promisify(execFile);
const CMD_TIMEOUT_MS = 5_000;
const ADAPTER_IP_POLL_MS = 1_000;

/** Default wait for rud1-tap to carry an IPv4 (DHCP lease or APIPA) before dialing. */
export const ADAPTER_IP_WAIT_MS = 30_000;

export type OnLinkRouteResult = {
  ok: boolean;
  /** true when the route was already present (idempotent add). */
  existed: boolean;
  error?: string;
};

/** Routes this process added and still owns, keyed `${adapter}|${ip}`. */
const tracked = new Map<string, { adapter: string; ip: string }>();

export function isLinkLocalIpv4(ip: string): boolean {
  return /^169\.254\.\d{1,3}\.\d{1,3}$/.test(ip);
}

/**
 * A host route is needed only when the target is link-local and the adapter
 * sits outside 169.254/16 (lease or pool IP). APIPA adapters are on-link.
 */
export function needsOnLinkRoute(host: string, adapterIp: string | null): boolean {
  if (!isIpv4Literal(host) || !isLinkLocalIpv4(host)) return false;
  if (!adapterIp) return false;
  return !isApipa(adapterIp);
}

export function buildAddRouteArgs(adapter: string, ip: string, platform = process.platform): string[] {
  switch (platform) {
    case "win32":
      return ["interface", "ipv4", "add", "route", `${ip}/32`, `interface=${adapter}`, "store=active"];
    case "darwin":
      return ["-n", "add", "-host", ip, "-interface", adapter];
    default:
      return ["route", "replace", `${ip}/32`, "dev", adapter];
  }
}

export function buildDeleteRouteArgs(adapter: string, ip: string, platform = process.platform): string[] {
  switch (platform) {
    case "win32":
      return ["interface", "ipv4", "delete", "route", `${ip}/32`, `interface=${adapter}`];
    case "darwin":
      return ["-n", "delete", "-host", ip, "-interface", adapter];
    default:
      return ["route", "del", `${ip}/32`, "dev", adapter];
  }
}

export function routeBinary(platform = process.platform): string {
  switch (platform) {
    case "win32":
      return "netsh";
    case "darwin":
      return "route";
    default:
      return "ip";
  }
}

/** netsh/ip/route all report an existing identical route as an error; treat it as success. */
export function isAlreadyExistsError(output: string): boolean {
  return /already exists|ya existe|existe ya|file exists|RTNETLINK answers: File exists|object already exists|El objeto ya existe/i.test(
    output,
  );
}

export async function ensureOnLinkRoute(adapter: string, ip: string): Promise<OnLinkRouteResult> {
  if (!isIpv4Literal(ip)) return { ok: false, existed: false, error: `not an IPv4 literal: ${ip}` };
  try {
    await execFileAsync(routeBinary(), buildAddRouteArgs(adapter, ip), { timeout: CMD_TIMEOUT_MS });
    tracked.set(`${adapter}|${ip}`, { adapter, ip });
    return { ok: true, existed: false };
  } catch (err) {
    const e = err as Error & { stdout?: string; stderr?: string };
    const out = `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message}`;
    if (isAlreadyExistsError(out)) {
      tracked.set(`${adapter}|${ip}`, { adapter, ip });
      return { ok: true, existed: true };
    }
    return { ok: false, existed: false, error: (e.stderr || e.stdout || e.message).trim() };
  }
}

export async function removeOnLinkRoute(adapter: string, ip: string): Promise<void> {
  tracked.delete(`${adapter}|${ip}`);
  if (!isIpv4Literal(ip)) return;
  try {
    await execFileAsync(routeBinary(), buildDeleteRouteArgs(adapter, ip), { timeout: CMD_TIMEOUT_MS });
  } catch {
    // Already gone (adapter down, reboot, manual cleanup) — nothing to do.
  }
}

/** Drops every route this process added. Best-effort; safe to call repeatedly. */
export async function removeTrackedRoutes(): Promise<number> {
  const entries = [...tracked.values()];
  for (const { adapter, ip } of entries) {
    await removeOnLinkRoute(adapter, ip);
  }
  return entries.length;
}

export function trackedRouteCount(): number {
  return tracked.size;
}

/**
 * Waits until the adapter carries an IPv4 (lease, pool push or APIPA). Returns
 * the address, or null on timeout / non-Windows (where we can't read it).
 */
export async function waitForAdapterIpv4(
  adapter: string,
  timeoutMs = ADAPTER_IP_WAIT_MS,
  sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
): Promise<string | null> {
  if (process.platform !== "win32") return null;
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const ip = await readAdapterIpV4(adapter);
    if (ip) return ip;
    if (Date.now() >= deadline) return null;
    await sleep(ADAPTER_IP_POLL_MS);
  }
}
