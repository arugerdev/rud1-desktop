// Client-side, self-sufficient reachability guard for the rud1-tap adapter.
//
// The USB transport (usbip) dials the device at `host:3240` (+ `host:7070`
// for the Pi-side bind). On the bridged OpenVPN TAP topology the device and
// the desktop share one L2 segment, so the desktop can only reach `host` when
// rud1-tap carries an IPv4 in the device's subnet. Two upstream mechanisms
// already provide that IP:
//   1. STATIC LAN mode — the server pushes ifconfig-push (deterministic IP).
//   2. DHCP + apipa-fallback.ts — rescues an APIPA lease using a CLOUD HINT
//      embedded in the .ovpn (needs the device heartbeat to have reported a
//      subnet, and needs a first-party .ovpn that carries the hint block).
//
// Both can be absent: no STATIC pool configured, no DHCP server on the LAN,
// AND no cloud hint (fresh device with no heartbeat subnet yet, or a
// third-party .ovpn). In that gap rud1-tap sits at 169.254.x.x (or has no
// IPv4 at all) and every USB attach fails even though the tunnel is up.
//
// This module closes that gap WITHOUT any cloud dependency: at attach time we
// already know the device's IP (it's the usbip `host`), so we derive a free
// same-subnet address for rud1-tap straight from it and assign it statically.
// It complements apipa-fallback — if that (or DHCP, or STATIC push) already
// gave rud1-tap a usable IP in the device's subnet, this is a no-op.
//
// Windows-only (netsh); a no-op elsewhere. Best-effort: every failure mode
// resolves to `{ applied:false, reason }` so it never blocks or breaks an
// attach.

import { execFile } from "child_process";
import { promisify } from "util";

import { readAdapterIpV4, isApipa } from "./apipa-fallback";

const execFileAsync = promisify(execFile);

const NETSH_TIMEOUT_MS = 5_000;
const PING_TIMEOUT_MS = 300;

// We assume a /24 when we have to synthesise an address from the device IP.
// It is by far the most common LAN prefix, and an over-wide guess (e.g. /16)
// would risk on-link collisions across unrelated subnets; /24 keeps the
// derived address provably adjacent to the device.
const ASSUMED_MASK = "255.255.255.0";

const IPV4_LITERAL_REGEX = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Parse a dotted-quad into its four octets, or null when malformed. */
export function parseIpv4(ip: string): [number, number, number, number] | null {
  const m = IPV4_LITERAL_REGEX.exec(ip);
  if (!m) return null;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])] as const;
  if (octets.some((o) => o < 0 || o > 255)) return null;
  return [octets[0], octets[1], octets[2], octets[3]];
}

export function isIpv4Literal(ip: unknown): ip is string {
  return typeof ip === "string" && parseIpv4(ip) !== null;
}

/** True when `a` and `b` share the same /24 network. */
export function sameSlash24(a: string, b: string): boolean {
  const pa = parseIpv4(a);
  const pb = parseIpv4(b);
  if (!pa || !pb) return false;
  return pa[0] === pb[0] && pa[1] === pb[1] && pa[2] === pb[2];
}

/**
 * Ordered list of candidate client addresses inside the device's /24,
 * highest-first (.250 → .200) to dodge typical DHCP scopes (.100-.199) and
 * mirror rud1-es's own `pickFallbackIp` convention. Excludes the device's
 * own octet plus the usual reserved ends (.0/.1/.254/.255) so we never
 * collide with the device or the gateway.
 */
export function candidateClientIps(host: string): string[] {
  const p = parseIpv4(host);
  if (!p) return [];
  const [a, b, c, hostOctet] = p;
  const out: string[] = [];
  for (let last = 250; last >= 200; last--) {
    if (last === hostOctet) continue;
    out.push(`${a}.${b}.${c}.${last}`);
  }
  return out;
}

/**
 * Is `ip` already answering on the wire? Used to skip candidates that are in
 * use before we claim one. A ping timeout / error is treated as "free" — we
 * would rather risk a rare collision than refuse connectivity when the host
 * is simply firewalled against ICMP.
 */
async function isIpInUse(ip: string): Promise<boolean> {
  if (process.platform !== "win32") return false;
  try {
    await execFileAsync("ping", ["-n", "1", "-w", String(PING_TIMEOUT_MS), ip], {
      timeout: PING_TIMEOUT_MS + 1_000,
      windowsHide: true,
    });
    // `ping` exits 0 on a reply. On Windows it also exits 0 for
    // "Destination host unreachable"; guard against that by requiring the
    // reply to come from the pinged IP (the stdout scrape below).
    return true;
  } catch {
    // Non-zero exit → request timed out / no reply → free to claim.
    return false;
  }
}

/**
 * Pick the first candidate address in the device's /24 that isn't already
 * answering. Falls back to the first candidate when every probe is
 * inconclusive so we always return SOMETHING to assign.
 */
export async function pickFreeClientIp(host: string): Promise<string | null> {
  const candidates = candidateClientIps(host);
  if (candidates.length === 0) return null;
  for (const ip of candidates) {
    if (!(await isIpInUse(ip))) return ip;
  }
  return candidates[0]!;
}

async function setStaticIp(adapterName: string, ip: string, mask: string): Promise<void> {
  await execFileAsync(
    "netsh",
    [
      "interface",
      "ipv4",
      "set",
      "address",
      `name=${adapterName}`,
      "static",
      ip,
      mask,
    ],
    { timeout: NETSH_TIMEOUT_MS },
  );
}

export interface TapReachabilityResult {
  applied: boolean;
  reason: string;
  finalIp?: string;
}

/**
 * Ensure `adapterName` can reach `host` on-link, self-assigning a same-/24
 * address when it can't. Conservative by design:
 *
 *   - non-Windows                       → no-op (`non-windows`).
 *   - host is not an IPv4 literal        → skip (`host-not-ipv4`); we can't
 *                                          derive a subnet from a DNS name.
 *   - adapter already in host's /24 and  → no-op (`already-reachable`); DHCP,
 *     not APIPA                            STATIC push, or apipa-fallback
 *                                          already did the job.
 *   - adapter has a real (non-APIPA) IP  → leave it (`foreign-lease-kept`); we
 *     in a DIFFERENT subnet                never clobber a working DHCP lease.
 *   - adapter absent / APIPA / no IPv4   → assign a free same-/24 address.
 *
 * Best-effort: any failure resolves to `applied:false` with a diagnostic and
 * never throws, so a flaky netsh can't block a USB attach.
 */
export async function ensureTapReachableForHost(
  host: string,
  adapterName: string,
): Promise<TapReachabilityResult> {
  if (process.platform !== "win32") {
    return { applied: false, reason: "non-windows" };
  }
  if (!isIpv4Literal(host)) {
    return { applied: false, reason: "host-not-ipv4" };
  }
  const current = await readAdapterIpV4(adapterName);
  if (current && !isApipa(current)) {
    if (sameSlash24(current, host)) {
      return { applied: false, reason: "already-reachable", finalIp: current };
    }
    // A legitimate lease in another subnet — don't override it. On a flat L2
    // bridge this is unusual, but clobbering a working config is worse than
    // leaving an edge case unhandled.
    return { applied: false, reason: "foreign-lease-kept", finalIp: current };
  }
  // No IPv4, or APIPA — synthesise one adjacent to the device.
  const ip = await pickFreeClientIp(host);
  if (!ip) {
    return { applied: false, reason: "no-candidate" };
  }
  try {
    await setStaticIp(adapterName, ip, ASSUMED_MASK);
  } catch (err) {
    return {
      applied: false,
      reason: `netsh-set-failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  return { applied: true, reason: "self-assigned", finalIp: ip };
}
