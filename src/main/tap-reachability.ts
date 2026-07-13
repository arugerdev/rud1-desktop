// Read-only reachability diagnostic for the rud1-tap adapter.
//
// The USB transport (usbip) dials the device at `host:3240` (+ `host:7070` for
// the Pi-side bind). Over the bridged OpenVPN TAP the desktop and the device
// share one L2 segment, so the desktop reaches `host` only when rud1-tap
// already carries a compatible IPv4. That address comes entirely from
// mechanisms this module does NOT touch:
//   • DHCP over the bridge (Ethernet present) — client and device get
//     same-subnet leases from the same customer LAN.
//   • Windows APIPA 169.254/16 (no DHCP) — meets the device's permanent
//     link-local floor (rud1-fw sets ipv4.link-local on br-rud1).
//   • OpenVPN STATIC push (STATIC LAN mode) — the server assigns the tap IP.
//
// This module used to SELF-ASSIGN a static /24 on rud1-tap when it looked
// unreachable. That was removed: the address was derived from the device IP,
// which can be stale (a previous Ethernet session's subnet), so it left a
// persistent wrong static on rud1-tap that then BLOCKED the link-local path —
// and it could fight the server's STATIC push. The desktop now NEVER mutates
// rud1-tap; it only observes and logs a reachability verdict so attach failures
// are diagnosable. Fixing the address is left to DHCP / APIPA / the server push.
//
// Windows-only assessment; elsewhere it reports "non-windows". Never throws.

import { readAdapterIpV4, isApipa } from "./apipa-fallback";

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

export interface TapReachabilityDiag {
  /** Best-effort: does rud1-tap's current addressing put `host` on-link? */
  likelyReachable: boolean;
  /** Short machine-readable classification, surfaced in the attach log. */
  reason: string;
  /** rud1-tap's current IPv4, or null when it has none / can't be read. */
  adapterIp: string | null;
}

/**
 * Classify whether rud1-tap can currently reach `host`, WITHOUT changing
 * anything. Pure observation — the result is for logging/diagnosis only.
 *
 * Reachable-on-paper cases:
 *   • link-local host + adapter on APIPA/169.254 (or no IPv4 yet) — both sit on
 *     the 169.254/16 link-local segment.
 *   • routable host + adapter in the same /24 — same customer-LAN subnet.
 *
 * Not-reachable cases (worth flagging when an attach then fails):
 *   • link-local host + adapter has a routable lease (no 169.254 to meet on).
 *   • routable host + adapter on APIPA / no IPv4 (mid-DHCP, or a subnet the
 *     tunnel doesn't carry).
 *   • routable host + adapter routable in a DIFFERENT subnet.
 */
export async function diagnoseTapReachability(
  host: string,
  adapterName: string,
): Promise<TapReachabilityDiag> {
  if (process.platform !== "win32") {
    return { likelyReachable: true, reason: "non-windows", adapterIp: null };
  }
  if (!isIpv4Literal(host)) {
    // A DNS-name host resolves via the normal stack; we can't reason about
    // on-link subnets, so don't flag it.
    return { likelyReachable: true, reason: "host-not-ipv4", adapterIp: null };
  }
  const current = await readAdapterIpV4(adapterName);

  if (isApipa(host)) {
    if (!current || isApipa(current)) {
      return { likelyReachable: true, reason: "link-local-both-169254", adapterIp: current };
    }
    return {
      likelyReachable: false,
      reason: "link-local-host-but-routable-client",
      adapterIp: current,
    };
  }

  // Routable host.
  if (!current) {
    return { likelyReachable: false, reason: "routable-host-no-adapter-ip", adapterIp: null };
  }
  if (isApipa(current)) {
    return { likelyReachable: false, reason: "routable-host-apipa-client", adapterIp: current };
  }
  if (sameSlash24(current, host)) {
    return { likelyReachable: true, reason: "same-subnet", adapterIp: current };
  }
  return { likelyReachable: false, reason: "different-subnet", adapterIp: current };
}
