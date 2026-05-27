// Windows DHCP client falls back to 169.254.x.x (link-local / APIPA) when no
// DHCP response arrives within ~30 s. On a bridged OpenVPN TAP the DHCP server
// is the customer-LAN router — if it's saturated or briefly unreachable when
// the tunnel comes up, the user ends up with an APIPA address that can't talk
// to anything on the bridge. This module reads cloud-injected hints from the
// .ovpn config comments and statically assigns a free IP from the LAN so the
// tunnel keeps working in DHCP-failure scenarios.
//
// Cloud-side hint format (emitted by rud1-es/ovpn-config.service.ts):
//   # rud1-lan-subnet: 192.168.0.0/24
//   # rud1-lan-gateway: 192.168.0.1        (optional)
//   # rud1-lan-fallback-ip: 192.168.0.250
//
// No-op on non-Windows (Linux/macOS use the OS's own dhclient/networkd which
// the user typically doesn't hit this race against, and netsh isn't available).

import { execFile } from "child_process";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

const APIPA_GRACE_MS = 15_000;
const NETSH_TIMEOUT_MS = 5_000;

export interface LanFallbackHint {
  subnet: string;
  gateway: string | null;
  fallbackIp: string;
}

export function parseLanFallbackHint(ovpnConfig: string): LanFallbackHint | null {
  let subnet: string | null = null;
  let gateway: string | null = null;
  let fallbackIp: string | null = null;
  for (const raw of ovpnConfig.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line.startsWith("#")) continue;
    const m = /^#\s*rud1-lan-([a-z-]+):\s*(.+?)\s*$/.exec(line);
    if (!m) continue;
    const value = m[2];
    switch (m[1]) {
      case "subnet":
        subnet = value;
        break;
      case "gateway":
        gateway = value;
        break;
      case "fallback-ip":
        fallbackIp = value;
        break;
    }
  }
  if (!subnet || !fallbackIp) return null;
  return { subnet, gateway, fallbackIp };
}

function cidrToMask(cidrPrefix: number): string {
  if (cidrPrefix < 0 || cidrPrefix > 32) return "255.255.255.0";
  const mask = (0xffffffff << (32 - cidrPrefix)) >>> 0;
  return [
    (mask >>> 24) & 0xff,
    (mask >>> 16) & 0xff,
    (mask >>> 8) & 0xff,
    mask & 0xff,
  ].join(".");
}

export async function readAdapterIpV4(adapterName: string): Promise<string | null> {
  if (process.platform !== "win32") return null;
  try {
    const { stdout } = await execFileAsync(
      "netsh",
      ["interface", "ipv4", "show", "addresses", `name=${adapterName}`],
      { timeout: NETSH_TIMEOUT_MS },
    );
    const m = /IP Address:\s*([\d.]+)/i.exec(stdout) ||
      /Dirección IP:\s*([\d.]+)/i.exec(stdout);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

export function isApipa(ip: string | null): boolean {
  return !!ip && /^169\.254\./.test(ip);
}

async function setStaticIp(
  adapterName: string,
  ip: string,
  mask: string,
  gateway: string | null,
): Promise<void> {
  const args = [
    "interface",
    "ipv4",
    "set",
    "address",
    `name=${adapterName}`,
    "static",
    ip,
    mask,
  ];
  if (gateway) args.push(gateway);
  await execFileAsync("netsh", args, { timeout: NETSH_TIMEOUT_MS });
}

export interface ApipaFallbackResult {
  applied: boolean;
  reason: string;
  finalIp?: string;
}

// Waits APIPA_GRACE_MS for DHCP, then statically assigns the hint IP if the
// adapter is still on 169.254.x.x. Best-effort: every failure mode falls back
// to "applied: false" with a diagnostic, so a missing hint or a wrong adapter
// name never blocks the calling connect path.
export async function maybeApplyApipaFallback(
  adapterName: string,
  hint: LanFallbackHint | null,
): Promise<ApipaFallbackResult> {
  if (process.platform !== "win32") {
    return { applied: false, reason: "non-windows" };
  }
  if (!hint) {
    return { applied: false, reason: "no-hint" };
  }
  // Give DHCP a real chance first — typical DHCP roundtrip is 1-3 s, but
  // bridge mode can queue offers behind ARP discovery on slow switches.
  await new Promise<void>((resolve) => setTimeout(resolve, APIPA_GRACE_MS));
  const current = await readAdapterIpV4(adapterName);
  if (!current) {
    return { applied: false, reason: "adapter-not-found" };
  }
  if (!isApipa(current)) {
    return { applied: false, reason: "dhcp-succeeded", finalIp: current };
  }
  const cidr = /\/(\d{1,2})$/.exec(hint.subnet);
  const mask = cidr ? cidrToMask(Number(cidr[1])) : "255.255.255.0";
  try {
    await setStaticIp(adapterName, hint.fallbackIp, mask, hint.gateway);
  } catch (err) {
    return {
      applied: false,
      reason: `netsh-set-failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  return {
    applied: true,
    reason: "apipa-replaced",
    finalIp: hint.fallbackIp,
  };
}
