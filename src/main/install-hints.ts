/**
 * Platform-aware "this piece is missing, here is how to get it" copy.
 *
 * On Windows everything ships inside the installer, so the hint is
 * "re-run the installer". On Linux and macOS nothing is bundled — the
 * OpenVPN and usbip binaries come from the distribution, and the useful
 * hint is the exact command for THAT distribution. Telling an Arch user
 * to download a Windows installer (which is what the old message did) is
 * a dead end.
 *
 * Distro detection reads /etc/os-release, the standard every modern
 * distribution ships. ID_LIKE covers the derivatives (Mint -> ubuntu,
 * EndeavourOS -> arch) without listing them one by one.
 */

import fs from "fs";

export type DistroFamily =
  | "arch"
  | "debian"
  | "fedora"
  | "suse"
  | "alpine"
  | "unknown";

/** Package names differ per family for usbip; openvpn is universal. */
export type SystemPackage = "openvpn" | "usbip";

const OPENVPN_DOWNLOAD_URL = "https://openvpn.net/community-downloads/";

/**
 * Pull the ID / ID_LIKE values out of an /etc/os-release body. Values may
 * be quoted and ID_LIKE may hold several space-separated ids.
 */
export function parseOsReleaseIds(content: string): string[] {
  const ids: string[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    const match = line.match(/^(ID|ID_LIKE)=(.*)$/);
    if (!match) continue;
    const value = (match[2] ?? "").trim().replace(/^["']|["']$/g, "");
    for (const part of value.split(/\s+/)) {
      const id = part.trim().toLowerCase();
      if (id) ids.push(id);
    }
  }
  return ids;
}

/** Map os-release ids onto the family whose package manager we know. */
export function classifyDistro(ids: readonly string[]): DistroFamily {
  for (const id of ids) {
    if (["arch", "archlinux", "manjaro", "endeavouros", "cachyos", "garuda"].includes(id)) {
      return "arch";
    }
    if (["debian", "ubuntu", "linuxmint", "pop", "raspbian", "elementary", "zorin"].includes(id)) {
      return "debian";
    }
    if (["fedora", "rhel", "centos", "rocky", "almalinux", "nobara"].includes(id)) {
      return "fedora";
    }
    if (id.startsWith("opensuse") || id === "suse" || id === "sles") return "suse";
    if (id === "alpine") return "alpine";
  }
  return "unknown";
}

let cachedFamily: DistroFamily | null = null;

/** Reads /etc/os-release once per process. Never throws. */
export function detectDistroFamily(): DistroFamily {
  if (cachedFamily) return cachedFamily;
  if (process.platform !== "linux") {
    cachedFamily = "unknown";
    return cachedFamily;
  }
  try {
    const content = fs.readFileSync("/etc/os-release", "utf8");
    cachedFamily = classifyDistro(parseOsReleaseIds(content));
  } catch {
    cachedFamily = "unknown";
  }
  return cachedFamily;
}

/** Test hatch: forget the cached /etc/os-release read. */
export function __resetDistroCacheForTests(): void {
  cachedFamily = null;
}

/**
 * The install command for a package on a family, or null when we don't
 * know the family — the caller then falls back to a generic sentence
 * instead of printing a command that won't exist.
 */
export function installCommand(
  pkg: SystemPackage,
  family: DistroFamily,
): string | null {
  switch (family) {
    case "arch":
      return `sudo pacman -S --needed ${pkg}`;
    case "debian":
      // Debian ships `usbip`; Ubuntu ships the same tool inside
      // linux-tools-generic. apt names the alternative when it misses.
      return `sudo apt install ${pkg}`;
    case "fedora":
      return `sudo dnf install ${pkg}`;
    case "suse":
      return `sudo zypper install ${pkg}`;
    case "alpine":
      return `sudo apk add ${pkg}`;
    case "unknown":
      return null;
  }
}

/**
 * Message for "OpenVPN is not installed". Built per platform so the
 * action is one the user can actually take where they are.
 */
export function openvpnMissingMessage(
  platform: NodeJS.Platform = process.platform,
  family: DistroFamily = detectDistroFamily(),
): string {
  if (platform === "win32") {
    return (
      `OpenVPN binary not found. Re-run the rud1 installer or download ` +
      `OpenVPN Community from ${OPENVPN_DOWNLOAD_URL} and try again.`
    );
  }
  if (platform === "darwin") {
    return (
      `OpenVPN is not installed. Install it with "brew install openvpn" ` +
      `and try again.`
    );
  }
  const cmd = installCommand("openvpn", family);
  return cmd
    ? `OpenVPN is not installed. Install it with "${cmd}" and try again.`
    : `OpenVPN is not installed. Install the "openvpn" package with your ` +
        `distribution's package manager and try again.`;
}

/** Same idea for the USB/IP client tools. */
export function usbipMissingHint(
  platform: NodeJS.Platform = process.platform,
  family: DistroFamily = detectDistroFamily(),
): string {
  if (platform === "darwin") {
    return "Install usbip via Homebrew (it ships in linux-tools or build from source).";
  }
  const cmd = installCommand("usbip", family);
  return cmd
    ? `Install it with "${cmd}" and try again.`
    : `Install the "usbip" package with your distribution's package manager.`;
}

/**
 * Message for "we need root and there is no way to ask for it": polkit
 * (pkexec) is missing, so we cannot pop the password dialog the way the
 * desktop normally does.
 */
export function pkexecMissingMessage(
  family: DistroFamily = detectDistroFamily(),
  platform: NodeJS.Platform = process.platform,
): string {
  if (platform === "darwin") {
    return (
      `rud1 needs administrator rights to create the VPN adapter and macOS ` +
      `has no way for the app to ask for them yet. Start rud1 from a ` +
      `terminal with sudo, or use the Windows or Linux build.`
    );
  }
  const cmd = installCommand("openvpn", family)?.replace(/openvpn$/, "polkit") ?? null;
  const install = cmd ? ` Install it with "${cmd}".` : "";
  return (
    `rud1 needs administrator rights to create the VPN adapter, but the ` +
    `system tool that asks for the password (pkexec, from polkit) is not ` +
    `installed.${install}`
  );
}
