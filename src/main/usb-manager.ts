/**
 * USB/IP client manager.
 *
 * Uses the usbip userspace tool to attach/detach USB devices exposed by
 * a remote host (typically a rud1 device running rud1-fw with USB/IP enabled).
 *
 * Linux is the primary supported platform. Windows support requires usbip-win
 * (https://github.com/vadimgrn/usbip-win2) to be bundled.
 *
 * Protocol: USB/IP (RFC 3538 / kernel.org usbip)
 * Default port: 3240
 *
 * Security: all user-supplied arguments (`host`, `busId`, `port`) are
 * validated with strict regexes BEFORE being forwarded to execFile, so
 * a crafted renderer message can never smuggle a flag (e.g. `busId="-h x"`)
 * or a shell metacharacter into the spawned usbip process. Guards throw
 * synchronously ahead of any spawn/fs call so a rejected input never
 * reaches the child_process binding at all.
 */

import { execFile } from "child_process";
import { promisify } from "util";
import { usbipPath } from "./binary-helper";

const execFileAsync = promisify(execFile);

export interface AttachedDevice {
  port: number;
  host: string;
  busId: string;
}

// ─── Argument validators ──────────────────────────────────────────────────────
//
// HOST_REGEX — accepts hostnames, IPv4 literals, and IPv6 literals (colon is
// whitelisted). Deliberately rejects spaces, shell metacharacters, path
// separators, URL schemes, and any character that would let a crafted value
// be interpreted as a usbip flag (no leading `-`).
//
// BUS_ID_REGEX — usbip bus IDs are of the form `<bus>-<port>[.<subport>...]`,
// e.g. `1-1`, `1-1.2`, `2-3.4.5`. Strict dotted/dash shape only.

const HOST_REGEX = /^[a-zA-Z0-9.\-:]{1,253}$/;
const BUS_ID_REGEX = /^[0-9]+-[0-9]+(?:\.[0-9]+)*$/;

export function validateHost(h: unknown): h is string {
  return typeof h === "string" && !h.startsWith("-") && HOST_REGEX.test(h);
}

export function validateBusId(b: unknown): b is string {
  return typeof b === "string" && BUS_ID_REGEX.test(b);
}

export function validatePort(p: unknown): p is number {
  return (
    typeof p === "number" &&
    Number.isInteger(p) &&
    p >= 0 &&
    p <= 65535
  );
}

function assertHost(host: unknown): asserts host is string {
  if (!validateHost(host)) {
    throw new Error("invalid host");
  }
}

function assertBusId(busId: unknown): asserts busId is string {
  if (!validateBusId(busId)) {
    throw new Error("invalid busId");
  }
}

function assertPort(port: unknown): asserts port is number {
  if (!validatePort(port)) {
    throw new Error("invalid port");
  }
}

// ─── Parsers ──────────────────────────────────────────────────────────────────

/**
 * Parse `usbip attach` stdout. Outputs `usbip: info: Port 0 imported` on
 * success; return the numeric port (0 on parse failure so the caller can
 * still surface the device as attached even when the port scrape misses).
 */
export function parseAttachPort(stdout: string): number {
  const match = stdout.match(/Port\s+(\d+)/i);
  return match ? parseInt(match[1]!, 10) : 0;
}

/**
 * Parse `usbip port` output into AttachedDevice rows. One entry per
 * port-in-use block. Tolerant of extra whitespace; skips unparseable
 * blocks silently (the returned list is a diagnostic view, not a
 * transactional source of truth).
 */
export function parseUsbipPort(stdout: string): AttachedDevice[] {
  const devices: AttachedDevice[] = [];
  const portRe = /Port\s+(\d+):\s+<Port in Use>\s+at\s+[\w.]+\s+speed.+\n.+\((\S+)\)\s+(\d+-[\d.]+)/gm;
  let m: RegExpExecArray | null;
  while ((m = portRe.exec(stdout)) !== null) {
    devices.push({
      port: parseInt(m[1]!, 10),
      host: m[2]!,
      busId: m[3]!,
    });
  }
  return devices;
}

// ─── Linux ────────────────────────────────────────────────────────────────────

async function attachLinux(host: string, busId: string): Promise<number> {
  const usbip = usbipPath();
  const { stdout } = await execFileAsync(usbip, ["attach", "-h", host, "-b", busId]);
  return parseAttachPort(stdout);
}

async function detachLinux(port: number): Promise<void> {
  const usbip = usbipPath();
  await execFileAsync(usbip, ["detach", "-p", String(port)]);
}

async function listLinux(): Promise<AttachedDevice[]> {
  const usbip = usbipPath();
  try {
    const { stdout } = await execFileAsync(usbip, ["port"]);
    return parseUsbipPort(stdout);
  } catch {
    return [];
  }
}

// ─── Windows (usbip-win) ──────────────────────────────────────────────────────

async function attachWindows(host: string, busId: string): Promise<number> {
  const usbip = usbipPath();
  await execFileAsync(usbip, ["attach", "-r", host, "-b", busId]);
  return 0; // usbip-win doesn't expose port numbers the same way
}

async function detachWindows(port: number): Promise<void> {
  const usbip = usbipPath();
  await execFileAsync(usbip, ["detach", "-p", String(port)]);
}

async function listWindows(): Promise<AttachedDevice[]> {
  return []; // usbip-win list format differs; implement as needed
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function usbAttach(host: string, busId: string): Promise<number> {
  assertHost(host);
  assertBusId(busId);
  if (process.platform === "win32") return attachWindows(host, busId);
  return attachLinux(host, busId);
}

export async function usbDetach(port: number): Promise<void> {
  assertPort(port);
  if (process.platform === "win32") return detachWindows(port);
  return detachLinux(port);
}

export async function usbList(): Promise<AttachedDevice[]> {
  if (process.platform === "win32") return listWindows();
  return listLinux();
}

/**
 * Test-only hatch — exposes internal validators, regexes, and parsers so
 * the unit tests can exercise them directly without invoking the real
 * usbip binary. Keep this export narrow: only pure helpers belong here.
 * Production callers must use the public API above.
 */
export const __test = {
  assertHost,
  assertBusId,
  assertPort,
  parseAttachPort,
  parseUsbipPort,
  HOST_REGEX,
  BUS_ID_REGEX,
};
