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
import { isBinaryAvailable, usbipInstallerPath, usbipPath } from "./binary-helper";

const execFileAsync = promisify(execFile);

const USBIP_WIN_INSTALL_URL = "https://github.com/vadimgrn/usbip-win2/releases";

/**
 * Stable error class for "USB/IP for Windows isn't installed" so the
 * IPC handler can recognise it and surface a structured response with
 * the bundled-installer path. The renderer turns that into an "Install
 * USB/IP" button instead of the generic Error.message string.
 *
 * On Linux/macOS we never bundle anything — the `wireguard-tools` /
 * `usbip-utils` packages are expected to be on PATH — so the message
 * is just an installation hint pointing at the platform package.
 */
export class UsbipMissingError extends Error {
  /** When non-null, the absolute path to the bundled NSIS installer
   *  the renderer should offer to launch (Windows only). */
  readonly installerPath: string | null;

  constructor(installerPath: string | null = null) {
    const isWin = process.platform === "win32";
    const platformHint = isWin
      ? `Install usbip-win2 (${USBIP_WIN_INSTALL_URL}) — the bundled installer runs the kernel driver setup.`
      : process.platform === "darwin"
      ? "Install usbip via Homebrew (it ships in linux-tools or build from source)."
      : "Install usbip-utils via your distro package manager (apt/dnf/pacman).";
    super(`USB/IP tools not found. ${platformHint}`);
    this.name = "UsbipMissingError";
    this.installerPath = installerPath;
  }
}

/**
 * Preflight gate. Refuses to spawn anything when:
 *   - the platform binary lookup can't find usbip (PATH + bundled +
 *     well-known install dirs all empty), OR
 *   - on Windows specifically, the resolved usbip.exe path is bare
 *     (binary-helper falls back to the literal "usbip" string when
 *     nothing matched). A bare path means PATH lookup will be tried,
 *     and if that fails too the spawn surfaces ENOENT — but with a
 *     missing kernel driver `usbip.exe` could exist while still
 *     refusing to attach. That's a different failure mode handled
 *     by the per-call error parser below.
 */
function ensureUsbipAvailable(): void {
  if (!isBinaryAvailable("usbip")) {
    throw new UsbipMissingError(usbipInstallerPath());
  }
}

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

/**
 * Patterns that mean "this exact bus is already attached" — surfaced
 * as a non-error so the panel doesn't punish the user for clicking
 * Attach twice. Each platform's wording differs; we match a common
 * enough substring on each. Matching is case-insensitive.
 */
const ALREADY_ATTACHED_PATTERNS: readonly RegExp[] = [
  /already attached/i,
  /already imported/i,
  /already in use/i,
  /device busy/i,
];

/**
 * Patterns that mean "the kernel driver isn't installed / loaded".
 * Distinct from "binary missing" — usbip.exe runs but cannot reach
 * the VHCI driver. Promote to UsbipMissingError so the renderer
 * surfaces the bundled-installer call-to-action.
 */
const DRIVER_MISSING_PATTERNS: readonly RegExp[] = [
  /vhci/i,
  /driver.*not.*(loaded|installed)/i,
  /could not open.*device/i,
];

function isAlreadyAttachedError(msg: string): boolean {
  return ALREADY_ATTACHED_PATTERNS.some((re) => re.test(msg));
}

function isDriverMissingError(msg: string): boolean {
  return DRIVER_MISSING_PATTERNS.some((re) => re.test(msg));
}

export async function usbAttach(host: string, busId: string): Promise<number> {
  assertHost(host);
  assertBusId(busId);
  ensureUsbipAvailable();
  try {
    if (process.platform === "win32") return await attachWindows(host, busId);
    return await attachLinux(host, busId);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (isAlreadyAttachedError(msg)) {
      // Idempotent: a second click after the panel reloaded shouldn't
      // explode. Return port 0 — the kernel knows the real one, but
      // the renderer just needs *some* truthy value to track state.
      return 0;
    }
    if (isDriverMissingError(msg)) {
      throw new UsbipMissingError(usbipInstallerPath());
    }
    throw err;
  }
}

export async function usbDetach(port: number): Promise<void> {
  assertPort(port);
  ensureUsbipAvailable();
  try {
    if (process.platform === "win32") return await detachWindows(port);
    return await detachLinux(port);
  } catch (err) {
    const msg = err instanceof Error ? err.message.toLowerCase() : String(err);
    // Same idempotency principle: if the port wasn't attached, treat
    // detach as a no-op rather than surfacing an error.
    if (msg.includes("not exist") || msg.includes("not attached") || msg.includes("invalid port")) {
      return;
    }
    throw err;
  }
}

export async function usbList(): Promise<AttachedDevice[]> {
  if (process.platform === "win32") return listWindows();
  return listLinux();
}

/** True when usbip is reachable from this app (bundled or system). */
export function isUsbipInstalled(): boolean {
  return isBinaryAvailable("usbip");
}

/** Bundled installer path, or null when not bundled / non-Windows. */
export function getUsbipInstallerPath(): string | null {
  return usbipInstallerPath();
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
