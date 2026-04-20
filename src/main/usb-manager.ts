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

// ─── Linux ────────────────────────────────────────────────────────────────────

async function attachLinux(host: string, busId: string): Promise<number> {
  const usbip = usbipPath();
  const { stdout } = await execFileAsync(usbip, ["attach", "-h", host, "-b", busId]);
  // usbip outputs: "usbip: info: Port 0 imported"
  const match = stdout.match(/Port\s+(\d+)/i);
  const port = match ? parseInt(match[1], 10) : 0;
  return port;
}

async function detachLinux(port: number): Promise<void> {
  const usbip = usbipPath();
  await execFileAsync(usbip, ["detach", "-p", String(port)]);
}

async function listLinux(): Promise<AttachedDevice[]> {
  const usbip = usbipPath();
  try {
    const { stdout } = await execFileAsync(usbip, ["port"]);
    const devices: AttachedDevice[] = [];
    const portRe = /Port\s+(\d+):\s+<Port in Use>\s+at\s+[\w.]+\s+speed.+\n.+\((\S+)\)\s+(\d+-[\d.]+)/gm;
    let m: RegExpExecArray | null;
    while ((m = portRe.exec(stdout)) !== null) {
      devices.push({ port: parseInt(m[1], 10), host: m[2], busId: m[3] });
    }
    return devices;
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
  if (process.platform === "win32") return attachWindows(host, busId);
  return attachLinux(host, busId);
}

export async function usbDetach(port: number): Promise<void> {
  if (process.platform === "win32") return detachWindows(port);
  return detachLinux(port);
}

export async function usbList(): Promise<AttachedDevice[]> {
  if (process.platform === "win32") return listWindows();
  return listLinux();
}
