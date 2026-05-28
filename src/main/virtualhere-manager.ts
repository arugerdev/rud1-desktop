// VirtualHere headless client orchestrator. Spawns vhclient.exe (or the
// equivalent binary on macOS/Linux) en background sin ventana ni tray,
// le envía comandos via -t "<cmd>" y parsea la salida estructurada.
//
// Comandos relevantes (https://www.virtualhere.com/client_command_line):
//   - LIST              → lista hubs descubiertos y devices
//   - USE,<address>      → attach (Windows monta vía WinUSB/usbser.sys)
//   - STOP USING,<addr>  → detach
//   - MANUAL HUB ADD,<host>:<port>  → fuerza descubrimiento de un server
//
// Free tier: 1 device a la vez. La UI bloquea el resto cuando hay uno
// attached.

import { execFile, spawn, ChildProcess } from "child_process";
import { promisify } from "util";

import { virtualHereClientPath } from "./binary-helper";

const execFileAsync = promisify(execFile);

export interface VirtualHereDevice {
  /** Dirección estable `<vendorId>:<productId>:<serial?>` o el address
   *  raw que VirtualHere expone (formato `<hubName>.<port>`). */
  address: string;
  vendorId: string;
  productId: string;
  serial?: string;
  productName?: string;
  vendorName?: string;
  inUse: boolean;
  /** True cuando ESTE cliente lo tiene attached. */
  inUseByThisClient: boolean;
}

export interface VirtualHereHub {
  /** Nombre arbitrario de servidor publicado por vhusbd (config ServerName). */
  serverName: string;
  /** host:port donde el server escucha. */
  endpoint: string;
  devices: VirtualHereDevice[];
}

export interface VirtualHereStatus {
  /** True cuando el binary está bundled. */
  binaryAvailable: boolean;
  /** True cuando el proceso del client está corriendo en background. */
  daemonRunning: boolean;
  hubs: VirtualHereHub[];
  /** Devices attached por este cliente; en free tier siempre length ≤ 1. */
  attached: VirtualHereDevice[];
  /** Cuántos devices simultáneos permite la licencia. Free = 1. */
  maxSimultaneousDevices: number;
}

// ─── Daemon lifecycle ─────────────────────────────────────────────────

let daemon: ChildProcess | null = null;

/**
 * Arranca el client en background. VirtualHere client en modo daemon
 * autodescubre hubs por broadcast UDP + persiste IPC para los comandos
 * -t "<cmd>". Llamar una vez al boot de rud1-desktop; idempotente.
 */
export function startVirtualHereDaemon(): { ok: boolean; error?: string } {
  if (daemon && !daemon.killed) return { ok: true };
  const binary = virtualHereClientPath();
  if (!binary) {
    return { ok: false, error: "vhclient binary missing — run fetch:virtualhere-win during build." };
  }
  try {
    daemon = spawn(binary, [], {
      windowsHide: true,
      stdio: ["ignore", "ignore", "ignore"],
      detached: false,
    });
    daemon.on("exit", () => {
      daemon = null;
    });
    return { ok: true };
  } catch (err) {
    daemon = null;
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

export function stopVirtualHereDaemon(): void {
  if (!daemon) return;
  try {
    daemon.kill();
  } catch {
    /* best-effort */
  }
  daemon = null;
}

export function isVirtualHereDaemonRunning(): boolean {
  return daemon !== null && !daemon.killed;
}

// ─── Command execution ────────────────────────────────────────────────

async function runCommand(cmd: string): Promise<string> {
  const binary = virtualHereClientPath();
  if (!binary) {
    throw new Error("vhclient binary missing");
  }
  const { stdout, stderr } = await execFileAsync(binary, ["-t", cmd], {
    windowsHide: true,
    timeout: 10_000,
    maxBuffer: 1_048_576,
  });
  if (stderr && stderr.trim().length > 0 && !stdout) {
    throw new Error(stderr.trim());
  }
  return stdout;
}

// ─── LIST parser ─────────────────────────────────────────────────────

/**
 * Parsea la salida de `vhclient -t LIST`. Formato típico:
 *
 *   VirtualHere Client (v5.6.5)
 *   ServerHub.local (192.168.1.10:7575)
 *     --> Arduino Uno (vendor 0x2a03 product 0x0043)
 *
 * VirtualHere no documenta un schema estricto y el formato cambia entre
 * versiones; el parser es defensivo y omite líneas que no matchea.
 */
export function parseListOutput(out: string): VirtualHereHub[] {
  const hubs: VirtualHereHub[] = [];
  let current: VirtualHereHub | null = null;

  for (const raw of out.split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (!line) continue;
    // Hub heading: `<name> (<host>:<port>)`
    const hubMatch = line.match(/^([^\s].*?)\s*\(([^)]+:\d+)\)\s*$/);
    if (hubMatch && !line.includes("vendor")) {
      current = {
        serverName: hubMatch[1]!.trim(),
        endpoint: hubMatch[2]!,
        devices: [],
      };
      hubs.push(current);
      continue;
    }
    if (!current) continue;
    // Device line: `--> <name> (vendor 0xVVVV product 0xPPPP[ serial=...])`
    const devMatch = line.match(
      /^\s*-+>\s*(.+?)\s*\(vendor\s+0x([0-9a-fA-F]+)\s+product\s+0x([0-9a-fA-F]+)(?:\s+serial=([^)]*))?\)(.*)$/,
    );
    if (devMatch) {
      const tail = devMatch[5] || "";
      const inUse = /\bin-use\b/i.test(tail) || /\bin use\b/i.test(tail);
      const inUseByThisClient = /by you/i.test(tail);
      current.devices.push({
        address: `${current.serverName}.${current.devices.length + 1}`,
        vendorId: devMatch[2]!.toLowerCase().padStart(4, "0"),
        productId: devMatch[3]!.toLowerCase().padStart(4, "0"),
        serial: devMatch[4]?.trim() || undefined,
        productName: devMatch[1]!.trim() || undefined,
        inUse,
        inUseByThisClient,
      });
      continue;
    }
  }
  return hubs;
}

export async function listVirtualHere(): Promise<VirtualHereHub[]> {
  const out = await runCommand("LIST");
  return parseListOutput(out);
}

// ─── USE / STOP USING ────────────────────────────────────────────────

export async function useDevice(address: string): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const out = await runCommand(`USE,${address}`);
    if (/IN USE BY ANOTHER CLIENT/i.test(out)) {
      return { ok: false, error: "Device in use by another client" };
    }
    if (/NO LICENSE AVAILABLE/i.test(out) || /maximum.*reached/i.test(out)) {
      return {
        ok: false,
        error: "VirtualHere free license allows 1 device at a time. Disconnect the other one first.",
      };
    }
    if (/USE failed/i.test(out)) {
      return { ok: false, error: out.trim() };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

export async function stopUsingDevice(address: string): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    await runCommand(`STOP USING,${address}`);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

// ─── Status snapshot ─────────────────────────────────────────────────

export async function statusSnapshot(): Promise<VirtualHereStatus> {
  const binary = virtualHereClientPath();
  if (!binary) {
    return {
      binaryAvailable: false,
      daemonRunning: false,
      hubs: [],
      attached: [],
      maxSimultaneousDevices: 1,
    };
  }
  let hubs: VirtualHereHub[] = [];
  try {
    hubs = await listVirtualHere();
  } catch {
    hubs = [];
  }
  const attached: VirtualHereDevice[] = [];
  for (const h of hubs) {
    for (const d of h.devices) {
      if (d.inUseByThisClient) attached.push(d);
    }
  }
  return {
    binaryAvailable: true,
    daemonRunning: isVirtualHereDaemonRunning(),
    hubs,
    attached,
    maxSimultaneousDevices: 1, // free tier
  };
}

/** Test-only — expone el parser puro. */
export const __test = { parseListOutput };
