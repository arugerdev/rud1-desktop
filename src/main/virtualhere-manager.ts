// VirtualHere headless orchestrator. Una sola instancia de vhui64.exe
// corre en background (windowsHide: true) y expone un named pipe local
// (\\.\pipe\vhclient en Windows, /tmp/vhclient en POSIX). Mandamos
// comandos por ese pipe — NUNCA via -t porque cada spawn -t levanta una
// instancia GUI que muestra modal "Aceptar".
//
// Comandos relevantes (https://www.virtualhere.com/client_api):
//   - LIST              → hubs descubiertos + devices
//   - USE,<address>     → attach
//   - STOP USING,<addr> → detach
//   - HELP              → lista de verbos
//
// Free tier: 1 device a la vez. La UI bloquea el resto.

import { spawn, ChildProcess } from "child_process";
import net from "net";

import { virtualHereClientPath } from "./binary-helper";
import {
  parseListOutput,
  type VirtualHereDevice,
  type VirtualHereHub,
} from "./virtualhere-parser";

export type { VirtualHereDevice, VirtualHereHub };

const PIPE_PATH =
  process.platform === "win32" ? "\\\\.\\pipe\\vhclient" : "/tmp/vhclient";

const PIPE_TIMEOUT_MS = 5_000;

export interface VirtualHereStatus {
  binaryAvailable: boolean;
  daemonRunning: boolean;
  hubs: VirtualHereHub[];
  attached: VirtualHereDevice[];
  maxSimultaneousDevices: number;
}

// ─── Daemon lifecycle ─────────────────────────────────────────────────

let daemon: ChildProcess | null = null;

export function startVirtualHereDaemon(): { ok: boolean; error?: string } {
  if (daemon && !daemon.killed) return { ok: true };
  const binary = virtualHereClientPath();
  if (!binary) {
    return {
      ok: false,
      error: "vhclient binary missing — run fetch:virtualhere-win during build.",
    };
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

// ─── Named pipe IPC ──────────────────────────────────────────────────

/**
 * Manda un comando al daemon vía named pipe. El protocolo VirtualHere es
 * petición + respuesta en un único stream: escribimos `<verbo>[,arg]\n`,
 * leemos hasta que el server cierra el lado escritura.
 *
 * Reintenta hasta 5s si el daemon aún no levantó el pipe (típico tras
 * spawn del proceso). Devuelve string crudo — el caller parsea según
 * el comando.
 */
async function sendPipeCommand(cmd: string): Promise<string> {
  const deadline = Date.now() + PIPE_TIMEOUT_MS;
  let lastErr: Error | null = null;
  while (Date.now() < deadline) {
    try {
      return await sendOnce(cmd);
    } catch (err) {
      lastErr = err instanceof Error ? err : new Error(String(err));
      // Pipe aún no existe: esperar 200ms y reintentar.
      if (lastErr.message.includes("ENOENT") || lastErr.message.includes("does not exist")) {
        await new Promise((r) => setTimeout(r, 200));
        continue;
      }
      throw lastErr;
    }
  }
  throw lastErr ?? new Error("vhclient pipe timeout");
}

function sendOnce(cmd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(PIPE_PATH);
    let buf = "";
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("pipe command timeout"));
    }, PIPE_TIMEOUT_MS);

    socket.on("connect", () => {
      socket.write(`${cmd}\n`);
    });
    socket.on("data", (chunk) => {
      buf += chunk.toString("utf8");
    });
    socket.on("end", () => {
      clearTimeout(timer);
      resolve(buf);
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

export async function listVirtualHere(): Promise<VirtualHereHub[]> {
  const out = await sendPipeCommand("LIST");
  return parseListOutput(out);
}

// ─── USE / STOP USING ────────────────────────────────────────────────

export async function useDevice(
  address: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const out = await sendPipeCommand(`USE,${address}`);
    const trimmed = out.trim();
    if (/^OK\b/i.test(trimmed)) return { ok: true };
    if (/^FAILED\b/i.test(trimmed)) {
      if (/license/i.test(trimmed) || /max/i.test(trimmed)) {
        return {
          ok: false,
          error: "VirtualHere free license allows 1 device at a time. Disconnect the other one first.",
        };
      }
      if (/in.?use/i.test(trimmed)) {
        return { ok: false, error: "Device in use by another client" };
      }
      return { ok: false, error: trimmed };
    }
    if (/^ERROR/i.test(trimmed)) {
      return { ok: false, error: trimmed.replace(/^ERROR:\s*/i, "") };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

export async function stopUsingDevice(
  address: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    const out = await sendPipeCommand(`STOP USING,${address}`);
    const trimmed = out.trim();
    if (/^OK\b/i.test(trimmed) || trimmed.length === 0) return { ok: true };
    if (/^FAILED\b/i.test(trimmed)) return { ok: false, error: trimmed };
    if (/^ERROR/i.test(trimmed)) {
      return { ok: false, error: trimmed.replace(/^ERROR:\s*/i, "") };
    }
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
    maxSimultaneousDevices: 1,
  };
}

