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

import { execFile, spawn, ChildProcess } from "child_process";
import * as net from "net";
import { promisify } from "util";

import { virtualHereClientPath } from "./binary-helper";
import {
  parseListOutput,
  type VirtualHereDevice,
  type VirtualHereHub,
} from "./virtualhere-parser";

export type { VirtualHereDevice, VirtualHereHub };

const execFileAsync = promisify(execFile);

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
//
// Modo app, no servicio. La doc oficial de VirtualHere especifica que el
// servicio se instala desde el menú "Right click USB Hubs → Install Client
// as a Service" del GUI — no existe flag CLI documentado para registrarlo.
// Spawneamos vhui64.exe como app normal y ocultamos la ventana principal
// con ShowWindow(SW_HIDE) via PowerShell. El tray icon de VirtualHere se
// queda visible (free tier no permite eliminarlo) pero NO hay ventana ni
// popup molesto al user.
//
// En POSIX el binario sí soporta -n para daemon mode sin UI.

let daemon: ChildProcess | null = null;

/**
 * Oculta la ventana principal de vhui64.exe usando Win32 ShowWindow.
 * Se llama después de spawn cuando la ventana ya existe (~1.5s típico).
 * Si la ventana no aparece a tiempo, simplemente loguea — no es fatal,
 * el operador podría ver la ventana brevemente.
 */
async function hideWindowsClientWindow(pid: number): Promise<void> {
  const psCmd = [
    "Add-Type -Name win -MemberDefinition '[DllImport(\"user32.dll\")] public static extern bool ShowWindow(int handle, int state);' -Namespace native -ErrorAction SilentlyContinue;",
    `$end = (Get-Date).AddSeconds(8);`,
    `while ((Get-Date) -lt $end) {`,
    `  $p = Get-Process -Id ${pid} -ErrorAction SilentlyContinue;`,
    `  if ($p -and $p.MainWindowHandle -ne 0) {`,
    `    [native.win]::ShowWindow($p.MainWindowHandle.ToInt32(), 0) | Out-Null;`,
    `    exit 0;`,
    `  }`,
    `  Start-Sleep -Milliseconds 200;`,
    `}`,
    `exit 1;`,
  ].join(" ");
  try {
    await execFileAsync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", psCmd],
      { windowsHide: true, timeout: 12_000 },
    );
  } catch {
    /* best-effort */
  }
}

export async function startVirtualHereDaemon(): Promise<{ ok: boolean; error?: string }> {
  if (daemon && !daemon.killed) return { ok: true };
  const binary = virtualHereClientPath();
  if (!binary) {
    return {
      ok: false,
      error: "vhclient binary missing — run fetch:virtualhere-win during build.",
    };
  }
  try {
    const args = process.platform === "win32" ? [] : ["-n"];
    daemon = spawn(binary, args, {
      windowsHide: true,
      stdio: ["ignore", "ignore", "ignore"],
      detached: false,
    });
    daemon.on("exit", () => {
      daemon = null;
    });
    if (process.platform === "win32" && daemon.pid) {
      // No await — corre en background mientras el resto del boot continúa.
      void hideWindowsClientWindow(daemon.pid);
    }
    return { ok: true };
  } catch (err) {
    daemon = null;
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

export async function stopVirtualHereDaemon(): Promise<void> {
  if (!daemon) return;
  try {
    daemon.kill();
  } catch {
    /* best-effort */
  }
  daemon = null;
}

export async function isVirtualHereDaemonRunning(): Promise<boolean> {
  return daemon !== null && !daemon.killed;
}

// ─── Diagnostic snapshot ─────────────────────────────────────────────
//
// Para que el operador pueda compartir el estado completo cuando algo
// no funciona y no tenemos forma de inspeccionarlo remotamente. Cada
// campo es independiente: un fallo en pipeRawOutput no impide reportar
// serviceRunning, etc.

export interface VirtualHereDebug {
  binaryPath: string | null;
  binaryExists: boolean;
  platform: string;
  serviceInstalled: boolean;
  serviceRunning: boolean;
  pipeReachable: boolean;
  pipeError?: string;
  pipeRawOutput?: string;
  parsedHubs: number;
  parsedDevices: number;
  serviceQueryRaw?: string;
}

export async function debugSnapshot(): Promise<VirtualHereDebug> {
  const binaryPath = virtualHereClientPath();
  const out: VirtualHereDebug = {
    binaryPath,
    binaryExists: Boolean(binaryPath),
    platform: process.platform,
    serviceInstalled: false,
    serviceRunning: false,
    pipeReachable: false,
    parsedHubs: 0,
    parsedDevices: 0,
  };
  out.serviceRunning = await isVirtualHereDaemonRunning();
  // Intentar leer el pipe aunque el servicio diga STOPPED — a veces
  // hay drift entre sc.exe y la realidad.
  try {
    const raw = await sendOnce("LIST");
    out.pipeReachable = true;
    out.pipeRawOutput = raw;
    const hubs = parseListOutput(raw);
    out.parsedHubs = hubs.length;
    out.parsedDevices = hubs.reduce((n, h) => n + h.devices.length, 0);
  } catch (err) {
    out.pipeError = err instanceof Error ? err.message : String(err);
  }
  return out;
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
  return process.platform === "win32"
    ? sendOnceWindowsPipe(cmd)
    : sendOnceUnixSocket(cmd);
}

// VirtualHere en Windows expone un named pipe en modo mensaje. Node `net`
// no negocia ese modo: el socket conecta pero nunca recibe data. PowerShell
// con System.IO.Pipes.NamedPipeClientStream sí maneja message-mode.
async function sendOnceWindowsPipe(cmd: string): Promise<string> {
  const escaped = cmd.replace(/'/g, "''");
  const psCmd = [
    `$ErrorActionPreference = 'Stop';`,
    `$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'vhclient', [System.IO.Pipes.PipeDirection]::InOut);`,
    `$pipe.Connect(${PIPE_TIMEOUT_MS});`,
    `$pipe.ReadMode = [System.IO.Pipes.PipeTransmissionMode]::Message;`,
    `$writer = New-Object System.IO.StreamWriter($pipe, [System.Text.Encoding]::ASCII);`,
    `$writer.AutoFlush = $true;`,
    `$writer.WriteLine('${escaped}');`,
    `$buf = New-Object byte[] 65536;`,
    `$sb = New-Object System.Text.StringBuilder;`,
    `do { $n = $pipe.Read($buf, 0, $buf.Length); if ($n -gt 0) { [void]$sb.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n)); } } while (-not $pipe.IsMessageComplete);`,
    `$pipe.Dispose();`,
    `[Console]::Out.Write($sb.ToString());`,
  ].join(" ");
  const { stdout } = await execFileAsync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", psCmd],
    { windowsHide: true, timeout: PIPE_TIMEOUT_MS + 5_000 },
  );
  return stdout;
}

function sendOnceUnixSocket(cmd: string): Promise<string> {
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
    daemonRunning: await isVirtualHereDaemonRunning(),
    hubs,
    attached,
    maxSimultaneousDevices: 1,
  };
}

