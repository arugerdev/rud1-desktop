// Instalación desatendida de la actualización en Windows.
//
// El instalador NSIS deja escrito en el registro dónde y con qué ámbito lo
// instaló el usuario la primera vez; releyéndolo podemos relanzar el MISMO
// setup en silencio con esa configuración exacta, sin asistente ni preguntas.
import { execFile, spawn as nodeSpawn, type ChildProcess } from "child_process";
import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { promisify } from "util";

const execFileAsync = promisify(execFile);

/** appId de package.json (build.appId). Pinado por test contra el manifiesto. */
export const APP_ID = "es.rud1.desktop";

// Namespace con el que electron-builder deriva APP_GUID del appId
// (NsisTarget: UUID.v5(appInfo.id, ELECTRON_BUILDER_NS_UUID)).
const ELECTRON_BUILDER_NS_UUID = "50e065bc-3134-11e6-9bab-38c9862bdaf3";

const REG_QUERY_TIMEOUT_MS = 5_000;
// Margen para detectar un fallo de arranque del setup antes de cerrarnos.
// Corto a propósito: el setup mata la app a los ~1,4 s de arrancar.
const SPAWN_WATCH_MS = 700;

export type InstallScope = "machine" | "user";

export interface InstallProfile {
  /** "machine" = instalado para todos (HKLM), "user" = solo este usuario. */
  scope: InstallScope;
  /** Carpeta que eligió el usuario en el setup. */
  installLocation: string;
}

export type SilentInstallPlan =
  | { ok: true; args: string[]; profile: InstallProfile }
  | { ok: false; reason: string };

/** UUID v5 (SHA-1), igual que builder-util-runtime. */
export function uuidV5(name: string, namespace: string): string {
  const ns = Buffer.from(namespace.replace(/-/g, ""), "hex");
  const hash = createHash("sha1").update(ns).update(Buffer.from(name, "utf8")).digest();
  const b = Buffer.from(hash.subarray(0, 16));
  b[6] = (b[6] & 0x0f) | 0x50;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = b.toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join("-");
}

/** GUID con el que el instalador nombra su clave de registro. */
export function installRegistryGuid(appId: string = APP_ID): string {
  return uuidV5(appId, ELECTRON_BUILDER_NS_UUID);
}

export function installRegistryKey(scope: InstallScope, appId: string = APP_ID): string {
  const hive = scope === "machine" ? "HKLM" : "HKCU";
  return `${hive}\\SOFTWARE\\${installRegistryGuid(appId)}`;
}

/**
 * Saca un valor REG_SZ de la salida de `reg query`. El valor puede llevar
 * espacios (C:\Program Files\rud1), así que solo se recorta por la derecha.
 */
export function parseRegQueryString(stdout: string, valueName: string): string | null {
  if (typeof stdout !== "string" || stdout.length === 0) return null;
  const wanted = valueName.toLowerCase();
  for (const rawLine of stdout.split(/\r?\n/)) {
    const m = /^\s+(\S+)\s+(REG_[A-Z_]+)\s{2,}(.*)$/.exec(rawLine);
    if (!m) continue;
    if (m[1].toLowerCase() !== wanted) continue;
    const value = m[3].replace(/\s+$/, "");
    return value.length > 0 ? value : null;
  }
  return null;
}

/** Normaliza una carpeta Windows para comparar (case-insensitive, sin barra final). */
export function normalizeWindowsDir(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const trimmed = input.trim().replace(/^"|"$/g, "");
  if (trimmed.length === 0) return null;
  const collapsed = trimmed.replace(/\//g, "\\").replace(/\\{2,}/g, "\\");
  const noTrailing = collapsed.replace(/\\+$/, "");
  if (noTrailing.length === 0) return null;
  return noTrailing.toLowerCase();
}

export function sameDirectory(a: unknown, b: unknown): boolean {
  const na = normalizeWindowsDir(a);
  const nb = normalizeWindowsDir(b);
  return na != null && nb != null && na === nb;
}

/**
 * Argumentos del setup para reinstalar sin asistente:
 *   --updated    → es una actualización: se salta licencia/carpeta y conserva
 *                  los accesos directos que ya tenía el usuario.
 *   /S           → silencioso, sin ventanas ni preguntas.
 *   /allusers|/currentuser → fija el ámbito que eligió el usuario, para que no
 *                  se resuelva por adivinación si existen las dos instalaciones.
 *   --force-run  → SOLO cuando no hay ventana de progreso. Normalmente reabre
 *                  rud1 ella, que hereda el token y no dispara el aviso de
 *                  permisos de Windows (el del setup sí, y además no es fiable).
 * La carpeta NO se pasa por /D: el propio setup la lee del registro (que es de
 * donde sale el perfil que hemos validado) y así evitamos el conocido lío de
 * /D con rutas que llevan espacios.
 */
export function buildInstallerArgs(
  scope: InstallScope,
  options: { forceRun?: boolean } = {},
): string[] {
  const args = ["--updated", "/S", scope === "machine" ? "/allusers" : "/currentuser"];
  if (options.forceRun) args.push("--force-run");
  return args;
}

export interface RegistryReader {
  (key: string, valueName: string): Promise<string | null>;
}

/** Lee un REG_SZ con reg.exe (solo lectura). Devuelve null si no existe. */
export const defaultRegistryReader: RegistryReader = async (key, valueName) => {
  const systemRoot = process.env["SystemRoot"] ?? "C:\\Windows";
  const regExe = path.join(systemRoot, "System32", "reg.exe");
  try {
    const { stdout } = await execFileAsync(
      regExe,
      ["query", key, "/v", valueName, "/reg:64"],
      { timeout: REG_QUERY_TIMEOUT_MS, windowsHide: true },
    );
    return parseRegQueryString(stdout, valueName);
  } catch {
    // Clave/valor ausente o reg.exe no disponible: no hay perfil que reusar.
    return null;
  }
};

/**
 * Recupera la configuración del primer setup. Mira las dos ubicaciones
 * posibles (todos los usuarios / solo yo) y devuelve la que apunta a la
 * carpeta desde la que estamos ejecutándonos.
 */
export async function readInstallProfile(options: {
  appDir: string;
  appId?: string;
  readRegistry?: RegistryReader;
}): Promise<InstallProfile | null> {
  const read = options.readRegistry ?? defaultRegistryReader;
  const appId = options.appId ?? APP_ID;
  const found: InstallProfile[] = [];
  for (const scope of ["machine", "user"] as const) {
    const location = await read(installRegistryKey(scope, appId), "InstallLocation");
    if (location != null) found.push({ scope, installLocation: location });
  }
  // La instalación que manda es la que coincide con el exe en ejecución.
  const exact = found.find((p) => sameDirectory(p.installLocation, options.appDir));
  return exact ?? null;
}

/**
 * Decide si podemos instalar en silencio. Ante cualquier duda devuelve
 * `ok: false` con el motivo y el flujo cae al instalador visible de siempre.
 */
export function planSilentInstall(options: {
  platform: NodeJS.Platform;
  isPackaged: boolean;
  installerPath: string;
  appDir: string;
  profile: InstallProfile | null;
  fileSystem?: typeof fs;
}): SilentInstallPlan {
  if (options.platform !== "win32") return { ok: false, reason: "solo-windows" };
  if (!options.isPackaged) return { ok: false, reason: "build-sin-empaquetar" };
  if (!options.installerPath.toLowerCase().endsWith(".exe")) {
    return { ok: false, reason: "el-artefacto-no-es-un-setup-exe" };
  }
  const fileSystem = options.fileSystem ?? fs;
  try {
    if (!fileSystem.existsSync(options.installerPath)) {
      return { ok: false, reason: "setup-descargado-no-encontrado" };
    }
  } catch {
    return { ok: false, reason: "setup-descargado-ilegible" };
  }
  const profile = options.profile;
  if (profile == null) return { ok: false, reason: "sin-perfil-de-instalacion" };
  if (!sameDirectory(profile.installLocation, options.appDir)) {
    return { ok: false, reason: "carpeta-del-registro-distinta-a-la-de-ejecucion" };
  }
  return { ok: true, args: buildInstallerArgs(profile.scope), profile };
}

export interface SplashOptions {
  /** Ruta del .ps1 que pinta la ventana de progreso (resources/bin). */
  scriptPath: string;
  /** Fichero centinela: la ventana se cierra cuando desaparece. */
  sentinelPath: string;
  /** Exe que la ventana volverá a abrir cuando el setup termine. */
  relaunchExe: string;
  /** Punto donde centrarla: normalmente el centro de la ventana que se cierra. */
  centerOn?: { x: number; y: number } | null;
  title: string;
  body: string;
  hint: string;
  elapsedLabel: string;
  theme: "light" | "dark";
}

/**
 * Carpeta de trabajo de la ventana de progreso. ProgramData a propósito: es
 * ASCII y sin espacios, así que la orden que la lanza no depende de cómo cmd
 * trate las comillas ni los acentos del nombre del usuario.
 */
export function splashWorkDir(env: NodeJS.ProcessEnv = process.env): string {
  return path.join(env["ProgramData"] ?? "C:\\ProgramData", "rud1");
}

export function splashScriptCopyPath(env?: NodeJS.ProcessEnv): string {
  return path.join(splashWorkDir(env), "update-progress.ps1");
}

export function splashConfigPath(env?: NodeJS.ProcessEnv): string {
  return path.join(splashWorkDir(env), "update-splash.txt");
}

/** Aquí se deja el pid del setup: la ventana se abre antes de arrancarlo. */
export function splashPidPath(env?: NodeJS.ProcessEnv): string {
  return path.join(splashWorkDir(env), "installer.pid");
}

/** clave=valor en UTF-8; los textos NO viajan por línea de comandos. */
export function renderSplashConfig(
  splash: SplashOptions,
  env?: NodeJS.ProcessEnv,
): string {
  const oneLine = (s: string) => String(s).replace(/[\r\n]+/g, " ").trim();
  const c = splash.centerOn;
  const center =
    c != null && Number.isFinite(c.x) && Number.isFinite(c.y)
      ? `${Math.round(c.x)},${Math.round(c.y)}`
      : "";
  return [
    `theme=${splash.theme}`,
    `center=${center}`,
    `title=${oneLine(splash.title)}`,
    `body=${oneLine(splash.body)}`,
    `hint=${oneLine(splash.hint)}`,
    `elapsed=${oneLine(splash.elapsedLabel)}`,
    `sentinel=${oneLine(splash.sentinelPath)}`,
    `relaunch=${oneLine(splash.relaunchExe)}`,
    `pidfile=${splashPidPath(env)}`,
    "",
  ].join("\n");
}

/** Borra la copia de trabajo de la ventana de progreso. */
export function cleanupSplashFiles(
  env?: NodeJS.ProcessEnv,
  fileSystem: typeof fs = fs,
): void {
  for (const p of [splashConfigPath(env), splashScriptCopyPath(env), splashPidPath(env)]) {
    try {
      fileSystem.unlinkSync(p);
    } catch {
      /* no estaba */
    }
  }
}

export interface StartSilentInstallResult {
  ok: boolean;
  reason?: string;
  pid?: number;
}

type SpawnFn = typeof nodeSpawn;

/**
 * Lanza la ventana de progreso. Si falla, la actualización sigue igual.
 *
 * Va por `cmd /c start` a propósito: un hijo directo muere cuando Electron
 * sale, y lanzado como "detached" PowerShell se queda sin consola y no
 * arranca. `start` le da consola propia y lo desvincula de nosotros.
 */
export function buildSplashCommand(scriptPath: string, configPath: string): string[] {
  return [
    "/c",
    "start",
    "",
    "powershell.exe",
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-WindowStyle",
    "Hidden",
    "-File",
    scriptPath,
    "-ConfigFile",
    configPath,
  ];
}

function launchSplash(
  splash: SplashOptions,
  spawnFn: SpawnFn,
  fileSystem: typeof fs,
  env?: NodeJS.ProcessEnv,
): boolean {
  try {
    // Copia propia: el setup está sobrescribiendo resourcesin y no queremos
    // que el fichero esté en uso mientras se reemplaza.
    const dir = splashWorkDir(env);
    const script = splashScriptCopyPath(env);
    const config = splashConfigPath(env);
    fileSystem.mkdirSync(dir, { recursive: true });
    fileSystem.copyFileSync(splash.scriptPath, script);
    fileSystem.writeFileSync(config, renderSplashConfig(splash, env), "utf8");
    // Un pid de un intento anterior confundiría a la ventana.
    try {
      fileSystem.unlinkSync(splashPidPath(env));
    } catch {
      /* no había */
    }
    const child = spawnFn("cmd.exe", buildSplashCommand(script, config), {
      detached: true,
      stdio: "ignore",
      windowsHide: true,
    });
    child.unref();
    return true;
  } catch {
    return false;
  }
}

/**
 * Deja la ventana de progreso en pantalla y arranca el setup en silencio.
 * Espera un momento para distinguir "no ha arrancado" de "está instalando":
 * si el proceso muere de inmediato devolvemos el fallo y quien llama puede
 * caer al instalador visible en vez de cerrar la app para nada.
 */
export async function startSilentInstall(options: {
  installerPath: string;
  args: string[];
  splash?: SplashOptions | null;
  env?: NodeJS.ProcessEnv;
  spawnFn?: SpawnFn;
  fileSystem?: typeof fs;
  watchMs?: number;
}): Promise<StartSilentInstallResult> {
  const spawnFn = options.spawnFn ?? nodeSpawn;
  const fileSystem = options.fileSystem ?? fs;
  const watchMs = options.watchMs ?? SPAWN_WATCH_MS;

  // La ventana de progreso PRIMERO: así no hay ni un instante en el que el
  // usuario se quede sin nada en pantalla. Recoge el pid del setup del
  // fichero que se escribe justo después.
  const splashUp =
    options.splash != null
      ? launchSplash(options.splash, spawnFn, fileSystem, options.env)
      : false;
  // Sin ventana que lo haga, que sea el setup quien reabra rud1 (con su
  // aviso de permisos): peor experiencia, pero mejor que quedarse cerrado.
  const args = splashUp ? options.args : [...options.args, "--force-run"];

  let child: ChildProcess;
  try {
    child = spawnFn(options.installerPath, args, {
      detached: true,
      stdio: "ignore",
      windowsHide: true,
    });
  } catch (err) {
    return { ok: false, reason: `no-arranca-el-setup: ${(err as Error)?.message ?? err}` };
  }

  if (splashUp && typeof child.pid === "number") {
    try {
      fileSystem.writeFileSync(splashPidPath(options.env), String(child.pid), "utf8");
    } catch {
      // Sin pid la ventana no sabrá cuándo acabó: se cerrará al borrarse el
      // centinela (rud1 nuevo) o por tope de tiempo.
    }
  }

  const outcome = await new Promise<StartSilentInstallResult>((resolve) => {
    let settled = false;
    const done = (r: StartSilentInstallResult) => {
      if (settled) return;
      settled = true;
      resolve(r);
    };
    const timer = setTimeout(() => done({ ok: true, pid: child.pid }), watchMs);
    child.once("error", (err: Error) => {
      clearTimeout(timer);
      done({ ok: false, reason: `no-arranca-el-setup: ${err?.message ?? err}` });
    });
    child.once("exit", (code: number | null) => {
      clearTimeout(timer);
      if (code === 0) done({ ok: true, pid: child.pid });
      else done({ ok: false, reason: `el-setup-terminó-con-código-${code}` });
    });
  });

  // Si el setup no ha arrancado, quien llama borra el centinela y la ventana
  // de progreso se cierra sola en el siguiente tick.
  try {
    child.unref();
  } catch {
    /* ignore */
  }
  return outcome;
}

export const __test = {
  ELECTRON_BUILDER_NS_UUID,
  SPAWN_WATCH_MS,
};
