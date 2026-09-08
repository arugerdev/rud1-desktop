/**
 * Tests de la instalación desatendida.
 *
 * Lo que más importa aquí es que el "no aplica" sea explícito: cada camino
 * que no podemos garantizar tiene que devolver un motivo, porque el fallback
 * es abrir el instalador visible y no dejar al usuario sin actualización.
 */

import { describe, expect, it } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { EventEmitter } from "events";

import {
  APP_ID,
  buildInstallerArgs,
  buildSplashCommand,
  installRegistryGuid,
  installRegistryKey,
  normalizeWindowsDir,
  parseRegQueryString,
  planSilentInstall,
  readInstallProfile,
  renderSplashConfig,
  sameDirectory,
  splashConfigPath,
  splashPidPath,
  splashScriptCopyPath,
  splashWorkDir,
  startSilentInstall,
  uuidV5,
  type InstallProfile,
  type SplashOptions,
} from "./silent-install";

describe("APP_ID", () => {
  it("es el appId real de package.json (si cambia, la clave del registro cambia)", () => {
    const pkg = JSON.parse(
      fs.readFileSync(path.join(__dirname, "..", "..", "package.json"), "utf8"),
    );
    expect(APP_ID).toBe(pkg.build.appId);
  });
});

describe("installRegistryGuid", () => {
  it("reproduce el GUID que electron-builder derivó del appId", () => {
    // Valor comprobado contra la instalación real:
    // HKLM\SOFTWARE\f42184da-d8ae-5258-9376-0ee4b8ed2fa5\InstallLocation
    expect(installRegistryGuid("es.rud1.desktop")).toBe(
      "f42184da-d8ae-5258-9376-0ee4b8ed2fa5",
    );
  });

  it("uuidV5 es determinista y cambia con el nombre", () => {
    const ns = "50e065bc-3134-11e6-9bab-38c9862bdaf3";
    expect(uuidV5("a", ns)).toBe(uuidV5("a", ns));
    expect(uuidV5("a", ns)).not.toBe(uuidV5("b", ns));
  });

  it("marca la versión 5 y la variante RFC 4122", () => {
    const guid = uuidV5("es.rud1.desktop", "50e065bc-3134-11e6-9bab-38c9862bdaf3");
    expect(guid[14]).toBe("5");
    expect(["8", "9", "a", "b"]).toContain(guid[19]);
  });

  it("apunta a HKLM para todos y a HKCU para un solo usuario", () => {
    expect(installRegistryKey("machine", "es.rud1.desktop")).toBe(
      "HKLM\\SOFTWARE\\f42184da-d8ae-5258-9376-0ee4b8ed2fa5",
    );
    expect(installRegistryKey("user", "es.rud1.desktop")).toBe(
      "HKCU\\SOFTWARE\\f42184da-d8ae-5258-9376-0ee4b8ed2fa5",
    );
  });
});

describe("parseRegQueryString", () => {
  const out = [
    "",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\f42184da-d8ae-5258-9376-0ee4b8ed2fa5",
    "    InstallLocation    REG_SZ    C:\\Program Files\\rud1",
    "",
  ].join("\r\n");

  it("conserva los espacios de la ruta", () => {
    expect(parseRegQueryString(out, "InstallLocation")).toBe("C:\\Program Files\\rud1");
  });

  it("no distingue mayúsculas en el nombre del valor", () => {
    expect(parseRegQueryString(out, "installlocation")).toBe("C:\\Program Files\\rud1");
  });

  it("devuelve null cuando el valor no está", () => {
    expect(parseRegQueryString(out, "KeepShortcuts")).toBeNull();
    expect(parseRegQueryString("", "InstallLocation")).toBeNull();
    expect(parseRegQueryString(undefined as unknown as string, "x")).toBeNull();
  });

  it("acepta REG_EXPAND_SZ", () => {
    const expand = "    InstallLocation    REG_EXPAND_SZ    %ProgramFiles%\\rud1";
    expect(parseRegQueryString(expand, "InstallLocation")).toBe("%ProgramFiles%\\rud1");
  });

  it("no confunde la línea de la clave con un valor", () => {
    expect(parseRegQueryString(out, "HKEY_LOCAL_MACHINE")).toBeNull();
  });
});

describe("normalizeWindowsDir / sameDirectory", () => {
  it("ignora mayúsculas, barra final, comillas y barras al revés", () => {
    expect(sameDirectory("C:\\Program Files\\rud1", "c:\\program files\\rud1\\")).toBe(true);
    expect(sameDirectory('"C:\\Program Files\\rud1"', "C:/Program Files/rud1")).toBe(true);
    expect(sameDirectory("C:\\Program Files\\\\rud1", "C:\\Program Files\\rud1")).toBe(true);
  });

  it("distingue carpetas distintas", () => {
    expect(sameDirectory("C:\\Program Files\\rud1", "C:\\Program Files\\rud1x")).toBe(false);
  });

  it("nada vacío cuenta como igual", () => {
    expect(normalizeWindowsDir("")).toBeNull();
    expect(normalizeWindowsDir("   ")).toBeNull();
    expect(normalizeWindowsDir(null)).toBeNull();
    expect(normalizeWindowsDir(42)).toBeNull();
    expect(sameDirectory(null, null)).toBe(false);
    expect(sameDirectory("", "")).toBe(false);
  });
});

describe("buildInstallerArgs", () => {
  it("pide actualización silenciosa y fija el ámbito elegido", () => {
    expect(buildInstallerArgs("machine")).toEqual(["--updated", "/S", "/allusers"]);
    expect(buildInstallerArgs("user")).toEqual(["--updated", "/S", "/currentuser"]);
  });

  it("solo delega la reapertura al setup si no hay ventana de progreso", () => {
    expect(buildInstallerArgs("machine")).not.toContain("--force-run");
    expect(buildInstallerArgs("machine", { forceRun: true })).toEqual([
      "--updated",
      "/S",
      "/allusers",
      "--force-run",
    ]);
  });

  it("no pasa /D: la carpeta la recupera el setup del registro", () => {
    for (const scope of ["machine", "user"] as const) {
      expect(buildInstallerArgs(scope).some((a) => a.startsWith("/D"))).toBe(false);
    }
  });
});

describe("planSilentInstall", () => {
  const dir = "C:\\Program Files\\rud1";
  const profile: InstallProfile = { scope: "machine", installLocation: dir };
  const setup = "C:\\Users\\x\\AppData\\Roaming\\rud1\\rud1-update.exe";
  const fsOk = { existsSync: () => true } as unknown as typeof fs;

  const base = {
    platform: "win32" as NodeJS.Platform,
    isPackaged: true,
    installerPath: setup,
    appDir: dir,
    profile,
    fileSystem: fsOk,
  };

  it("acepta el caso normal y devuelve el perfil aplicado", () => {
    const plan = planSilentInstall(base);
    expect(plan.ok).toBe(true);
    if (!plan.ok) return;
    expect(plan.args).toEqual(["--updated", "/S", "/allusers"]);
    expect(plan.profile.scope).toBe("machine");
  });

  it("solo Windows", () => {
    const plan = planSilentInstall({ ...base, platform: "darwin" });
    expect(plan).toEqual({ ok: false, reason: "solo-windows" });
  });

  it("nunca en una build sin empaquetar", () => {
    const plan = planSilentInstall({ ...base, isPackaged: false });
    expect(plan).toEqual({ ok: false, reason: "build-sin-empaquetar" });
  });

  it("solo un setup .exe", () => {
    const plan = planSilentInstall({ ...base, installerPath: "C:\\tmp\\rud1.dmg" });
    expect(plan.ok).toBe(false);
    if (plan.ok) return;
    expect(plan.reason).toBe("el-artefacto-no-es-un-setup-exe");
  });

  it("el setup descargado tiene que existir", () => {
    const plan = planSilentInstall({
      ...base,
      fileSystem: { existsSync: () => false } as unknown as typeof fs,
    });
    expect(plan.ok).toBe(false);
    if (plan.ok) return;
    expect(plan.reason).toBe("setup-descargado-no-encontrado");
  });

  it("sin perfil en el registro no se instala en silencio", () => {
    const plan = planSilentInstall({ ...base, profile: null });
    expect(plan.ok).toBe(false);
    if (plan.ok) return;
    expect(plan.reason).toBe("sin-perfil-de-instalacion");
  });

  it("si el registro apunta a otra carpeta que la del exe, no se toca", () => {
    const plan = planSilentInstall({ ...base, appDir: "D:\\portable\\rud1" });
    expect(plan.ok).toBe(false);
    if (plan.ok) return;
    expect(plan.reason).toBe("carpeta-del-registro-distinta-a-la-de-ejecucion");
  });
});

describe("readInstallProfile", () => {
  const appDir = "C:\\Program Files\\rud1";

  it("elige el ámbito cuya carpeta coincide con el exe en ejecución", async () => {
    const profile = await readInstallProfile({
      appDir,
      readRegistry: async (key) =>
        key.startsWith("HKLM") ? "C:\\Program Files\\rud1\\" : null,
    });
    expect(profile).toEqual({ scope: "machine", installLocation: "C:\\Program Files\\rud1\\" });
  });

  it("con las dos instalaciones presentes gana la que coincide", async () => {
    const profile = await readInstallProfile({
      appDir: "C:\\Users\\x\\AppData\\Local\\Programs\\rud1",
      readRegistry: async (key) =>
        key.startsWith("HKLM")
          ? "C:\\Program Files\\rud1"
          : "C:\\Users\\x\\AppData\\Local\\Programs\\rud1",
    });
    expect(profile?.scope).toBe("user");
  });

  it("devuelve null si ninguna coincide", async () => {
    const profile = await readInstallProfile({
      appDir: "D:\\otra\\ruta",
      readRegistry: async () => "C:\\Program Files\\rud1",
    });
    expect(profile).toBeNull();
  });

  it("devuelve null cuando el registro no tiene nada", async () => {
    expect(await readInstallProfile({ appDir, readRegistry: async () => null })).toBeNull();
  });
});

describe("ventana de progreso", () => {
  it("trabaja en una carpeta ASCII y sin espacios", () => {
    const env = { ProgramData: "C:\\ProgramData" } as NodeJS.ProcessEnv;
    expect(splashWorkDir(env)).toBe("C:\\ProgramData\\rud1");
    expect(splashScriptCopyPath(env)).toContain("update-progress.ps1");
    expect(splashConfigPath(env)).toContain("update-splash.txt");
    expect(splashPidPath(env)).toBe("C:\\ProgramData\\rud1\\installer.pid");
    for (const p of [splashScriptCopyPath(env), splashConfigPath(env), splashPidPath(env)]) {
      expect(p).not.toMatch(/\s/);
      // eslint-disable-next-line no-control-regex
      expect(p).toMatch(/^[\x20-\x7e]+$/);
    }
  });

  const splash: SplashOptions = {
    scriptPath: "C:\\Program Files\\rud1\\resources\\bin\\update-progress.ps1",
    sentinelPath: "C:\\Users\\Aruger\\AppData\\Roaming\\rud1\\update-in-progress.json",
    relaunchExe: "C:\\Program Files\\rud1\\rud1.exe",
    centerOn: { x: 960, y: 540 },
    title: "Instalando la actualización",
    body: "rud1 se cerrará\ny volverá a abrirse",
    hint: "Se mantiene la carpeta",
    elapsedLabel: "Transcurrido",
    theme: "dark",
  };

  it("la config lleva textos, centinela, exe a reabrir y pid, uno por línea", () => {
    const env = { ProgramData: "C:\\ProgramData" } as NodeJS.ProcessEnv;
    const cfg = renderSplashConfig(splash, env);
    expect(cfg).toContain("theme=dark");
    expect(cfg).toContain("title=Instalando la actualización");
    expect(cfg).toContain("body=rud1 se cerrará y volverá a abrirse");
    expect(cfg).toContain(`sentinel=${splash.sentinelPath}`);
    expect(cfg).toContain(`relaunch=${splash.relaunchExe}`);
    expect(cfg).toContain("pidfile=C:\\ProgramData\\rud1\\installer.pid");
    expect(cfg).toContain("center=960,540");
    // Un valor con salto de línea rompería el formato clave=valor.
    expect(cfg.split("\n").filter((l) => l.length > 0)).toHaveLength(9);
  });

  it("sin punto de centrado la clave queda vacía y la ventana decide", () => {
    expect(renderSplashConfig({ ...splash, centerOn: null })).toContain("center=\n");
    const sinClave = { ...splash };
    delete sinClave.centerOn;
    expect(renderSplashConfig(sinClave)).toContain("center=\n");
    expect(
      renderSplashConfig({ ...splash, centerOn: { x: NaN, y: 3 } }),
    ).toContain("center=\n");
  });

  it("se lanza por cmd start, que es lo que la desvincula de la app", () => {
    const cmd = buildSplashCommand("C:\\ProgramData\\rud1\\p.ps1", "C:\\ProgramData\\rud1\\c.txt");
    expect(cmd.slice(0, 4)).toEqual(["/c", "start", "", "powershell.exe"]);
    expect(cmd).toContain("-ConfigFile");
    expect(cmd).toContain("C:\\ProgramData\\rud1\\c.txt");
    // El pid del setup viaja por fichero: la ventana se abre antes que él.
    expect(cmd).not.toContain("-WatchPid");
  });
});

describe("startSilentInstall", () => {
  function fakeChild(): EventEmitter & { pid: number; unref: () => void } {
    const c = new EventEmitter() as EventEmitter & { pid: number; unref: () => void };
    c.pid = 4242;
    c.unref = () => {};
    return c;
  }

  it("da por bueno el arranque cuando el setup sigue vivo", async () => {
    const calls: string[] = [];
    const res = await startSilentInstall({
      installerPath: "C:\\tmp\\setup.exe",
      args: ["--updated", "/S"],
      watchMs: 5,
      spawnFn: ((cmd: string) => {
        calls.push(cmd);
        return fakeChild();
      }) as never,
    });
    expect(res.ok).toBe(true);
    expect(res.pid).toBe(4242);
    expect(calls).toEqual(["C:\\tmp\\setup.exe"]);
  });

  it("un fallo al lanzarlo no se traga: devuelve el motivo", async () => {
    const res = await startSilentInstall({
      installerPath: "C:\\tmp\\setup.exe",
      args: [],
      watchMs: 50,
      spawnFn: (() => {
        throw new Error("ENOENT");
      }) as never,
    });
    expect(res.ok).toBe(false);
    expect(res.reason).toContain("ENOENT");
  });

  it("si el setup muere con error de inmediato, no damos por hecho que instala", async () => {
    const child = fakeChild();
    const promise = startSilentInstall({
      installerPath: "C:\\tmp\\setup.exe",
      args: [],
      watchMs: 2000,
      spawnFn: (() => child) as never,
    });
    setTimeout(() => child.emit("exit", 1), 5);
    const res = await promise;
    expect(res.ok).toBe(false);
    expect(res.reason).toContain("1");
  });

  it("lanza la ventana de progreso además del setup", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rud1-splash-"));
    const script = path.join(dir, "update-progress.ps1");
    fs.writeFileSync(script, "# fake");
    const spawned: string[] = [];
    const res = await startSilentInstall({
      installerPath: "C:\\tmp\\setup.exe",
      args: [],
      watchMs: 5,
      env: { ProgramData: dir } as NodeJS.ProcessEnv,
      spawnFn: ((cmd: string) => {
        spawned.push(cmd);
        return fakeChild();
      }) as never,
      splash: {
        scriptPath: script,
        sentinelPath: path.join(dir, "marker.json"),
        relaunchExe: path.join(dir, "rud1.exe"),
        title: "t",
        body: "b",
        hint: "h",
        elapsedLabel: "e",
        theme: "dark",
      },
    });
    expect(res.ok).toBe(true);
    // La ventana primero: así no hay ni un instante en blanco al cerrarse rud1.
    expect(spawned).toEqual(["cmd.exe", "C:\\tmp\\setup.exe"]);
    expect(fs.existsSync(path.join(dir, "rud1", "update-splash.txt"))).toBe(true);
    expect(fs.existsSync(path.join(dir, "rud1", "update-progress.ps1"))).toBe(true);
    expect(fs.readFileSync(path.join(dir, "rud1", "installer.pid"), "utf8")).toBe("4242");
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("si la ventana de progreso falla, la instalación sigue", async () => {
    const res = await startSilentInstall({
      installerPath: "C:\\tmp\\setup.exe",
      args: [],
      watchMs: 5,
      env: { ProgramData: "Z:\\no\\existe" } as NodeJS.ProcessEnv,
      spawnFn: (() => fakeChild()) as never,
      splash: {
        scriptPath: "Z:\\no\\existe\\update-progress.ps1",
        sentinelPath: "Z:\\no\\existe\\marker.json",
        relaunchExe: "Z:\\no\\existe\\rud1.exe",
        title: "t",
        body: "b",
        hint: "h",
        elapsedLabel: "e",
        theme: "light",
      },
    });
    expect(res.ok).toBe(true);
  });
});
