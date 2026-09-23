// Abre la memoria USB que el equipo comparte por SMB; la contraseña viaja por stdin, nunca en argv.
import { spawn } from "child_process";
import { Socket } from "net";
import { shell } from "electron";
import { t } from "./i18n";

export interface UsbFolderParams {
  host: string;
  share: string;
  username: string;
  password: string;
}

export type UsbFolderResult = { ok: true } | { ok: false; error: string };

// IPv4 o nombre DNS; sin ':' porque un IPv6 literal no vale tal cual en una ruta UNC.
const HOST_REGEX = /^(?!-)[A-Za-z0-9.-]{1,253}$/;
const SHARE_REGEX = /^usb-[0-9a-z-]{1,40}$/;
const USERNAME_REGEX = /^[a-z0-9_]{1,32}$/;
const PASSWORD_REGEX = /^[A-Za-z0-9_-]{8,128}$/;

const MAP_TIMEOUT_MS = 20_000;
const PROBE_TIMEOUT_MS = 5_000;
const SMB_PORT = 445;

export const POWERSHELL_ARGS: readonly string[] = [
  "-NoProfile",
  "-NonInteractive",
  "-Command",
  "-",
];

export function validateUsbFolderParams(p: unknown): p is UsbFolderParams {
  if (p == null || typeof p !== "object") return false;
  const { host, share, username, password } = p as Record<string, unknown>;
  return (
    typeof host === "string" &&
    HOST_REGEX.test(host) &&
    !host.includes("..") &&
    typeof share === "string" &&
    SHARE_REGEX.test(share) &&
    typeof username === "string" &&
    USERNAME_REGEX.test(username) &&
    typeof password === "string" &&
    PASSWORD_REGEX.test(password)
  );
}

// PowerShell también cierra comillas simples con las tipográficas, así que se duplican todas.
export function psLiteral(value: string): string {
  return `'${value.replace(/['‘’‚‛]/g, (q) => q + q)}'`;
}

export function uncPath(host: string, share: string): string {
  return `\\\\${host}\\${share}`;
}

// CredWrite en el almacén de credenciales del usuario. La app corre elevada y un
// New-SmbMapping solo lo vería la sesión de administrador, no el Explorador.
const CRED_WRITER_CS =
  "using System; using System.Runtime.InteropServices; public static class Rud1Cred { " +
  "[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct CREDENTIAL { " +
  "public int Flags; public int Type; public string TargetName; public string Comment; " +
  "public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public int CredentialBlobSize; " +
  "public IntPtr CredentialBlob; public int Persist; public int AttributeCount; public IntPtr Attributes; " +
  "public string TargetAlias; public string UserName; } " +
  "[DllImport(\"advapi32.dll\", CharSet = CharSet.Unicode, SetLastError = true)] " +
  "static extern bool CredWrite(ref CREDENTIAL c, int flags); " +
  "public static int Write(string target, string user, string pass) { " +
  "byte[] b = System.Text.Encoding.Unicode.GetBytes(pass); CREDENTIAL c = new CREDENTIAL(); " +
  "c.Type = 2; c.TargetName = target; c.UserName = user; c.Persist = 2; c.CredentialBlobSize = b.Length; " +
  "c.CredentialBlob = Marshal.AllocHGlobal(b.Length); " +
  "try { Marshal.Copy(b, 0, c.CredentialBlob, b.Length); return CredWrite(ref c, 0) ? 0 : Marshal.GetLastWin32Error(); } " +
  "finally { Marshal.FreeHGlobal(c.CredentialBlob); } } }";

// Una sentencia completa por línea: `-Command -` ejecuta stdin línea a línea.
export function buildMapScript(p: UsbFolderParams): string {
  const remote = psLiteral(uncPath(p.host, p.share));
  const target = psLiteral(p.host);
  const user = psLiteral(`${p.host}\\${p.username}`);
  const pass = psLiteral(p.password);
  return [
    "$ErrorActionPreference = 'Stop'",
    `$r = ${remote}`,
    `$src = ${psLiteral(CRED_WRITER_CS)}`,
    `try { if (-not ('Rud1Cred' -as [type])) { Add-Type -TypeDefinition $src }; $ce = [Rud1Cred]::Write(${target}, ${user}, ${pass}) } catch { $ce = -1 }`,
    "try { Get-SmbMapping -RemotePath $r -ErrorAction SilentlyContinue | Remove-SmbMapping -Force -ErrorAction SilentlyContinue } catch { }",
    `if ($ce -ne 0) { 'RUD1_ERR ' + $ce } else { try { New-SmbMapping -RemotePath $r -UserName ${user} -Password ${pass} -Persistent $false | Out-Null; 'RUD1_OK' } catch { $c = $null; $d = $_.Exception.ErrorData; if ($d) { $c = $d.CimInstanceProperties['error_Code'].Value }; if (-not $c) { $c = $_.Exception.HResult }; 'RUD1_ERR ' + $c } }`,
    "",
  ].join("\r\n");
}

export function parseMapOutput(stdout: string): { ok: true } | { ok: false; code: number | null } {
  if (/^RUD1_OK\s*$/m.test(stdout)) return { ok: true };
  const m = /^RUD1_ERR\s+(-?\d+)/m.exec(stdout);
  return { ok: false, code: m ? Number(m[1]) : null };
}

const UNREACHABLE_CODES = new Set([51, 53, 64, 121, 1231, 1232, 1311]);
const CREDENTIAL_CODES = new Set([5, 86, 1326, 1327, 1330, 1331, 1909, 2202]);
const NO_SHARE_CODES = new Set([67, 2310]);
const CONFLICT_CODE = 1219;

export function errorMessageForCode(code: number | null): string {
  if (code != null && UNREACHABLE_CODES.has(code)) return t("usbFolder.unreachable");
  if (code != null && CREDENTIAL_CODES.has(code)) return t("usbFolder.credentialsRejected");
  if (code != null && NO_SHARE_CODES.has(code)) return t("usbFolder.shareNotFound");
  if (code === CONFLICT_CODE) return t("usbFolder.credentialConflict");
  return t("usbFolder.failed", { code: code == null ? "?" : String(code) });
}

export interface PsRunResult {
  stdout: string;
  timedOut: boolean;
}

export function runPowerShellStdin(script: string, timeoutMs = MAP_TIMEOUT_MS): Promise<PsRunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn("powershell.exe", [...POWERSHELL_ARGS], {
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let settled = false;
    const finish = (r: PsRunResult | Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (r instanceof Error) reject(r);
      else resolve(r);
    };
    const timer = setTimeout(() => {
      child.kill();
      finish({ stdout, timedOut: true });
    }, timeoutMs);
    child.stdout?.on("data", (b: Buffer) => {
      stdout += b.toString("utf8");
    });
    child.stderr?.on("data", () => undefined);
    child.on("error", (err) => finish(err));
    child.on("close", () => finish({ stdout, timedOut: false }));
    child.stdin?.on("error", () => undefined);
    child.stdin?.end(script, "utf8");
  });
}

export function probeSmbPort(host: string, timeoutMs = PROBE_TIMEOUT_MS): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = new Socket();
    const done = (ok: boolean) => {
      sock.destroy();
      resolve(ok);
    };
    sock.setTimeout(timeoutMs, () => done(false));
    sock.once("connect", () => done(true));
    sock.once("error", () => done(false));
    sock.connect(SMB_PORT, host);
  });
}

export interface UsbFolderDeps {
  platform: NodeJS.Platform;
  probe: (host: string) => Promise<boolean>;
  runPowerShell: (script: string) => Promise<PsRunResult>;
  openPath: (path: string) => Promise<string>;
}

const defaultDeps: UsbFolderDeps = {
  platform: process.platform,
  probe: (host) => probeSmbPort(host),
  runPowerShell: (script) => runPowerShellStdin(script),
  openPath: (path) => shell.openPath(path),
};

export async function openUsbFolder(
  params: unknown,
  deps: Partial<UsbFolderDeps> = {},
): Promise<UsbFolderResult> {
  const d = { ...defaultDeps, ...deps };
  if (d.platform !== "win32") return { ok: false, error: t("usbFolder.unsupportedPlatform") };
  if (!validateUsbFolderParams(params)) return { ok: false, error: t("usbFolder.invalidParams") };

  const { host, share } = params;
  if (!(await d.probe(host))) return { ok: false, error: t("usbFolder.unreachable") };

  let run: PsRunResult;
  try {
    run = await d.runPowerShell(buildMapScript(params));
  } catch {
    return { ok: false, error: t("usbFolder.failed", { code: "spawn" }) };
  }
  if (run.timedOut) return { ok: false, error: t("usbFolder.unreachable") };

  const parsed = parseMapOutput(run.stdout);
  if (!parsed.ok) {
    console.warn(`[usb-folder] mapping ${share}@${host} failed code=${parsed.code ?? "?"}`);
    return { ok: false, error: errorMessageForCode(parsed.code) };
  }

  const openErr = await d.openPath(uncPath(host, share));
  if (openErr !== "") return { ok: false, error: t("usbFolder.openFailed") };
  return { ok: true };
}
