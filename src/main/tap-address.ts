// Dirección de rescate para rud1-tap cuando nadie se la da.
//
// En Windows, openvpn (ip-win32 dynamic, el valor por defecto) no da el túnel
// por levantado hasta que el adaptador TAP tiene una IPv4: espera 5 s y luego
// hasta 30 s más imprimiendo "Route: Waiting for TUN/TAP interface to come
// up...". La dirección llega por DHCP desde la LAN del equipo, o del propio
// driver cuando el relay empuja un `ifconfig-push` (LAN STATIC). Si el equipo
// no tiene LAN detrás (solo SIM, sin cable) no contesta nadie, y Windows tarda
// más que eso en ponerse una APIPA. Un adaptador que nunca tuvo dirección se
// quedaba así y el intento caducaba antes de que el puerto de gestión sirviera
// de nada.
//
// Aquí se hace lo que haría Windows, pero ya: una 169.254.x.y fija. Es on-link
// con el puerto de gestión del equipo, que vive en 169.254.0/24 y
// 169.254.255/24 (rud1-fw mgmtport); por eso se elige fuera de esos dos
// bloques, igual que una APIPA, y nunca choca con él.
//
// Fijarla apaga el DHCP del adaptador, así que se deja una marca en disco y se
// devuelve a DHCP al desconectar y antes de cada conexión. Sin eso, el
// siguiente equipo con DHCP de planta no daría dirección al técnico. La marca
// cubre también la IP de LAN que pone `maybeApplyApipaFallback`.

import { execFile } from "child_process";
import fs from "fs/promises";
import path from "path";
import { promisify } from "util";

import { readAdapterIpV4 } from "./apipa-fallback";

const execFileAsync = promisify(execFile);
const NETSH_TIMEOUT_MS = 5_000;

/**
 * Cuánto se deja esperar a openvpn al adaptador antes de ponerle dirección.
 * Se cuenta desde su primer "Waiting for TUN/TAP", que llega 5 s después de
 * abrir el adaptador. El DHCP de planta contesta en 1-3 s, pero si la primera
 * petición se pierde (por SIM pasa) Windows la repite a los ~4 s y la
 * respuesta cruza otra vez el móvil. Con 10 s el rescate llega a los ~15 s y
 * no le quita el lease a ese reintento: fijar la dirección apaga el DHCP.
 */
export const TAP_RESCUE_GRACE_MS = 10_000;

/**
 * Lo que openvpn sigue esperando desde su primer "Waiting for TUN/TAP" antes
 * de dar el arranque por terminado igualmente ("Initialization Sequence
 * Completed With Errors"): su ventana de route-delay, 30 s.
 */
export const OPENVPN_TAP_WAIT_MS = 30_000;
const TAP_WAIT_SLACK_MS = 5_000;

export const LINK_LOCAL_MASK = "255.255.0.0";

/** Línea con la que openvpn dice que sigue esperando al adaptador. */
export function isWaitingForTapLine(line: string): boolean {
  return line.includes("Waiting for TUN/TAP interface to come up");
}

/**
 * Toca rescatar: openvpn lleva el margen entero esperando al adaptador y el
 * relay no le ha empujado una IP propia.
 */
export function shouldRescueTapAddress(
  waitingSince: number | null,
  now: number,
  pushedIp: string | null = null,
  graceMs = TAP_RESCUE_GRACE_MS,
): boolean {
  // Con `ifconfig-push` (LAN STATIC) openvpn espera a ver ESA dirección en el
  // adaptador, no una cualquiera: una 169.254 no lo desbloquea, y fijarla
  // apaga el DHCP por el que el driver tiene que entregarle la suya.
  if (pushedIp) return false;
  return waitingSince != null && now - waitingSince >= graceMs;
}

/**
 * Plazo de arranque mientras openvpn espera al adaptador. Para entonces ya
 * habló con el relay, así que no se corta antes de que acabe su propia espera,
 * se haya podido aplicar el rescate o no.
 */
export function initDeadlineWithTapWait(baseDeadline: number, waitingSince: number | null): number {
  if (waitingSince == null) return baseDeadline;
  return Math.max(baseDeadline, waitingSince + OPENVPN_TAP_WAIT_MS + TAP_WAIT_SLACK_MS);
}

/**
 * 169.254.X.Y con X e Y en 1..254. Deja fuera 169.254.0/24 y 169.254.255/24
 * (reservados por RFC 3927 y usados por el puerto de gestión) y las .0/.255.
 */
export function pickLinkLocalIpv4(random: () => number = Math.random): string {
  const octet = () => 1 + Math.floor(random() * 254);
  return `169.254.${octet()}.${octet()}`;
}

export function buildSetStaticArgs(adapter: string, ip: string): string[] {
  return ["interface", "ipv4", "set", "address", `name=${adapter}`, "static", ip, LINK_LOCAL_MASK];
}

export function buildSetDhcpArgs(adapter: string): string[] {
  return ["interface", "ipv4", "set", "address", `name=${adapter}`, "dhcp"];
}

export type TapRescueResult =
  | { applied: true; ip: string }
  | { applied: false; reason: string };

/** Deja constancia de que la dirección fija del adaptador la puso rud1. */
export async function markTapStatic(markerPath: string, adapter: string, ip: string): Promise<void> {
  try {
    await fs.mkdir(path.dirname(markerPath), { recursive: true });
    await fs.writeFile(markerPath, JSON.stringify({ adapter, ip, at: new Date().toISOString() }), "utf8");
  } catch {
    /* best-effort: sin marca solo se pierde la vuelta automática a DHCP */
  }
}

/**
 * Si el adaptador sigue sin IPv4, le pone una 169.254 fija y deja la marca.
 * Nunca lanza: un fallo aquí solo significa que openvpn agota su propia espera.
 */
export async function rescueTapAddress(
  adapter: string,
  markerPath: string,
  random: () => number = Math.random,
): Promise<TapRescueResult> {
  if (process.platform !== "win32") return { applied: false, reason: "non-windows" };
  const current = await readAdapterIpV4(adapter);
  if (current) return { applied: false, reason: `already-has-ip ${current}` };
  const ip = pickLinkLocalIpv4(random);
  try {
    await execFileAsync("netsh", buildSetStaticArgs(adapter, ip), { timeout: NETSH_TIMEOUT_MS });
  } catch (err) {
    return {
      applied: false,
      reason: `netsh-set-failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  await markTapStatic(markerPath, adapter, ip);
  return { applied: true, ip };
}

/**
 * Devuelve el adaptador a DHCP si la dirección fija la puso rud1 (hay marca).
 * Una IP fija que configuró el usuario a mano no se toca. Nunca lanza.
 */
export async function restoreTapDhcpIfOurs(adapter: string, markerPath: string): Promise<boolean> {
  if (process.platform !== "win32") return false;
  try {
    await fs.access(markerPath);
  } catch {
    return false;
  }
  try {
    await execFileAsync("netsh", buildSetDhcpArgs(adapter), { timeout: NETSH_TIMEOUT_MS });
  } catch {
    // netsh también falla cuando el DHCP ya estaba activo ("ya está
    // habilitado"); eso es el estado buscado. Cualquier otro fallo deja la
    // marca para reintentarlo en la próxima conexión.
    if (!(await isDhcpEnabled(adapter))) return false;
  }
  await fs.rm(markerPath, { force: true }).catch(() => undefined);
  return true;
}

/** Lee "DHCP habilitado: Sí" / "DHCP enabled: Yes" de `netsh ... show config`. */
export function parseDhcpEnabled(netshConfig: string): boolean {
  // Se mira solo si dice "No": la í de "Sí" puede llegar como otro carácter
  // según la página de códigos con la que escriba netsh.
  const m = /DHCP\s+(?:enabled|habilitado):\s*(\S+)/i.exec(netshConfig);
  return !!m && !/^no$/i.test(m[1]);
}

async function isDhcpEnabled(adapter: string): Promise<boolean> {
  try {
    const { stdout } = await execFileAsync(
      "netsh",
      ["interface", "ipv4", "show", "config", `name=${adapter}`],
      { timeout: NETSH_TIMEOUT_MS },
    );
    return parseDhcpEnabled(stdout);
  } catch {
    return false;
  }
}
