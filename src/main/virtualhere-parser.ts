// Parser puro de la salida del comando LIST del cliente VirtualHere.
// Aislado de virtualhere-manager (que importa electron.app via
// binary-helper) para que los tests no necesiten un contexto Electron.

export interface VirtualHereDevice {
  address: string;
  vendorId: string;
  productId: string;
  serial?: string;
  productName?: string;
  vendorName?: string;
  inUse: boolean;
  inUseByThisClient: boolean;
}

export interface VirtualHereHub {
  serverName: string;
  endpoint: string;
  devices: VirtualHereDevice[];
}

/**
 * Parsea la salida de LIST. Formato típico:
 *
 *   VirtualHere Client IPC, below are the available devices:
 *   (Value in brackets = address, * = Auto-Use)
 *
 *   rud1 (rud1-CF0A:7575)
 *     --> Arduino Uno (rud1-CF0A.114)
 *
 *   Auto-Find currently on
 *   Auto-Use All currently off
 *   ...
 */
export function parseListOutput(out: string): VirtualHereHub[] {
  const hubs: VirtualHereHub[] = [];
  let current: VirtualHereHub | null = null;

  for (const raw of out.split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (!line) continue;
    // Footer: las líneas "Auto-Find", "Reverse", etc no son devices.
    if (/^(Auto-Find|Auto-Use|Reverse|VirtualHere)/i.test(line)) {
      current = null;
      continue;
    }
    // Hub heading: `<name> (<host>:<port>)` con UN paréntesis y puerto numérico
    // al final. Aceptamos opcionalmente sufijos "* = Auto-Use" pegados.
    const hubMatch = line.match(/^([^\s].*?)\s+\(([^()]+:\d+)\)\s*\*?\s*$/);
    if (hubMatch && !/in.?use|by you|vendor/i.test(line)) {
      current = {
        serverName: hubMatch[1]!.trim(),
        endpoint: hubMatch[2]!.trim(),
        devices: [],
      };
      hubs.push(current);
      continue;
    }
    if (!current) continue;
    // Device line. Formato real del IPC LIST:
    //   `  --> (COM3) Arduino Uno (rud1-CF0A.114) (In use by you)`
    //   `  --> Arduino Uno (rud1-CF0A.114)`
    //   `  --> USB Disk (myhub.115) (in-use by 192.168.1.50)`
    //
    // El name puede llevar prefix entre paréntesis como `(COM3)` cuando
    // el device YA está attached y Windows le asignó COMxx. Recorremos
    // los paréntesis del final hacia atrás buscando el address (el
    // único formato `<hub>.<id>` con un punto). El resto (sufijos
    // "(in-use by X)") forman el tail; lo previo es el productName.
    const devLine = line.replace(/^\s*-+>\s*/, "");
    if (line.trimStart().startsWith("-->") || /^\s*-+>/.test(line)) {
      const parens = extractParens(devLine);
      // Busca el address: `<hub_or_alpha>.<id_alpha_num>` sin espacios.
      const addrIdx = parens.findIndex((p) =>
        /^[A-Za-z0-9-]+\.[A-Za-z0-9]+$/.test(p.content.trim()),
      );
      if (addrIdx < 0) continue;
      const addressContent = parens[addrIdx]!.content.trim();
      // productName = todo antes del paréntesis address, removed sufijos
      // pre-name como `(COM3) `.
      const before = devLine.slice(0, parens[addrIdx]!.start).trim();
      // Quita prefijos paréntesis tipo "(COM3)" del nombre.
      const productName = before.replace(/^\([^()]*\)\s*/, "").trim() || undefined;
      // Tail: todo después del address paren, donde están los flags.
      const tail = devLine.slice(parens[addrIdx]!.end).trim();
      const inUse = /\b(in.?use|by you|by this|by\b)/i.test(tail);
      const inUseByThisClient = /by you/i.test(tail) || /by this/i.test(tail);
      current.devices.push({
        address: addressContent,
        vendorId: "",
        productId: "",
        productName,
        inUse,
        inUseByThisClient,
      });
      continue;
    }
  }
  return hubs;
}

/** Devuelve cada `(...)` top-level con su offset en el string. */
function extractParens(s: string): Array<{ content: string; start: number; end: number }> {
  const out: Array<{ content: string; start: number; end: number }> = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "(") {
      if (depth === 0) start = i;
      depth++;
    } else if (s[i] === ")") {
      depth--;
      if (depth === 0 && start >= 0) {
        out.push({ content: s.slice(start + 1, i), start, end: i + 1 });
        start = -1;
      }
    }
  }
  return out;
}
