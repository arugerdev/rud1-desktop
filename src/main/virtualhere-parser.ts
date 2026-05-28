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
    // Hub heading: `<name> (<host>:<port>)` sin "vendor" en la línea
    const hubMatch = line.match(/^([^\s].*?)\s+\(([^()]+:\d+)\)\s*$/);
    if (hubMatch && !line.includes("vendor")) {
      current = {
        serverName: hubMatch[1]!.trim(),
        endpoint: hubMatch[2]!.trim(),
        devices: [],
      };
      hubs.push(current);
      continue;
    }
    if (!current) continue;
    // Device line: `--> <name> (<hub>.<address>)` con sufijos opcionales
    const devMatch = line.match(/^\s*-+>\s*(.+?)\s+\(([^()]+\.[\dA-Za-z]+)\)(.*)$/);
    if (devMatch) {
      const tail = devMatch[3] || "";
      const inUse = /\b(in-use|in use)\b/i.test(tail);
      const inUseByThisClient = /by you/i.test(tail) || /by this/i.test(tail);
      current.devices.push({
        address: devMatch[2]!.trim(),
        vendorId: "",
        productId: "",
        productName: devMatch[1]!.trim() || undefined,
        inUse,
        inUseByThisClient,
      });
      continue;
    }
  }
  return hubs;
}
