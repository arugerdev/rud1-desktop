/**
 * Registers all Electron IPC handlers for the native bridge.
 * Called once from the main process after the app is ready.
 *
 * Channels (must match preload/index.ts):
 *   vpn:connect     — start WireGuard tunnel
 *   vpn:disconnect  — stop WireGuard tunnel
 *   vpn:status      — check tunnel status
 *   usb:attach      — attach a remote USB device via USB/IP
 *   usb:detach      — detach an attached USB device
 *   usb:list        — list currently attached devices
 *   app:version     — get app version
 *   app:platform    — get OS platform
 */

import { ipcMain, app } from "electron";
import { vpnConnect, vpnDisconnect, vpnStatus } from "./vpn-manager";
import { usbAttach, usbDetach, usbList } from "./usb-manager";

const ALLOWED_ORIGIN = process.env.RUD1_APP_ORIGIN ?? "https://rud1.es";

function checkSender(event: Electron.IpcMainInvokeEvent): boolean {
  const url = event.senderFrame?.url ?? "";
  // Allow localhost in dev mode
  if (!app.isPackaged && (url.startsWith("http://localhost") || url.startsWith("http://127.0.0.1"))) {
    return true;
  }
  return url.startsWith(ALLOWED_ORIGIN);
}

export function registerIpcHandlers(): void {
  ipcMain.handle("vpn:connect", async (event, wgConfig: string) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      await vpnConnect(wgConfig);
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle("vpn:disconnect", async (event) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      await vpnDisconnect();
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle("vpn:status", async (event) => {
    if (!checkSender(event)) return { connected: false };
    try {
      return await vpnStatus();
    } catch {
      return { connected: false };
    }
  });

  ipcMain.handle("usb:attach", async (event, host: string, busId: string) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      const port = await usbAttach(host, busId);
      return { ok: true, port };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle("usb:detach", async (event, port: number) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      await usbDetach(port);
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle("usb:list", async (event) => {
    if (!checkSender(event)) return [];
    try {
      return await usbList();
    } catch {
      return [];
    }
  });

  ipcMain.handle("app:version", () => app.getVersion());
  ipcMain.handle("app:platform", () => process.platform);
}
