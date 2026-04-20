/**
 * Preload script — runs in an isolated context before the renderer page loads.
 * Exposes the native API to the web app via contextBridge.
 *
 * The web app accesses these methods via window.electronAPI.
 * Type declarations for window.electronAPI are in src/types/electron.d.ts
 * (or defined in the web app itself).
 */

import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("electronAPI", {
  vpn: {
    connect: (wgConfig: string) =>
      ipcRenderer.invoke("vpn:connect", wgConfig) as Promise<{ ok: boolean; error?: string }>,

    disconnect: () =>
      ipcRenderer.invoke("vpn:disconnect") as Promise<{ ok: boolean; error?: string }>,

    status: () =>
      ipcRenderer.invoke("vpn:status") as Promise<{ connected: boolean; ip?: string }>,
  },

  usb: {
    attach: (host: string, busId: string) =>
      ipcRenderer.invoke("usb:attach", host, busId) as Promise<{ ok: boolean; port?: number; error?: string }>,

    detach: (port: number) =>
      ipcRenderer.invoke("usb:detach", port) as Promise<{ ok: boolean; error?: string }>,

    list: () =>
      ipcRenderer.invoke("usb:list") as Promise<{ port: number; host: string; busId: string }[]>,
  },

  app: {
    getVersion: () =>
      ipcRenderer.invoke("app:version") as Promise<string>,

    getPlatform: () =>
      ipcRenderer.invoke("app:platform") as Promise<NodeJS.Platform>,
  },
});
