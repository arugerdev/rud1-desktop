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

  net: {
    ping: (host: string) =>
      ipcRenderer.invoke("net:ping", host) as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          host: string;
          alive: boolean;
          avgRttMs: number | null;
          lossPct: number;
          raw: string;
        };
      }>,

    interfaces: () =>
      ipcRenderer.invoke("net:interfaces") as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          name: string;
          mac: string;
          up: boolean;
          internal: boolean;
          addresses: { address: string; cidr: string | null; family: "IPv4" | "IPv6" }[];
        }[];
      }>,

    resolveRoute: (destination: string) =>
      ipcRenderer.invoke("net:resolveRoute", destination) as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          destination: string;
          iface: string | null;
          gateway: string | null;
          raw: string;
        };
      }>,

    traceroute: (host: string) =>
      ipcRenderer.invoke("net:traceroute", host) as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          host: string;
          hops: { index: number; host: string | null; rttMs: number | null }[];
          raw: string;
        };
      }>,

    dnsLookup: (hostname: string) =>
      ipcRenderer.invoke("net:dnsLookup", hostname) as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          hostname: string;
          a: string[];
          aaaa: string[];
          cname: string | null;
        };
      }>,
  },

  app: {
    getVersion: () =>
      ipcRenderer.invoke("app:version") as Promise<string>,

    getPlatform: () =>
      ipcRenderer.invoke("app:platform") as Promise<NodeJS.Platform>,
  },
});
