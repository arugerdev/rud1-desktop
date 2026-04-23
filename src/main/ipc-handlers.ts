/**
 * Registers all Electron IPC handlers for the native bridge.
 * Called once from the main process after the app is ready.
 *
 * Channels (must match preload/index.ts):
 *   vpn:connect       — start WireGuard tunnel
 *   vpn:disconnect    — stop WireGuard tunnel
 *   vpn:status        — check tunnel status
 *   usb:attach        — attach a remote USB device via USB/IP
 *   usb:detach        — detach an attached USB device
 *   usb:list          — list currently attached devices
 *   net:ping          — ICMP reachability probe (LAN-route diagnostics)
 *   net:interfaces    — enumerate local NICs
 *   net:resolveRoute  — which local iface egresses packets to an IP
 *   net:traceroute    — hop-by-hop path with RTT per hop
 *   net:dnsLookup     — A / AAAA / CNAME records for a hostname
 *   net:publicIp      — detect operator's public IPv4 / IPv6 via ipify
 *   net:portCheck     — TCP connect probe with timeout + latency
 *   diag:wgStatus     — parsed `wg show` output (tunnels + peers)
 *   diag:tunnelHealth — combined WG/public ping + TCP probe + verdict
 *   diag:mtuProbe     — DF-flag bisect ping to discover path MTU
 *   diag:fullDiagnosis — consolidated wgStatus + tunnelHealth + systemStats (parallel)
 *   diag:exportReport — serialize fullDiagnosis to ~/.rud1/diag/ with sha256 integrity
 *   diag:listReports  — enumerate previously-written reports under ~/.rud1/diag/
 *   diag:readReport   — read + sha256 + JSON.parse a report (path-traversal guarded)
 *   diag:deleteReport — unlink a report file (path-traversal guarded)
 *   diag:openReportsFolder — reveal ~/.rud1/diag/ in the OS file explorer
 *   diag:saveReportCopy    — copy a report to a user-chosen location via Save As dialog
 *   system:stats      — CPU/memory/interfaces/uptime snapshot for diagnostics
 *   app:version       — get app version
 *   app:platform      — get OS platform
 */

import { ipcMain, app, BrowserWindow } from "electron";
import { vpnConnect, vpnDisconnect, vpnStatus } from "./vpn-manager";
import { usbAttach, usbDetach, usbList } from "./usb-manager";
import {
  ping,
  interfaces,
  resolveRoute,
  traceroute,
  dnsLookup,
  publicIp,
  portCheck,
} from "./net-diag-manager";
import {
  wgStatus,
  tunnelHealth,
  mtuProbe,
  fullDiagnosis,
  exportReport,
  listReports,
  readReport,
  deleteReport,
  openReportsFolder,
  saveReportCopy,
} from "./tunnel-diag-manager";
import { getStats as getSystemStats } from "./system-manager";

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

  ipcMain.handle("net:ping", async (event, host: string) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      const result = await ping(host);
      return { ok: true, result };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle("net:interfaces", async (event) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      return { ok: true, result: interfaces() };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle("net:resolveRoute", async (event, destination: string) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      const result = await resolveRoute(destination);
      return { ok: true, result };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle("net:traceroute", async (event, host: string) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      const result = await traceroute(host);
      return { ok: true, result };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle("net:dnsLookup", async (event, hostname: string) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      const result = await dnsLookup(hostname);
      return { ok: true, result };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle("net:publicIp", async (event) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      const result = await publicIp();
      return { ok: true, result };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle(
    "net:portCheck",
    async (
      event,
      opts: { host: string; port: number; timeoutMs?: number },
    ) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        const result = await portCheck(opts);
        return { ok: true, result };
      } catch (err) {
        return {
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  );

  ipcMain.handle("diag:wgStatus", async (event, tunnelName?: string) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      const result = await wgStatus(tunnelName);
      return { ok: true, result };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle(
    "diag:tunnelHealth",
    async (
      event,
      opts: {
        wgHost: string;
        publicHost: string;
        publicPort: number;
        timeoutMs?: number;
        autoMtuProbe?: boolean;
        mtuProbeTimeoutMs?: number;
      },
    ) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        const result = await tunnelHealth(opts);
        return { ok: true, result };
      } catch (err) {
        return {
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  );

  ipcMain.handle(
    "diag:mtuProbe",
    async (
      event,
      args: { host: string; opts?: { start?: number; min?: number; timeoutMs?: number } },
    ) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        if (!args || typeof args !== "object" || typeof args.host !== "string") {
          return { ok: false, error: "invalid args" };
        }
        const result = await mtuProbe(args.host, args.opts);
        return { ok: true, result };
      } catch (err) {
        return {
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  );

  ipcMain.handle(
    "diag:fullDiagnosis",
    async (
      event,
      opts?: {
        wgInterface?: string;
        wgHost?: string;
        publicHost?: string;
        publicPort?: number;
        autoMtuProbe?: boolean;
        mtuProbeTimeoutMs?: number;
      },
    ) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        const result = await fullDiagnosis(opts);
        return { ok: true, result };
      } catch (err) {
        // fullDiagnosis is designed to never throw, but keep the envelope
        // symmetrical with the other diag:* channels just in case.
        return {
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  );

  ipcMain.handle(
    "diag:exportReport",
    async (
      event,
      opts?: {
        wgInterface?: string;
        wgHost?: string;
        publicHost?: string;
        publicPort?: number;
        autoMtuProbe?: boolean;
        mtuProbeTimeoutMs?: number;
      },
    ) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        const result = await exportReport(opts ?? {});
        return { ok: true, result };
      } catch (err) {
        return {
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  );

  ipcMain.handle("diag:listReports", async (event) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      const result = await listReports();
      return { ok: true, result };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  });

  ipcMain.handle("diag:readReport", async (event, reportPath: string) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      const result = await readReport(reportPath);
      return { ok: true, result };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  });

  ipcMain.handle("diag:deleteReport", async (event, reportPath: string) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      const result = await deleteReport(reportPath);
      return { ok: true, result };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  });

  ipcMain.handle("diag:openReportsFolder", async (event) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      const result = await openReportsFolder();
      return { ok: true, result };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  });

  ipcMain.handle(
    "diag:saveReportCopy",
    async (event, opts: { path: string; defaultFilename?: string }) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        // Anchor the native dialog to the invoking window when possible so
        // macOS renders it as a sheet. `BrowserWindow.fromWebContents` may
        // return null (e.g. sender is a detached webview) — saveReportCopy
        // accepts null and falls back to a free-floating dialog.
        const parentWindow = BrowserWindow.fromWebContents(event.sender);
        const result = await saveReportCopy({
          path: opts?.path,
          defaultFilename: opts?.defaultFilename,
          parentWindow,
        });
        return { ok: true, result };
      } catch (err) {
        return {
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  );

  ipcMain.handle("system:stats", async (event) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      const result = await getSystemStats();
      return { ok: true, result };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle("app:version", () => app.getVersion());
  ipcMain.handle("app:platform", () => process.platform);
}
