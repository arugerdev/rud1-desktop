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
 *   diag:compareReports    — read two reports and return a structured diff (deltas, swapped flag)
 *   diag:autoSnapshotStatus    — return the persisted opt-in snapshot config + next-run timestamp
 *   diag:autoSnapshotConfigure — persist opt-in, interval, and diagnosis options; (re)start timer
 *   diag:autoSnapshotRunNow    — trigger a snapshot immediately (does not change the schedule)
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
  compareReports,
} from "./tunnel-diag-manager";
import {
  configureAutoSnapshot,
  getAutoSnapshotStatus,
  triggerAutoSnapshotNow,
} from "./auto-snapshot-manager";
import { getStats as getSystemStats } from "./system-manager";
import { probeFirmware } from "./firmware-discovery";

const ALLOWED_ORIGIN = process.env.RUD1_APP_ORIGIN ?? "https://rud1.es";

// Control-character + whitespace + quote rejection list, applied against the
// RAW sender URL BEFORE any URL parsing. WHATWG URL happily canonicalises
// \n / \r / tabs / nulls into their percent-encoded forms, so a naive
// post-parse check would miss CRLF-injection shapes like
// `https://rud1.es\r\nSet-Cookie:...`. We refuse them at the boundary.
const UNSAFE_URL_CHARS = /[\x00-\x1f\x7f\s"<>\\^`{|}]/;

// Hard cap so a megabyte sender URL from a compromised frame can't OOM the
// URL parser or flood logs.
const MAX_SENDER_URL_LENGTH = 2048;

/**
 * Pure predicate used by `checkSender`. Separated so it is unit-testable
 * without an Electron main-process stub.
 *
 * Security invariants (see also the iter-22 test suite):
 *   • the RAW input must be a non-empty string, length-capped, and free of
 *     control/whitespace/quote characters — applied BEFORE `new URL()` so
 *     WHATWG canonicalisation cannot mask a CRLF or null-byte injection.
 *   • the URL must parse.
 *   • for the production origin: scheme + host (+ optional port) must match
 *     ALLOWED_ORIGIN exactly — NOT a `startsWith` compare, which would let
 *     `https://rud1.es.evil.com/` through. We compare `u.origin` against the
 *     parsed ALLOWED_ORIGIN's origin.
 *   • for dev mode (only when `app.isPackaged === false`): hostname must be
 *     exactly `localhost` or `127.0.0.1`, scheme `http:` or `https:`. Again,
 *     exact hostname match — no `startsWith`.
 */
export function isOriginAllowed(
  rawUrl: unknown,
  opts: { isPackaged: boolean; allowedOrigin?: string } = { isPackaged: true },
): boolean {
  if (typeof rawUrl !== "string") return false;
  if (rawUrl.length === 0 || rawUrl.length > MAX_SENDER_URL_LENGTH) return false;
  if (UNSAFE_URL_CHARS.test(rawUrl)) return false;

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }

  // Reject dangerous schemes outright. `new URL("javascript:alert(1)")`
  // parses with protocol "javascript:" — explicit allowlist is safer than
  // blocklist. We only accept http/https here.
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;

  // Userinfo components can be used to smuggle credentials and to bypass
  // naive hostname-allowlist checks in downstream consumers.
  if (parsed.username !== "" || parsed.password !== "") return false;

  if (!opts.isPackaged) {
    // Dev-mode: localhost or 127.0.0.1 with http OR https, exact hostname.
    if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") {
      return true;
    }
    // Fall through to the production origin check so a dev build pointed at
    // a real origin (via RUD1_APP_ORIGIN) still works.
  }

  const allowedOrigin = opts.allowedOrigin ?? ALLOWED_ORIGIN;
  let allowed: URL;
  try {
    allowed = new URL(allowedOrigin);
  } catch {
    return false;
  }
  // `URL.origin` normalises scheme + host + port; it omits path/query/hash.
  // Equality here forbids prefix smuggling like `https://rud1.es.evil.com/`
  // AND subdomain smuggling like `https://evil.rud1.es/`.
  return parsed.origin === allowed.origin;
}

function checkSender(event: Electron.IpcMainInvokeEvent): boolean {
  // senderFrame may be null if the frame was disposed between the renderer
  // dispatching the message and the main process picking it up. Treat as a
  // failed sender check — handlers return the "Unauthorized origin" envelope.
  const url = event.senderFrame?.url;
  if (typeof url !== "string") return false;
  return isOriginAllowed(url, { isPackaged: app.isPackaged });
}

// Test-only surface. Not re-exported from the package entry point; only
// imported by ipc-handlers.test.ts. Matches the `__test` pattern used in
// auto-updater.ts (iter 21).
export const __test = {
  isOriginAllowed,
  checkSender,
  UNSAFE_URL_CHARS,
  MAX_SENDER_URL_LENGTH,
  ALLOWED_ORIGIN,
};

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

  ipcMain.handle(
    "diag:compareReports",
    async (event, args: { pathA: string; pathB: string }) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        if (
          !args ||
          typeof args !== "object" ||
          typeof args.pathA !== "string" ||
          typeof args.pathB !== "string"
        ) {
          return { ok: false, error: "invalid args" };
        }
        const result = await compareReports({ pathA: args.pathA, pathB: args.pathB });
        return { ok: true, result };
      } catch (err) {
        return {
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  );

  ipcMain.handle("diag:autoSnapshotStatus", async (event) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      return { ok: true, result: getAutoSnapshotStatus() };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle(
    "diag:autoSnapshotConfigure",
    async (
      event,
      next: {
        enabled: boolean;
        intervalMs?: number;
        opts?: {
          wgInterface?: string;
          wgHost?: string;
          publicHost?: string;
          publicPort?: number;
          autoMtuProbe?: boolean;
          mtuProbeTimeoutMs?: number;
        };
      },
    ) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        if (!next || typeof next !== "object" || typeof next.enabled !== "boolean") {
          return { ok: false, error: "invalid args" };
        }
        const result = await configureAutoSnapshot(next);
        return { ok: true, result };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    },
  );

  ipcMain.handle("diag:autoSnapshotRunNow", async (event) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      // The manager already returns an envelope: success carries the new
      // status; "already running" is a soft failure that includes the current
      // status so the renderer can still refresh its view without a separate
      // round-trip.
      return await triggerAutoSnapshotNow();
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

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

  // setup:probeFirmware — best-effort discovery of a locally-reachable rud1
  // device. The renderer (cloud panel embedded in the BrowserWindow) calls
  // this to decide whether to surface a "Configure your rud1 now" banner.
  // The probe is rate-limited at the manager level by virtue of being short
  // and parallel; the renderer is expected to call it on app focus / tray
  // open, not on a fast timer.
  ipcMain.handle("setup:probeFirmware", async (event) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      const probe = await probeFirmware();
      return { ok: true, result: probe };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });
}
