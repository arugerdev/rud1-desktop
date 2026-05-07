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
 *   firstBootDedupe:list       — list persisted notified-host records (iter 28 Settings UI)
 *   firstBootDedupe:clearHost  — drop a single host from the persisted dedupe set
 *   firstBootDedupe:clearAll   — drop ALL hosts from the persisted dedupe set
 *   versionCheck:state         — snapshot the live VersionCheckState (iter 37 Settings/About)
 *   versionCheck:recheck       — trigger an immediate version-check refetch
 *   clipboard:writeText        — copy a string to the OS clipboard (iter 37, length-capped)
 *   shell:openExternal         — open an http/https URL in the system browser (iter 37, allowlisted)
 *   system:stats      — CPU/memory/interfaces/uptime snapshot for diagnostics
 *   app:version       — get app version
 *   app:platform      — get OS platform
 */

import { ipcMain, app, BrowserWindow, clipboard, shell } from "electron";
import { getAutoStart, setAutoStart } from "./auto-start-manager";
import {
  getPreferences,
  setPreferences,
  type PreferencesPatch,
} from "./preferences-manager";
import {
  fetchHandshakeStdout,
  getLastWgConfig,
  vpnConnect,
  vpnDisconnect,
  vpnStatus,
  inspectConfig,
  formatUptimeMs,
} from "./vpn-manager";
import {
  VpnHealthMonitor,
  parseHandshakeSnapshot,
} from "./vpn-health-monitor";
import {
  usbAttach,
  usbDetach,
  usbDetachAll,
  usbDetachByBusId,
  usbList,
  isUsbipInstalled,
  getUsbipInstallerPath,
  UsbipMissingError,
} from "./usb-manager";
import {
  serialBridgeOpen,
  serialBridgeClose,
  serialBridgeCloseAll,
  serialBridgeStatus,
  serialBridgeSessionFor,
  serialBridgeConfigurePair,
  serialBridgeReset,
  Com0comMissingError,
  Com0comPairNotAliasedError,
  Com0comPairNoEmuBRError,
} from "./serial-bridge-manager";
import { com0comInstallerPath } from "./binary-helper";
import {
  notifyVpnConnected,
  notifyVpnCgnatWarning,
  notifyVpnDisconnected,
  notifyUsbAttached,
  notifyUsbDetached,
} from "./notifications";
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
import type { NotifiedHost } from "./first-boot-dedupe";
import type { VersionCheckState } from "./version-check-manager";

/**
 * Iter 28 — accessor surface that bridges the persisted first-boot
 * dedupe set in `index.ts` (which owns the in-memory mirror plus the
 * `<userData>/first-boot-notifications.json` filepath) to the IPC layer.
 *
 * `registerIpcHandlers` is called BEFORE `app.whenReady()` resolves the
 * userData path, so the accessors can't capture concrete values; they
 * have to be late-bound via callbacks. The renderer-driven mutations
 * (`clearHost` / `clearAll`) MUST round-trip through index.ts so the
 * in-memory `notifiedHosts` and the persisted JSON stay in lockstep —
 * otherwise the next probe tick would re-add a host the operator just
 * cleared.
 *
 * Optional because the iter-22 ipc-handlers tests construct the registrar
 * without this hook; the firstBootDedupe channels simply skip
 * registration when the accessor is absent.
 */
export interface FirstBootDedupeAccessor {
  list: () => readonly NotifiedHost[];
  clearHost: (host: string) => Promise<readonly NotifiedHost[]>;
  clearAll: () => Promise<void>;
}

/**
 * Iter 37 — accessor surface for the Settings/About panel's "Updates"
 * section. The panel needs read access to the live `VersionCheckState`
 * (so it can render the iter-36 blocked-state banner among other
 * verdicts) plus a notification hook so main can push state transitions
 * without the renderer polling. Mirrors the iter-28 first-boot-dedupe
 * accessor pattern verbatim — `registerIpcHandlers` is called BEFORE
 * `app.whenReady()` resolves and before the manager is constructed, so
 * we late-bind via callbacks and the channels skip registration when the
 * accessor is absent (keeps the iter-22 ipc-handlers test harness clean).
 *
 * `recheck` triggers an immediate re-poll; the renderer wires it to a
 * "Check for updates now" button. Best-effort — the manager's
 * `checkOnce` already handles overlapping fetches by racing to the
 * latest state.
 */
export interface VersionCheckAccessor {
  getState: () => VersionCheckState;
  recheck: () => void;
}

/**
 * Iter 7 — accessor for the persisted USB/IP attach state used by the
 * auto-reattach flow. The handler hooks into `usb:attach` /
 * `usb:detach` to keep the file in sync, and into `vpn:connect` to
 * trigger a sweep that re-attaches every persisted session after the
 * tunnel comes back up.
 *
 * `onVpnConnected` is fire-and-forget from the handler's perspective:
 * the VPN connect resolver doesn't wait on the attach sweep so a
 * single misbehaving USB doesn't block the connect notification.
 */
export interface UsbSessionStateAccessor {
  recordAttach: (entry: {
    host: string;
    busId: string;
    label?: string;
    port?: number;
  }) => Promise<void>;
  recordDetachByPort: (port: number) => Promise<void>;
  recordDetachByBusId: (busId: string) => Promise<void>;
  onVpnConnected: () => Promise<void>;
}

// Allowlist of origins the renderer frame can present and still be trusted
// for IPC. Comma-separated `RUD1_APP_ORIGIN` lets ops pin a single origin
// per environment (staging, dev, on-prem) without code changes.
//
// The default covers the two production hosts Vercel serves the app under:
// the apex (`https://rud1.es`) and the `www.` host (`https://www.rud1.es`).
// Whichever one the project's Vercel domain config marks as primary, the
// other becomes a 308 redirect — and the BrowserWindow follows the redirect,
// so by the time IPC fires the sender frame is on the canonical host. We
// accept both up front so the bridge doesn't fight the redirect.
//
// Each entry is still exact-matched at the URL.origin level (scheme + host
// + port). Adding `www.` to the allowlist does NOT loosen the
// subdomain-smuggling defenses for arbitrary subdomains like
// `https://evil.rud1.es/` — those still fail.
const ALLOWED_ORIGINS: readonly string[] = (() => {
  const raw = process.env.RUD1_APP_ORIGIN;
  if (raw && raw.trim().length > 0) {
    const parts = raw
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    if (parts.length > 0) return parts;
  }
  return ["https://rud1.es", "https://www.rud1.es"];
})();

// Control-character + whitespace + quote rejection list, applied against the
// RAW sender URL BEFORE any URL parsing. WHATWG URL happily canonicalises
// \n / \r / tabs / nulls into their percent-encoded forms, so a naive
// post-parse check would miss CRLF-injection shapes like
// `https://rud1.es\r\nSet-Cookie:...`. We refuse them at the boundary.
const UNSAFE_URL_CHARS = /[\x00-\x1f\x7f\s"<>\\^`{|}]/;

// Hard cap so a megabyte sender URL from a compromised frame can't OOM the
// URL parser or flood logs.
const MAX_SENDER_URL_LENGTH = 2048;

// Iter 37 — hard caps for the new clipboard / shell IPC channels so a
// compromised renderer (or a misbehaving Settings/About panel) can't push a
// runaway payload through. The clipboard cap is generous enough to hold a
// long download URL or a paragraph of release-note text but refuses anything
// resembling a paste-bomb. The shell cap is the same as the sender-URL cap.
const MAX_CLIPBOARD_TEXT_LENGTH = 8192;
const MAX_OPEN_EXTERNAL_URL_LENGTH = 2048;

/**
 * Iter 37 — allowlist for `shell:openExternal`. Restricted to http/https
 * only (no `javascript:`, `file:`, `data:`, `mailto:`, etc.) to keep a
 * compromised renderer from invoking the OS handler for a dangerous
 * scheme. Returns the parsed URL on success, null on rejection.
 *
 * No origin pinning here — the operator may legitimately follow a
 * release-notes URL or a download link to anywhere on the public web —
 * but the scheme allowlist is a hard requirement. Userinfo components
 * are also rejected (mirrors the policy in `isOriginAllowed` and
 * `isValidFeedUrl`) to block credential smuggling.
 */
export function isOpenExternalUrlAllowed(rawUrl: unknown): boolean {
  if (typeof rawUrl !== "string") return false;
  if (rawUrl.length === 0 || rawUrl.length > MAX_OPEN_EXTERNAL_URL_LENGTH) return false;
  if (UNSAFE_URL_CHARS.test(rawUrl)) return false;
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  if (parsed.username !== "" || parsed.password !== "") return false;
  return true;
}

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
  opts: {
    isPackaged: boolean;
    /** Single allowed origin (back-compat). Mutually exclusive with `allowedOrigins`. */
    allowedOrigin?: string;
    /** Multiple allowed origins. Each is exact-matched at URL.origin level. */
    allowedOrigins?: readonly string[];
  } = { isPackaged: true },
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

  // Resolve the candidate list. `allowedOrigin` (singular) is honoured for
  // back-compat; `allowedOrigins` wins when both are present. Empty array
  // is treated as "no override" so a misconfigured caller passing `[]`
  // doesn't accidentally allowlist nothing AND fall back to nothing.
  const candidates: readonly string[] = (() => {
    if (opts.allowedOrigins && opts.allowedOrigins.length > 0) return opts.allowedOrigins;
    if (opts.allowedOrigin) return [opts.allowedOrigin];
    return ALLOWED_ORIGINS;
  })();

  for (const candidate of candidates) {
    let allowed: URL;
    try {
      allowed = new URL(candidate);
    } catch {
      // A malformed entry in the allowlist must NOT silently widen the
      // check — skip it and let the others (if any) decide. If every
      // entry is malformed we fall through to the final `return false`,
      // which is fail-closed.
      continue;
    }
    // `URL.origin` normalises scheme + host + port; it omits path/query/hash.
    // Equality here forbids prefix smuggling like `https://rud1.es.evil.com/`
    // AND subdomain smuggling like `https://evil.rud1.es/` for any host that
    // isn't in the allowlist verbatim.
    if (parsed.origin === allowed.origin) return true;
  }
  return false;
}

/**
 * Iter 28 — registry of webContents IDs the main process opened itself
 * (e.g. the first-boot dedupe inspector). These are loaded from a `data:`
 * URL with a strict CSP and the same preload bridge as the cloud panel;
 * the URL would never pass `isOriginAllowed` (which requires http/https),
 * so checkSender consults this set instead. The main process is the sole
 * writer — markWebContentsTrusted is exported only for use within this
 * package (and the test surface).
 */
const trustedWebContentsIds = new Set<number>();

export function markWebContentsTrusted(id: number): void {
  trustedWebContentsIds.add(id);
}

export function unmarkWebContentsTrusted(id: number): void {
  trustedWebContentsIds.delete(id);
}

function checkSender(event: Electron.IpcMainInvokeEvent): boolean {
  // Trusted main-process-opened windows (e.g. iter 28 dedupe inspector)
  // bypass the origin URL check — they're loaded from `data:` URLs that
  // wouldn't pass isOriginAllowed, but the main process opened them and
  // controls their HTML byte-for-byte, so they're inherently trusted.
  // `event.sender` may be missing in synthetic test events; the
  // optional-chain keeps checkSender callable without a real
  // webContents stub.
  const senderId = event.sender?.id;
  if (typeof senderId === "number" && trustedWebContentsIds.has(senderId)) {
    return true;
  }
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
  ALLOWED_ORIGINS,
  trustedWebContentsIds,
  // Iter 37 — clipboard / shell allowlists.
  isOpenExternalUrlAllowed,
  MAX_CLIPBOARD_TEXT_LENGTH,
  MAX_OPEN_EXTERNAL_URL_LENGTH,
};

export function registerIpcHandlers(opts: {
  firstBootDedupe?: FirstBootDedupeAccessor;
  versionCheck?: VersionCheckAccessor;
  usbSessionState?: UsbSessionStateAccessor;
} = {}): void {
  // Per-port label cache for detach notifications. The renderer already
  // knows the human-readable name when it calls attach (vendor + product
  // from the cloud's UsbDevice row); we stash it here so the matching
  // detach notification can echo the same label without the renderer
  // having to thread it through a second IPC. Capped at 64 entries —
  // far above realistic concurrent attach counts on any sane setup.
  const usbLabelByPort = new Map<number, string>();
  function rememberUsbLabel(port: number, label: string | undefined) {
    if (!label) return;
    if (usbLabelByPort.size >= 64) {
      const firstKey = usbLabelByPort.keys().next().value;
      if (firstKey !== undefined) usbLabelByPort.delete(firstKey);
    }
    usbLabelByPort.set(port, label);
  }

  // Iter 8 — auto-reconnect monitor. Polls `wg show … latest-handshakes`
  // every 30 s after a successful connect; if the handshake age
  // crosses the stale threshold (3 min) it tears down + re-installs
  // the tunnel using the cached wgConfig in vpn-manager. The renderer
  // controls the kill switch via the `vpnAutoReconnect` preference;
  // the monitor reads it on every tick so a Settings flip takes
  // immediate effect without restarting the loop.
  const vpnHealthMonitor = new VpnHealthMonitor({
    fetchSnapshot: async () => {
      try {
        const stdout = await fetchHandshakeStdout();
        return parseHandshakeSnapshot(stdout, Date.now());
      } catch {
        // `wg show` failed (binary missing, tunnel torn down between
        // ticks). Treat as no-tunnel so the FSM doesn't pretend
        // the tunnel is stale and trigger a wasted reconnect.
        return { kind: "no-tunnel" };
      }
    },
    reconnect: async () => {
      const cfg = getLastWgConfig();
      if (!cfg) return;
      try {
        await vpnDisconnect();
      } catch {
        // Disconnect can fail if the service was already gone;
        // continue to the connect attempt anyway.
      }
      await vpnConnect(cfg);
    },
    enabled: () => {
      // Default: opted in. The renderer can flip the preference
      // off via Settings; getPreferences().vpnAutoReconnect ===
      // false short-circuits the loop.
      const prefs = getPreferences();
      return prefs.vpnAutoReconnect !== false;
    },
  });

  ipcMain.handle("vpn:connect", async (event, wgConfig: string) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    // Pre-flight: parse the config and surface non-fatal warnings (CGNAT,
    // missing Endpoint) on the response envelope. We still attempt the
    // connect — wireguard.exe will just sit there with no handshake — but
    // the renderer can show an actionable hint instead of a generic
    // "tunnel installed" toast that masks the real failure.
    const preflight = inspectConfig(typeof wgConfig === "string" ? wgConfig : "");
    try {
      await vpnConnect(wgConfig);
      // CGNAT path: fire the dedicated warning toast INSTEAD of the
      // generic success one. The tunnel is technically installed, but
      // calling it "Connected" would mislead the user into thinking
      // their handshake will succeed when the ISP-side CGNAT will
      // almost certainly drop the inbound UDP. Either path is exactly
      // one notification — we don't double-fire.
      if (preflight.cgnat) {
        notifyVpnCgnatWarning();
      } else {
        notifyVpnConnected();
      }
      // Auto-reattach persisted USB/IP sessions. Fire-and-forget so a
      // hung kernel module on one device doesn't block the connect
      // resolver — the sweep logs per-device errors and moves on.
      if (opts.usbSessionState) {
        void opts.usbSessionState.onVpnConnected().catch(() => undefined);
      }
      // Iter 8 — kick off the auto-reconnect health monitor. Idempotent:
      // start() is a no-op when the timer is already armed.
      vpnHealthMonitor.start();
      return {
        ok: true,
        endpoint: preflight.endpoint,
        cgnat: preflight.cgnat,
        hasEndpoint: preflight.hasEndpoint,
      };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
        endpoint: preflight.endpoint,
        cgnat: preflight.cgnat,
        hasEndpoint: preflight.hasEndpoint,
      };
    }
  });

  ipcMain.handle("vpn:disconnect", async (event) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    // Pre-flight: detach any USB devices currently attached over the
    // tunnel BEFORE we tear it down. Once the tunnel is gone the vhci
    // port is left pointing at an unreachable peer — every URB times
    // out and `usbip attach` to the same bus id fails with "port already
    // in use" until the operator manually runs `usbip detach -p <n>`.
    // Best-effort: failures here don't block the disconnect, they're
    // reported back so the renderer can paint a hint chip.
    let usbCleanup: { detached: number; failed: number } = {
      detached: 0,
      failed: 0,
    };
    try {
      const sweep = await usbDetachAll();
      // Drop any cached labels for ports we just released so a stale
      // entry doesn't surface in a future detach notification.
      for (const dev of sweep.detached) {
        usbLabelByPort.delete(dev.port);
        if (opts.usbSessionState) {
          await opts.usbSessionState
            .recordDetachByPort(dev.port)
            .catch(() => undefined);
        }
      }
      usbCleanup = {
        detached: sweep.detached.length,
        failed: sweep.failed.length,
      };
    } catch {
      // Swallow — the disconnect itself is the user-visible action and
      // a missing usbip binary or transient list failure shouldn't gate it.
    }
    // Serial bridge sessions are independent from USB/IP attachments
    // but ride the same WG tunnel — close them in the same sweep so
    // the rud1-bridge subprocesses don't sit on dead TCP sockets
    // waiting for a 30s keepalive timeout to notice the route is
    // gone. Failures are best-effort just like the USB sweep above.
    try {
      await serialBridgeCloseAll();
    } catch {
      // Same rationale as usbDetachAll: don't block VPN disconnect.
    }
    try {
      // Iter 59: capture uptime via the result envelope so the
      // notification toast can render "Tunnel dropped after 2h 14m".
      // Preserves the prior `{ok:true}` shape — `uptimeMs` is additive.
      const result = await vpnDisconnect();
      // Iter 8 — explicit user disconnect: stop the auto-reconnect
      // monitor so it doesn't immediately pull the tunnel back up.
      // Re-armed by the next vpn:connect.
      vpnHealthMonitor.stop();
      notifyVpnDisconnected(undefined, formatUptimeMs(result.uptimeMs));
      return {
        ok: true,
        uptimeMs: result.uptimeMs,
        usbDetached: usbCleanup.detached,
        usbDetachFailed: usbCleanup.failed,
      };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
        usbDetached: usbCleanup.detached,
        usbDetachFailed: usbCleanup.failed,
      };
    }
  });

  ipcMain.handle("vpn:status", async (event) => {
    // Iter 57: error / unauthorized paths must still satisfy the renderer's
    // VpnStatusResult shape (lifecycle stamps are part of the contract now);
    // returning a bare `{connected:false}` would break a strict consumer.
    // Iter 58 added `tunnelUptimeMs` to that contract — keep error paths in
    // sync so a strict TS consumer doesn't read `undefined` off the field.
    if (!checkSender(event)) {
      return {
        connected: false,
        lastConnectedAt: null,
        lastDisconnectedAt: null,
        tunnelUptimeMs: null,
      };
    }
    try {
      return await vpnStatus();
    } catch {
      return {
        connected: false,
        lastConnectedAt: null,
        lastDisconnectedAt: null,
        tunnelUptimeMs: null,
      };
    }
  });

  ipcMain.handle(
    "usb:attach",
    async (event, host: string, busId: string, label?: string) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        const port = await usbAttach(host, busId);
        rememberUsbLabel(port, label);
        notifyUsbAttached(label ?? null, busId);
        if (opts.usbSessionState) {
          await opts.usbSessionState
            .recordAttach({ host, busId, label, port })
            .catch(() => undefined);
        }
        return { ok: true, port };
      } catch (err) {
        // UsbipMissingError carries a structured `installerPath` so the
        // renderer can offer a one-click install instead of just
        // dumping the message string.
        if (err instanceof UsbipMissingError) {
          return {
            ok: false,
            error: err.message,
            usbipMissing: true,
            installerPath: err.installerPath,
          };
        }
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    },
  );

  ipcMain.handle("usb:detach", async (event, port: number) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      await usbDetach(port);
      const label = usbLabelByPort.get(port);
      usbLabelByPort.delete(port);
      // The bus id is unrecoverable from the port alone post-detach;
      // pass an empty string and let the helper render "USB detached"
      // when the cached label is also missing.
      notifyUsbDetached(label ?? null, "");
      if (opts.usbSessionState) {
        await opts.usbSessionState.recordDetachByPort(port).catch(() => undefined);
      }
      return { ok: true };
    } catch (err) {
      if (err instanceof UsbipMissingError) {
        return {
          ok: false,
          error: err.message,
          usbipMissing: true,
          installerPath: err.installerPath,
        };
      }
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  /**
   * Bus-ID-keyed detach for renderers that lost their port→bus map.
   * The renderer tracks attach state in React state, which gets reset on
   * page reload, navigation, or desktop restart — at which point clicking
   * Detach has only the bus id in hand. Resolves to the live `usbip port`
   * snapshot, finds the matching attachment, and runs the regular detach.
   * Idempotent: a bus id with no current attachment is a silent no-op.
   */
  ipcMain.handle("usb:detachByBusId", async (event, busId: string) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      await usbDetachByBusId(busId);
      // The label cache is keyed on port, not bus id, and the port is
      // not surfaced from usbDetachByBusId. We don't try to reconcile
      // here because the cache is bounded (64 entries, FIFO eviction)
      // and a stale entry only affects an unrelated future detach
      // notification's label string. Worst case: that notification
      // reads "USB device detached" instead of "Arduino Uno detached".
      notifyUsbDetached(null, busId);
      if (opts.usbSessionState) {
        await opts.usbSessionState.recordDetachByBusId(busId).catch(() => undefined);
      }
      return { ok: true };
    } catch (err) {
      if (err instanceof UsbipMissingError) {
        return {
          ok: false,
          error: err.message,
          usbipMissing: true,
          installerPath: err.installerPath,
        };
      }
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

  // Status probe used by the panel to decide whether to surface the
  // "Install USB/IP" CTA before the user even tries Attach.
  ipcMain.handle("usb:status", async (event) => {
    if (!checkSender(event)) {
      return { ok: false, error: "Unauthorized origin" } as const;
    }
    return {
      ok: true as const,
      installed: isUsbipInstalled(),
      installerPath: getUsbipInstallerPath(),
      platform: process.platform,
    };
  });

  // Launches the bundled NSIS installer with elevation so the user
  // can complete the kernel-driver install in one click. Returns
  // immediately after spawning — the installer's own UI walks the
  // user through driver acceptance. We do NOT await `wait=true`:
  // a busy modal blocking the Electron main process is worse UX
  // than letting the user retry Attach after closing the installer.
  ipcMain.handle("usb:launchInstaller", async (event) => {
    if (!checkSender(event)) {
      return { ok: false, error: "Unauthorized origin" } as const;
    }
    if (process.platform !== "win32") {
      return {
        ok: false,
        error: "USB/IP installer is bundled only for Windows builds.",
      } as const;
    }
    const path = getUsbipInstallerPath();
    if (!path) {
      return {
        ok: false,
        error: "Bundled USB/IP installer missing — re-run npm run fetch:usbip-win.",
      } as const;
    }
    // shell.openPath uses the OS file association. For a .exe that
    // means `ShellExecute` with the default verb, which honours the
    // installer's manifest (`requireAdministrator`) and triggers UAC
    // automatically. Returns the empty string on success.
    const result = await shell.openPath(path);
    if (result !== "") {
      return { ok: false, error: result } as const;
    }
    return { ok: true as const };
  });

  // ── Serial bridge — alternate transport for CDC-class devices ─────────
  //
  // The cloud's Connect tab routes Arduino-style devices through this
  // path instead of USB/IP because the kernel `usbip_host` module is
  // unstable when CDC interfaces re-enumerate (avrdude DTR-toggle
  // reset). The renderer calls `serial:open` with the bus id + the
  // Pi-side TCP port (returned by the Pi's POST /api/serial-bridge/open),
  // we spawn the bundled rud1-bridge Go binary, and surface back a
  // local path the user opens in their Arduino IDE.

  ipcMain.handle(
    "serial:open",
    async (event, opts: {
      busId: string;
      piHost: string;
      baud?: number;
      dataBits?: number;
      parity?: string;
      stopBits?: string;
      label?: string;
    }) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        const result = await serialBridgeOpen(opts);
        return { ok: true as const, result };
      } catch (err) {
        if (err instanceof Com0comMissingError) {
          return {
            ok: false as const,
            error: err.message,
            com0comMissing: true,
            setupcPath: err.setupcPath,
            hasPairs: err.hasPairs,
          };
        }
        if (err instanceof Com0comPairNotAliasedError) {
          return {
            ok: false as const,
            error: err.message,
            com0comPairNotAliased: true,
            pair: err.pair,
            setupcPath: err.setupcPath,
          };
        }
        if (err instanceof Com0comPairNoEmuBRError) {
          return {
            ok: false as const,
            error: err.message,
            com0comPairNoEmuBR: true,
            pair: err.pair,
            setupcPath: err.setupcPath,
          };
        }
        return {
          ok: false as const,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  );

  ipcMain.handle("serial:close", async (event, busId: string) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      await serialBridgeClose(busId);
      return { ok: true as const };
    } catch (err) {
      return {
        ok: false as const,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  });

  // Manual DTR pulse for an open bridge session. Wraps the firmware's
  // POST /api/serial-bridge/reset; the renderer surfaces this as a
  // "Reset" button next to a bridged device. Common use case: an
  // Arduino IDE upload that the operator's client didn't trigger via
  // RFC 2217 (raw TCP scopes, com0com pairs that mishandle modem
  // control IOCTLs across the virtual pair).
  ipcMain.handle(
    "serial:reset",
    async (event, opts: { busId: string; piHost: string; pulseMs?: number }) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        await serialBridgeReset(opts);
        return { ok: true as const };
      } catch (err) {
        return {
          ok: false as const,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  );

  ipcMain.handle("serial:status", async (event) => {
    if (!checkSender(event)) {
      return { ok: false as const, error: "Unauthorized origin" };
    }
    try {
      const result = await serialBridgeStatus();
      return { ok: true as const, result };
    } catch (err) {
      return {
        ok: false as const,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  });

  ipcMain.handle("serial:sessionFor", async (event, busId: string) => {
    if (!checkSender(event)) {
      return { ok: false as const, error: "Unauthorized origin" };
    }
    try {
      const result = serialBridgeSessionFor(busId);
      return { ok: true as const, result };
    } catch (err) {
      return {
        ok: false as const,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  });

  // Configure a com0com pair by assigning COMxx aliases. Triggers
  // a UAC prompt because setupc.exe needs admin to write the kernel
  // driver's IOCTLs. Idempotent: if a pair is already aliased, returns
  // the existing pair. Defaults to COM200 / COM201 (deliberately high
  // numbers so they don't collide with the operator's real COM ports).
  ipcMain.handle(
    "serial:configurePair",
    async (event, opts?: { userPortAlias?: string; bridgePortAlias?: string }) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        const pair = await serialBridgeConfigurePair(opts);
        return { ok: true as const, result: pair };
      } catch (err) {
        if (err instanceof Com0comMissingError) {
          return {
            ok: false as const,
            error: err.message,
            com0comMissing: true,
          };
        }
        return {
          ok: false as const,
          error: err instanceof Error ? err.message : String(err),
        };
      }
    },
  );

  // Launches the bundled com0com installer with elevation so the user
  // can complete the kernel-driver install in one click. Symmetric to
  // `usb:launchInstaller`. Returns immediately after spawning — the
  // installer's own UI walks the user through driver acceptance.
  ipcMain.handle("serial:launchInstaller", async (event) => {
    if (!checkSender(event)) {
      return { ok: false, error: "Unauthorized origin" } as const;
    }
    if (process.platform !== "win32") {
      return {
        ok: false,
        error: "com0com is bundled only for Windows builds.",
      } as const;
    }
    const installerPath = com0comInstallerPath();
    if (!installerPath) {
      return {
        ok: false,
        error: "Bundled com0com installer missing — re-run npm run fetch:com0com-win.",
      } as const;
    }
    // shell.openPath uses ShellExecute → triggers UAC for the signed
    // installer's `requireAdministrator` manifest. Empty string on
    // success.
    const result = await shell.openPath(installerPath);
    if (result !== "") {
      return { ok: false, error: result } as const;
    }
    return { ok: true as const };
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

  // Auto-start (per-user "launch at login"). Read-side is cheap so we
  // re-query on every renderer refresh rather than caching — the panel
  // shows the live OS state without us having to invalidate on toggle.
  ipcMain.handle("app:getAutoStart", async (event) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    try {
      const state = await getAutoStart();
      return { ok: true, result: state };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  });

  ipcMain.handle("app:setAutoStart", async (event, enabled: unknown) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    if (typeof enabled !== "boolean") {
      return { ok: false, error: "enabled must be a boolean" };
    }
    try {
      const state = await setAutoStart(enabled);
      return { ok: true, result: state };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  });

  // Persisted user preferences (theme + per-category notification
  // toggles). The Settings window reads on mount and writes on every
  // toggle. Validation is shape-only here; preferences-manager re-
  // validates and falls back to safe defaults so a malformed patch
  // can't corrupt the cache.
  ipcMain.handle("app:getPreferences", (event) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    return { ok: true, result: getPreferences() };
  });

  ipcMain.handle("app:setPreferences", async (event, rawPatch: unknown) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    if (!rawPatch || typeof rawPatch !== "object") {
      return { ok: false, error: "patch must be an object" };
    }
    const patch = rawPatch as Record<string, unknown>;
    const cleaned: PreferencesPatch = {};
    if (
      patch.theme === "system" ||
      patch.theme === "light" ||
      patch.theme === "dark"
    ) {
      cleaned.theme = patch.theme;
    }
    const rawN = patch.notifications;
    if (rawN && typeof rawN === "object") {
      const n = rawN as Record<string, unknown>;
      const partial: PreferencesPatch["notifications"] = {};
      if (typeof n.firstBoot === "boolean") partial.firstBoot = n.firstBoot;
      if (typeof n.vpn === "boolean") partial.vpn = n.vpn;
      if (typeof n.usb === "boolean") partial.usb = n.usb;
      if (Object.keys(partial).length > 0) cleaned.notifications = partial;
    }
    if (typeof patch.vpnAutoReconnect === "boolean") {
      cleaned.vpnAutoReconnect = patch.vpnAutoReconnect;
    }
    try {
      const result = await setPreferences(cleaned);
      return { ok: true, result };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  });

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

  // ─── iter 28: first-boot dedupe inspection / management ─────────────────
  // The renderer-side Settings panel calls these to surface and mutate the
  // persisted notified-hosts set. All three channels are gated on the
  // origin check like every other IPC; they're additionally gated on
  // `opts.firstBootDedupe` being supplied — the iter-22 unit-test harness
  // constructs the registrar bare, and we don't want it to accidentally
  // expose stub behaviour.
  const dedupe = opts.firstBootDedupe;
  if (dedupe) {
    ipcMain.handle("firstBootDedupe:list", (event) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        // Defensive copy: callers must not mutate the in-memory mirror.
        return { ok: true, result: dedupe.list().map((h) => ({ ...h })) };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    });

    ipcMain.handle("firstBootDedupe:clearHost", async (event, host: unknown) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      // Mirror the SAFE_HOST_RE shape used by firmware-discovery so a
      // compromised renderer can't push a 100KB string through here.
      if (typeof host !== "string" || host.length === 0 || host.length > 253) {
        return { ok: false, error: "invalid host" };
      }
      try {
        const remaining = await dedupe.clearHost(host);
        return { ok: true, result: remaining.map((h) => ({ ...h })) };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    });

    ipcMain.handle("firstBootDedupe:clearAll", async (event) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        await dedupe.clearAll();
        return { ok: true };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    });
  }

  // ─── iter 37: version-check state surface for Settings/About panel ──────
  // The renderer-side Settings/About panel calls `versionCheck:state` to
  // read the live `VersionCheckState` and subscribes to push updates via
  // the `versionCheck:update` event (broadcast by index.ts on every state
  // transition — same pattern as iter-28 firstBootDedupe:update). Same
  // late-binding rationale as the dedupe accessor — the manager is
  // constructed inside `app.whenReady()` so the registrar can't capture
  // its instance at module load.
  const versionCheck = opts.versionCheck;
  if (versionCheck) {
    ipcMain.handle("versionCheck:state", (event) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        // Snapshot via JSON round-trip so a downstream consumer can't
        // mutate the manager's in-memory state through a structurally
        // shared reference. The state is small (a few hundred bytes
        // worst case) so the clone cost is invisible.
        const snapshot = JSON.parse(JSON.stringify(versionCheck.getState())) as VersionCheckState;
        return { ok: true, result: snapshot };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    });

    ipcMain.handle("versionCheck:recheck", (event) => {
      if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
      try {
        versionCheck.recheck();
        return { ok: true };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    });
  }

  // ─── iter 37: clipboard + shell:openExternal for the Settings/About panel ─
  //
  // The "Copy download URL" button in the iter-37 update-blocked banner
  // must round-trip through main rather than calling
  // `navigator.clipboard.writeText` — the data:-URL origin the panel
  // loads from would otherwise need a permission grant the operator
  // can't easily surface. Origin / sender check is the same as every
  // other channel; the trustedWebContentsIds bypass for main-process-
  // opened windows applies (the Settings/About window registers itself
  // via markWebContentsTrusted just like the dedupe inspector did).
  ipcMain.handle("clipboard:writeText", (event, text: unknown) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    if (typeof text !== "string") return { ok: false, error: "invalid text" };
    if (text.length === 0) return { ok: false, error: "empty text" };
    if (text.length > MAX_CLIPBOARD_TEXT_LENGTH) {
      return { ok: false, error: "text exceeds size cap" };
    }
    try {
      clipboard.writeText(text);
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle("shell:openExternal", async (event, url: unknown) => {
    if (!checkSender(event)) return { ok: false, error: "Unauthorized origin" };
    if (!isOpenExternalUrlAllowed(url)) {
      return { ok: false, error: "URL rejected by allowlist" };
    }
    try {
      // `shell.openExternal` is async on the main process side; we await
      // so the renderer's promise resolves only after the OS handler has
      // been dispatched (or failed). The OS-side success/failure is
      // best-effort — `shell.openExternal` doesn't surface a "no handler
      // installed" error until much later — but the IPC envelope still
      // matches the rest of the surface.
      await shell.openExternal(url as string);
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  });
}
