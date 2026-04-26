/**
 * rud1 Desktop — Electron main process.
 *
 * Loads the rud1.es web app in a BrowserWindow and injects the native bridge
 * (VPN, USB/IP) via the preload script. The web app detects that it's running
 * in Electron via window.electronAPI and enables native controls.
 *
 * Configuration (env vars or defaults):
 *   RUD1_APP_URL      — URL to load (default: https://rud1.es)
 *   RUD1_APP_ORIGIN   — allowed origin for IPC (default: https://rud1.es)
 *   RUD1_DEV_TOOLS    — open DevTools on start (set to "1" for debugging)
 */

import {
  app,
  BrowserWindow,
  shell,
  Menu,
  Notification,
  Tray,
} from "electron";
import os from "os";
import path from "path";
import {
  markWebContentsTrusted,
  registerIpcHandlers,
  unmarkWebContentsTrusted,
} from "./ipc-handlers";
import { resumeAutoSnapshotFromDisk } from "./auto-snapshot-manager";
import {
  probeFirmware,
  isFirstBoot,
  shouldNotifyFirstBoot,
  type FirmwareProbeResult,
} from "./firmware-discovery";
import {
  DEDUPE_FILENAME,
  addHost as dedupeAddHost,
  isHostNotified,
  loadNotifiedHosts,
  removeHost as dedupeRemoveHost,
  saveNotifiedHosts,
  type NotifiedHost,
} from "./first-boot-dedupe";
import { computeTrayState } from "./tray-attention";
import { createTray as createTrayInstance, setTrayIcon } from "./tray";
import {
  VersionCheckManager,
  buildVersionCheckMenuItems,
  formatBlockedStateMessage,
  formatVersionCheckSummary,
  applySignatureFetchGate,
  type VersionCheckState,
} from "./version-check-manager";
import {
  buildSettingsWindowHtmlWithRuntimeVersion,
} from "./settings-window-html";
import {
  isAutoUpdateEnabled,
  isRolloutForceEnabled,
  isSigStrictEnabled,
  parseSigFetchTimeoutMs,
  startBackgroundDownload,
  applyAndRestart,
  configureAutoUpdaterRuntime,
  getAutoUpdateState,
  subscribeAutoUpdate,
  resetAutoUpdateState,
} from "./auto-updater";

const APP_URL = process.env.RUD1_APP_URL ?? "https://rud1.es";
const OPEN_DEV_TOOLS = process.env.RUD1_DEV_TOOLS === "1";
// Iter 29 — manifest URL for the lightweight desktop version check.
// Defaults to a stable path under the same domain as the app; can be
// overridden in dev/staging via env. An empty string disables the
// check entirely (the manager validates this and parks in the "error"
// state, which the tray reads as "do not surface").
const VERSION_MANIFEST_URL =
  process.env.RUD1_VERSION_MANIFEST_URL ?? "https://rud1.es/desktop/manifest.json";
// Recheck cadence for the LAN firmware probe. 60s is short enough that an
// operator who plugs a device in during a session sees the tray entry
// within a minute, but long enough that the probe is invisible on the
// network.
const FIRMWARE_PROBE_INTERVAL_MS = 60_000;

let mainWindow: BrowserWindow | null = null;
let dedupeWindow: BrowserWindow | null = null;
// Iter 37 — singleton Settings/About inspector window. Opened from the
// tray's "Settings & About" entry; reused on subsequent clicks. The
// renderer subscribes to `versionCheck:update` events broadcast from
// main so it stays in sync without polling — see `broadcastVersionCheckUpdate`.
let settingsWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let lastFirmwareProbe: FirmwareProbeResult | null = null;
let firmwareProbeTimer: NodeJS.Timeout | null = null;
// Persisted rising-edge dedupe for the first-boot notification (iter 27).
// Populated from `<userData>/first-boot-notifications.json` after
// app.whenReady() — `getPath("userData")` is unavailable before then. The
// probe loop reads this in-memory mirror; disk writes happen on rising/
// falling edges only.
let notifiedHosts: NotifiedHost[] = [];
let dedupeFilepath: string | null = null;
// Iter 28 — the most-recently-applied tray attention count. Used by
// `setTrayAttention` to compute a no-op-when-unchanged diff via
// `computeTrayState`. Resets to 0 at startup; the first probe transitions
// 0 → N if any first-boot host is on the LAN.
let trayAttentionCount = 0;
// Iter 29 — desktop version-check manager. Started from app.whenReady()
// so app.getVersion() returns the packaged value; the cached state is
// read from the tray menu rebuild path so the operator sees the
// "Update available" affordance without a manual trigger.
let versionCheckManager: VersionCheckManager | null = null;
let lastVersionCheckState: VersionCheckState = { kind: "idle" };
// Iter 30 — captured from the last successful manifest fetch (when present)
// so `applyAndRestart` can verify the downloaded artifact's SHA-256. The
// manifest schema doesn't currently advertise this; the field is kept
// optional and threaded through the menu handlers so a future schema
// rev can populate it without rewiring the tray.
let lastManifestSha256: string | null = null;

function createWindow(): BrowserWindow {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    title: "rud1",
    backgroundColor: "#09090b", // matches zinc-950 dark background
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  // Open external links in the system browser, not in the app
  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  win.loadURL(APP_URL);

  if (OPEN_DEV_TOOLS) win.webContents.openDevTools();

  win.on("closed", () => { mainWindow = null; });

  return win;
}

function createTray(): void {
  tray = createTrayInstance();
  rebuildTrayMenu();
  tray.on("click", () => { mainWindow?.show() ?? createWindow(); });
}

// rebuildTrayMenu refreshes the context menu using the cached
// `lastFirmwareProbe`. Called both at tray-creation time AND whenever the
// background probe finishes — `lastFirmwareProbe.reachable` deciding the
// shape of the menu (a "Configure local rud1" entry appears only when a
// first-boot device is on the LAN). Setting context menu is idempotent so
// we don't bother diffing. Tooltip is owned by setTrayAttention (iter 28)
// so the badge state machine is the sole writer.
function rebuildTrayMenu(): void {
  if (!tray) return;
  const items: Electron.MenuItemConstructorOptions[] = [
    { label: "Open rud1", click: () => { mainWindow?.show() ?? createWindow(); } },
  ];
  if (lastFirmwareProbe && isFirstBoot(lastFirmwareProbe)) {
    const url = lastFirmwareProbe.setupUrl;
    items.push({ type: "separator" });
    items.push({
      // The host is appended in parens so the operator can tell apart
      // multiple devices on the same LAN at a glance — `rud1.local` is
      // ambiguous on a multi-Pi network, but `192.168.50.1` is not.
      label: `Configure local rud1 (${lastFirmwareProbe.host})`,
      click: () => { void shell.openExternal(url); },
    });
  } else if (lastFirmwareProbe && lastFirmwareProbe.reachable) {
    // Already-paired device on the LAN — surface a quick-link to its panel
    // so the operator can hop into the local UI without switching tabs.
    items.push({ type: "separator" });
    items.push({
      label: `Open local rud1 panel (${lastFirmwareProbe.host})`,
      click: () => { void shell.openExternal(lastFirmwareProbe!.panelUrl); },
    });
  }
  // Iter 28 — Settings UI for the persisted first-boot dedupe set. Always
  // shown so an operator can audit / clear notified hosts on demand
  // (a power user may want to flush after rotating Pis even when the LAN
  // is currently quiet). Count is appended for at-a-glance visibility.
  items.push({ type: "separator" });
  items.push({
    label: `First-boot notifications (${notifiedHosts.length})`,
    submenu: [
      {
        label: `Show notified hosts (${notifiedHosts.length})`,
        click: () => { showDedupeWindow(); },
      },
      {
        label: "Clear all notified hosts",
        enabled: notifiedHosts.length > 0,
        click: () => { void clearAllNotifiedHosts(); },
      },
    ],
  });
  // Iter 29 — desktop version check entry. The manager only runs after
  // app.whenReady(), so the very first menu rebuild hits "idle" and we
  // intentionally hide the row to avoid flashing a meaningless state.
  // Every later rebuild (post-fetch) renders one of:
  //   • "Update available (vX.Y.Z)" — bold, click opens download URL or
  //     the manifest path so the operator can act
  //   • "Up to date (vX.Y.Z)" — disabled informational row
  //   • "Couldn't check for updates: …" — disabled with reason
  items.push({ type: "separator" });
  // Iter 30 — when auto-update is opted in we hand the version-check
  // builder our auto-update state + click handlers; the builder picks
  // the right rows (download progress, restart-to-install, etc).
  const autoForMenu = isAutoUpdateEnabled() ? getAutoUpdateState() : undefined;
  for (const it of buildVersionCheckMenuItems(
    lastVersionCheckState,
    {
      openExternal: (u) => { void shell.openExternal(u); },
      recheck: () => { void versionCheckManager?.checkOnce(); },
      // Iter 48 — sig-strict gate. When `RUD1_DESKTOP_SIG_STRICT=1` is
      // set we run `applySignatureFetchGate` against the current
      // verdict before kicking off the download. If the gate blocks,
      // we publish the new verdict to `lastVersionCheckState` so the
      // tray + Settings/About panel surface the block; the download
      // never starts. When sig-strict is OFF the gate is a no-op
      // passthrough — iter-30/31 behaviour is byte-identical.
      startDownload: (u, sha) => {
        if (!isSigStrictEnabled()) {
          void startBackgroundDownload(u, { sha256: sha });
          return;
        }
        void (async () => {
          const gated = await applySignatureFetchGate(lastVersionCheckState, {
            manifestUrl: VERSION_MANIFEST_URL,
            fetchTimeoutMs: parseSigFetchTimeoutMs(),
          });
          if (gated.kind === "update-blocked-by-signature-fetch") {
            lastVersionCheckState = gated;
            rebuildTrayMenu();
            broadcastVersionCheckUpdate(gated);
            return;
          }
          void startBackgroundDownload(u, { sha256: sha });
        })();
      },
      applyAndRestart: () => { void applyAndRestart(); },
      resetAutoUpdate: () => { resetAutoUpdateState(); },
    },
    autoForMenu,
    lastManifestSha256,
  )) {
    items.push(it);
  }
  // Iter 37 — Settings/About panel entry. Opens the in-app inspector
  // window that surfaces the live version-check state (in particular the
  // iter-36 update-blocked-by-min-bootstrap banner) plus links into the
  // existing iter-28 first-boot dedupe inspector.
  items.push({ type: "separator" });
  items.push({
    label: "Settings & About…",
    click: () => { showSettingsWindow(); },
  });
  items.push({ type: "separator" });
  items.push({ label: "Quit", click: () => app.quit() });
  tray.setContextMenu(Menu.buildFromTemplate(items));
}

/**
 * setTrayAttention — apply the iter 28 visual badge for first-boot devices.
 *
 * macOS:    `tray.setTitle("N")` renders the count next to the icon in the
 *           menu bar. This is the strongest at-a-glance signal Electron
 *           offers without shipping a second tray-icon asset.
 * Win/Lin:  `setTitle` is a macOS-only API and silently no-ops elsewhere.
 *           We fall back to a tooltip update — visible only on hover, but
 *           still better than nothing, and the tray menu CTA + iter 26 OS
 *           notification already cover the loud-signal slot for those
 *           platforms. This compromise avoids shipping (or generating at
 *           runtime via `sharp`) a tinted overlay icon, which `resources/`
 *           doesn't currently contain at all (createTray falls back to
 *           `nativeImage.createEmpty()`).
 *
 * The state machine (`computeTrayState` in tray-attention.ts) decides
 * whether the call is a no-op so we don't spam Electron on idle ticks.
 */
function setTrayAttention(count: number): void {
  if (!tray) return;
  const transition = computeTrayState(trayAttentionCount, count);
  if (!transition.changed) return;
  trayAttentionCount = transition.next.count;
  // setTitle is macOS-only — the call is harmless on Windows/Linux but
  // gating it keeps the hot-path readable in profiler traces.
  if (process.platform === "darwin") {
    tray.setTitle(transition.next.title);
  }
  tray.setToolTip(transition.next.tooltip);
  // Iter 30 — swap the actual tray pixels on the rising/falling edge
  // so Win/Linux operators get a visible signal (the macOS title is
  // redundant here, but `setTrayIcon` no-ops when the state is unchanged).
  setTrayIcon(transition.next.count > 0 ? "attention" : "idle");
}

/**
 * Count distinct hosts currently in first-boot state. The probe loop only
 * tracks one host at a time today (probeFirmware races N candidates and
 * returns the first hit), so this is effectively 0-or-1 — but we keep the
 * function name plural so a future multi-host probe can drop in without
 * the badge plumbing changing shape.
 */
function countFirstBootHosts(): number {
  return lastFirmwareProbe && isFirstBoot(lastFirmwareProbe) ? 1 : 0;
}

// startFirmwareProbeLoop schedules a recurring LAN probe. Intentionally
// fire-and-forget: a failed probe leaves `lastFirmwareProbe.reachable=false`
// and the tray menu collapses to the no-device shape on the next rebuild.
function startFirmwareProbeLoop(): void {
  void runFirmwareProbe();
  firmwareProbeTimer = setInterval(() => {
    void runFirmwareProbe();
  }, FIRMWARE_PROBE_INTERVAL_MS);
  // Allow the process to exit even when the timer is still running.
  if (typeof firmwareProbeTimer.unref === "function") {
    firmwareProbeTimer.unref();
  }
}

async function runFirmwareProbe(): Promise<void> {
  const prev = lastFirmwareProbe;
  let next: FirmwareProbeResult | null = null;
  try {
    next = await probeFirmware();
  } catch {
    next = null;
  }
  lastFirmwareProbe = next;
  rebuildTrayMenu();
  setTrayAttention(countFirstBootHosts());
  if (next == null) return;

  // Falling edge: a host that was first-boot but is now reachable+complete
  // (or unreachable) is dropped from the persisted dedupe set so it can
  // re-notify if the same host re-enters first-boot mode later.
  if (prev && isFirstBoot(prev) && !isFirstBoot(next)) {
    const before = notifiedHosts.length;
    notifiedHosts = dedupeRemoveHost(notifiedHosts, prev.host);
    if (notifiedHosts.length !== before && dedupeFilepath) {
      void saveNotifiedHosts(dedupeFilepath, notifiedHosts);
    }
  }

  if (!shouldNotifyFirstBoot(prev, next)) return;
  // Persisted gate: even if the in-memory rising-edge predicate says yes
  // (e.g. cold-start with `prev=null`), suppress when the host was already
  // notified within the 30-day TTL.
  if (isHostNotified(notifiedHosts, next.host, new Date())) return;

  notifyFirstBootDevice(next);
  notifiedHosts = dedupeAddHost(notifiedHosts, next.host, new Date());
  if (dedupeFilepath) {
    void saveNotifiedHosts(dedupeFilepath, notifiedHosts);
  }
}

/**
 * Iter 28 — clear a single host from the persisted first-boot dedupe set.
 *
 * Called from:
 *   • the IPC handler `firstBootDedupe:clearHost` (Settings UI)
 *   • the dedupe inspector window's per-row "Clear" button (which round-trips
 *     through the IPC channel above)
 *
 * Always atomically writes the JSON file — we accept a brief disk write on
 * every clear because the operator-driven path is rare (clicks per session
 * measured in single digits) and consistency with the iter 27 falling-edge
 * persistence is more valuable than a debounce.
 */
async function clearNotifiedHost(host: string): Promise<readonly NotifiedHost[]> {
  const before = notifiedHosts.length;
  notifiedHosts = dedupeRemoveHost(notifiedHosts, host);
  if (notifiedHosts.length !== before && dedupeFilepath) {
    await saveNotifiedHosts(dedupeFilepath, notifiedHosts);
  }
  rebuildTrayMenu();
  broadcastDedupeUpdate();
  return notifiedHosts;
}

/**
 * Iter 28 — clear all hosts from the persisted dedupe set. Atomic write of
 * the empty array (preserving the version-1 envelope) so a process kill
 * mid-write doesn't leave a torn JSON file.
 */
async function clearAllNotifiedHosts(): Promise<void> {
  notifiedHosts = [];
  if (dedupeFilepath) {
    await saveNotifiedHosts(dedupeFilepath, notifiedHosts);
  }
  rebuildTrayMenu();
  broadcastDedupeUpdate();
}

/**
 * Iter 28 — push a fresh notified-hosts list to the dedupe inspector
 * window if it's open. The window's renderer subscribes via a preload
 * `onUpdate` listener so it doesn't have to poll. Best-effort: a closed
 * window is a no-op.
 */
function broadcastDedupeUpdate(): void {
  if (!dedupeWindow || dedupeWindow.isDestroyed()) return;
  dedupeWindow.webContents.send(
    "firstBootDedupe:update",
    notifiedHosts.map((h) => ({ ...h })),
  );
}

/**
 * Iter 28 — small modal window listing notified hosts. Built as a plain
 * `data:` URL HTML page rather than a separate file under `resources/` to
 * avoid a build-step change for one trivial UI surface; the document is
 * sandboxed and the only IPC it does is via the same preload bridge as
 * the main window.
 *
 * Reuses the existing preload script — `firstBootDedupe:list/clearHost/
 * clearAll` channels are exposed there. The window is a singleton; calling
 * showDedupeWindow when it already exists just brings it to the front.
 */
function showDedupeWindow(): void {
  if (dedupeWindow && !dedupeWindow.isDestroyed()) {
    dedupeWindow.focus();
    return;
  }
  dedupeWindow = new BrowserWindow({
    width: 540,
    height: 480,
    title: "rud1 — First-boot notifications",
    backgroundColor: "#09090b",
    minimizable: false,
    maximizable: false,
    parent: mainWindow ?? undefined,
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  dedupeWindow.setMenu(null);
  // The inspector's `data:` origin would never pass isOriginAllowed, so
  // we register its webContents id in the trusted set on ipc-handlers —
  // the main process opened this window and controls its HTML exactly,
  // so it's a legitimate trust bridge.
  const trustedId = dedupeWindow.webContents.id;
  markWebContentsTrusted(trustedId);
  // Inline HTML page (data URL). CSP inside the document forbids remote
  // resources; preload bridge runs in an isolated context unaffected by
  // the document CSP.
  dedupeWindow.loadURL(buildDedupeWindowHtml());
  dedupeWindow.on("closed", () => {
    unmarkWebContentsTrusted(trustedId);
    dedupeWindow = null;
  });
}

function buildDedupeWindowHtml(): string {
  // CSP: deny everything by default; allow inline scripts/styles only —
  // the page does not call out to any network. The preload bridge lives
  // in a separate context (contextIsolation: true) so this CSP doesn't
  // constrain it.
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none';" />
<title>rud1 — First-boot notifications</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; background:#09090b; color:#e4e4e7; margin:0; padding:16px; }
  h1 { font-size:14px; font-weight:600; margin:0 0 8px 0; }
  p.help { font-size:12px; color:#a1a1aa; margin:0 0 16px 0; }
  table { width:100%; border-collapse:collapse; font-size:12px; }
  th, td { text-align:left; padding:8px; border-bottom:1px solid #27272a; vertical-align:middle; }
  th { color:#a1a1aa; font-weight:500; font-size:11px; text-transform:uppercase; letter-spacing:0.04em; }
  td.host { font-family: ui-monospace, "SF Mono", Consolas, monospace; }
  td.when { color:#a1a1aa; }
  button { background:#27272a; color:#e4e4e7; border:1px solid #3f3f46; border-radius:4px; padding:4px 10px; font-size:12px; cursor:pointer; }
  button:hover { background:#3f3f46; }
  button.danger { color:#fca5a5; border-color:#7f1d1d; }
  button.danger:hover { background:#450a0a; }
  .footer { display:flex; justify-content:space-between; align-items:center; margin-top:16px; }
  .empty { color:#71717a; font-style:italic; padding:24px 8px; text-align:center; }
</style>
</head>
<body>
  <h1>First-boot notifications</h1>
  <p class="help">Hosts the desktop app has already notified you about. Entries expire automatically after 30 days; a host that was finished and re-flashed will re-notify on its next first-boot detection.</p>
  <div id="list"></div>
  <div class="footer">
    <span id="status"></span>
    <button id="clear-all" class="danger" disabled>Clear all</button>
  </div>
<script>
  // Renderer for the dedupe inspector. Talks to main exclusively through
  // window.electronAPI.firstBootDedupe.{list,clearHost,clearAll} which is
  // wired up in preload/index.ts.
  const listEl = document.getElementById('list');
  const statusEl = document.getElementById('status');
  const clearAllBtn = document.getElementById('clear-all');
  function relativeTime(iso) {
    const t = Date.parse(iso);
    if (Number.isNaN(t)) return iso;
    const deltaMs = Date.now() - t;
    const sec = Math.round(deltaMs / 1000);
    if (sec < 60) return sec + 's ago';
    const min = Math.round(sec / 60);
    if (min < 60) return min + 'm ago';
    const hr = Math.round(min / 60);
    if (hr < 48) return hr + 'h ago';
    const day = Math.round(hr / 24);
    return day + 'd ago';
  }
  function escape(s) {
    return String(s).replace(/[&<>"']/g, function(c) {
      return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c];
    });
  }
  function render(hosts) {
    if (!hosts || hosts.length === 0) {
      listEl.innerHTML = '<div class="empty">No notified hosts.</div>';
      clearAllBtn.disabled = true;
      statusEl.textContent = '';
      return;
    }
    clearAllBtn.disabled = false;
    statusEl.textContent = hosts.length + ' notified host' + (hosts.length === 1 ? '' : 's');
    var rows = hosts.map(function(h) {
      return '<tr>' +
        '<td class="host">' + escape(h.host) + '</td>' +
        '<td class="when" title="' + escape(h.notifiedAt) + '">' + escape(relativeTime(h.notifiedAt)) + '</td>' +
        '<td style="text-align:right;"><button data-host="' + escape(h.host) + '" class="row-clear">Clear</button></td>' +
      '</tr>';
    }).join('');
    listEl.innerHTML = '<table><thead><tr><th>Host</th><th>Notified</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>';
    Array.prototype.forEach.call(document.querySelectorAll('button.row-clear'), function(btn) {
      btn.addEventListener('click', function() {
        const host = btn.getAttribute('data-host');
        if (!host) return;
        btn.disabled = true;
        window.electronAPI.firstBootDedupe.clearHost(host).then(function(res) {
          if (res && res.ok && Array.isArray(res.result)) render(res.result);
        });
      });
    });
  }
  clearAllBtn.addEventListener('click', function() {
    if (!confirm('Clear all notified hosts? They will re-notify on the next first-boot detection.')) return;
    clearAllBtn.disabled = true;
    window.electronAPI.firstBootDedupe.clearAll().then(function() {
      render([]);
    });
  });
  // Initial fetch + subscribe to updates pushed from main.
  window.electronAPI.firstBootDedupe.list().then(function(res) {
    if (res && res.ok && Array.isArray(res.result)) render(res.result);
    else render([]);
  });
  if (typeof window.electronAPI.firstBootDedupe.onUpdate === 'function') {
    window.electronAPI.firstBootDedupe.onUpdate(function(hosts) { render(hosts); });
  }
</script>
</body>
</html>`;
  return "data:text/html;charset=utf-8," + encodeURIComponent(html);
}

// ─── Iter 37 — Settings/About panel ────────────────────────────────────────
//
// Surfaces the live `VersionCheckState` (in particular the iter-36
// `update-blocked-by-min-bootstrap` verdict) in a small inspector window.
// Reuses the iter-28 data:-URL + trustedWebContentsIds pattern so the
// origin allowlist isn't weakened. The renderer is a dumb template that
// reads the state on open, subscribes to push updates, and supports two
// operations:
//   • "Copy download URL" → IPC clipboard:writeText (avoids the
//     navigator.clipboard permission grant for data: origins)
//   • "What's new" link    → IPC shell:openExternal (allowlisted to
//     http/https main-side)

function broadcastVersionCheckUpdate(state: VersionCheckState): void {
  if (!settingsWindow || settingsWindow.isDestroyed()) return;
  // Defensive clone via JSON round-trip mirrors the IPC handler's
  // anti-aliasing snapshot — a malicious / buggy renderer that retained a
  // reference can't mutate the manager's in-memory state through it.
  try {
    const snapshot = JSON.parse(JSON.stringify(state)) as VersionCheckState;
    settingsWindow.webContents.send("versionCheck:update", snapshot);
  } catch {
    // best-effort
  }
}

function showSettingsWindow(): void {
  if (settingsWindow && !settingsWindow.isDestroyed()) {
    settingsWindow.focus();
    return;
  }
  settingsWindow = new BrowserWindow({
    width: 580,
    height: 540,
    title: "rud1 — Settings & About",
    backgroundColor: "#09090b",
    minimizable: false,
    maximizable: false,
    parent: mainWindow ?? undefined,
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  settingsWindow.setMenu(null);
  // Same trust-bridge rationale as the dedupe inspector: the panel loads
  // from a `data:` URL whose origin would never pass `isOriginAllowed`,
  // so we register its webContents id in the trusted set. The main
  // process opened this window and controls its HTML byte-for-byte.
  const trustedId = settingsWindow.webContents.id;
  markWebContentsTrusted(trustedId);
  // Iter 44 — thread app.getVersion() into the panel HTML so the
  // renderer-side "Copy diagnostics" inline rebuild can populate
  // `currentVersion` on the `error` envelope (the error state shape
  // doesn't carry it). Captured at HTML build time as a JSON-encoded
  // constant — same idea as `installId` below; safe to call here
  // because `app.whenReady()` has already resolved by the time the
  // tray opens this window.
  // Iter 46 — go through the named-wrapper helper rather than the
  // raw `buildSettingsWindowHtml`. The wrapper bakes `app.getVersion()`
  // into all four diagnostic-blob surfaces (the inline APP_VERSION
  // constant + the three renderer-side rebuilds for error, blocked,
  // and update-available) so a future call site can't forget the
  // override on any one of them.
  settingsWindow.loadURL(
    buildSettingsWindowHtmlWithRuntimeVersion(app.getVersion()),
  );
  settingsWindow.on("closed", () => {
    unmarkWebContentsTrusted(trustedId);
    settingsWindow = null;
  });
}

// notifyFirstBootDevice fires a single OS notification when a first-boot
// rud1 appears on the LAN. Clicking the notification opens the device's
// setup URL in the system browser — same destination as the tray entry,
// just discoverable without the operator hunting for the tray icon.
//
// Notification.isSupported() is false on:
//   - Linux without notify-send / libnotify       (silent no-op)
//   - Windows when toast notifications are off in OS settings
//   - Production builds without an app User Model ID set on first run
//
// We swallow the support gap silently rather than logging — the tray menu
// already surfaces the same affordance, so notification absence is a
// graceful degradation, not an error.
function notifyFirstBootDevice(probe: FirmwareProbeResult): void {
  if (!Notification.isSupported()) return;
  const note = new Notification({
    title: "rud1 device ready to configure",
    body: `A first-boot device is on the LAN at ${probe.host}. Click to open the setup wizard.`,
    silent: false,
  });
  note.on("click", () => {
    void shell.openExternal(probe.setupUrl);
    mainWindow?.show();
  });
  note.show();
}

// ─── App lifecycle ────────────────────────────────────────────────────────────

app.whenReady().then(() => {
  registerIpcHandlers({
    firstBootDedupe: {
      list: () => notifiedHosts,
      clearHost: (host) => clearNotifiedHost(host),
      clearAll: () => clearAllNotifiedHosts(),
    },
    // Iter 37 — Settings/About panel surface. Late-bound: the manager is
    // constructed a few lines below inside this same whenReady block, so
    // the accessor closures snapshot `versionCheckManager` at call time
    // rather than at registrar time. `getState` falls back to the cached
    // `lastVersionCheckState` if the manager is null (shouldn't happen at
    // runtime — it's set immediately below — but the fallback keeps the
    // typing honest).
    versionCheck: {
      getState: () =>
        versionCheckManager ? versionCheckManager.getState() : lastVersionCheckState,
      recheck: () => {
        void versionCheckManager?.checkOnce();
      },
    },
  });
  mainWindow = createWindow();
  createTray();

  // Resolve userData and prime the persisted first-boot dedupe set BEFORE
  // the probe loop fires. If the load is slow (cold disk, network drive)
  // the loop still starts on time — a cache miss just means the very first
  // tick after launch may re-notify a host we already knew about, which is
  // strictly better than blocking startup on disk I/O.
  dedupeFilepath = path.join(app.getPath("userData"), DEDUPE_FILENAME);
  void loadNotifiedHosts(dedupeFilepath, new Date()).then((loaded) => {
    notifiedHosts = loaded;
    // Refresh the tray menu so the "First-boot notifications (N)" badge
    // reflects the persisted count once the load completes (the menu is
    // built before this resolves with `notifiedHosts.length === 0`).
    rebuildTrayMenu();
    broadcastDedupeUpdate();
  });
  startFirmwareProbeLoop();

  // Iter 29 — desktop version check. Started here (not at module load)
  // because `app.getVersion()` requires `app.whenReady()` to resolve,
  // and the tray must already exist for the rebuild callback to wire
  // up. We never block startup on the first fetch — `start()` schedules
  // an immediate `checkOnce` async + an interval; failures park in the
  // "error" state and the tray surfaces a Retry entry.
  // Iter 34 — derive a stable per-installation identifier for staged
  // rollouts. There's no pre-existing UUID stored anywhere in the app
  // today; we synthesise one from `app.getName()` + the OS hostname so
  // every install on a given host bucket-maps to the same number across
  // restarts. (The hostname is local-only and not exfiltrated; the
  // bucket itself is a sha256-derived integer in [1, 100].)
  const installId = `${app.getName()}:${os.hostname()}`;

  versionCheckManager = new VersionCheckManager({
    manifestUrl: VERSION_MANIFEST_URL,
    currentVersion: app.getVersion(),
    installId,
    // Iter 35 — function-typed so a runtime change to the env var or
    // persisted-config flag takes effect on the next poll without
    // restarting the app. `isRolloutForceEnabled` reads `process.env`
    // and the userData JSON inside; safe to call once per fetch tick.
    forceRollout: () => isRolloutForceEnabled(),
    onStateChange: (state) => {
      lastVersionCheckState = state;
      rebuildTrayMenu();
      // Iter 37 — push the new state to the Settings/About panel if it's
      // open so the operator sees verdict transitions (idle → checking →
      // update-blocked-by-min-bootstrap, etc.) without reopening the
      // window. Best-effort: a closed panel is a no-op.
      broadcastVersionCheckUpdate(state);
    },
  });
  versionCheckManager.start();

  // Iter 30 — wire the auto-updater module's Electron-side handles so
  // its env-flag gate and download/apply path can run when the operator
  // has opted in. Subscribing to its state machine triggers tray menu
  // rebuilds on every "downloading… 42%" tick.
  configureAutoUpdaterRuntime({});
  subscribeAutoUpdate(() => { rebuildTrayMenu(); });

  // Resume opt-in periodic diagnosis snapshots if the operator had them
  // enabled. Fire-and-forget: startup must not block on disk I/O, and
  // resume failures are recoverable — the next configure() call overwrites
  // whatever state was persisted.
  void resumeAutoSnapshotFromDisk().catch(() => {
    /* ignore — surfaced on next status query */
  });

  // macOS: re-create window when dock icon is clicked
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) mainWindow = createWindow();
  });
});

// Keep the app running in the tray on window close (Windows/Linux)
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    // Don't quit — stay in tray
  }
});

app.on("before-quit", () => {
  if (firmwareProbeTimer) {
    clearInterval(firmwareProbeTimer);
    firmwareProbeTimer = null;
  }
  versionCheckManager?.stop();
  tray?.destroy();
});

// Handle deep links: rud1://
app.setAsDefaultProtocolClient("rud1");
app.on("open-url", (_event, url) => {
  mainWindow?.loadURL(`${APP_URL}?deeplink=${encodeURIComponent(url)}`);
});

// Windows deep-link via second-instance
app.on("second-instance", (_event, argv) => {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
    const deeplink = argv.find((a) => a.startsWith("rud1://"));
    if (deeplink) mainWindow.loadURL(`${APP_URL}?deeplink=${encodeURIComponent(deeplink)}`);
  }
});

if (!app.requestSingleInstanceLock()) app.quit();
