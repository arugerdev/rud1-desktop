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
  nativeImage,
} from "electron";
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

const APP_URL = process.env.RUD1_APP_URL ?? "https://rud1.es";
const OPEN_DEV_TOOLS = process.env.RUD1_DEV_TOOLS === "1";
// Recheck cadence for the LAN firmware probe. 60s is short enough that an
// operator who plugs a device in during a session sees the tray entry
// within a minute, but long enough that the probe is invisible on the
// network.
const FIRMWARE_PROBE_INTERVAL_MS = 60_000;

let mainWindow: BrowserWindow | null = null;
let dedupeWindow: BrowserWindow | null = null;
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
  const icon = nativeImage.createFromPath(
    path.join(app.getAppPath(), "resources", "icon.png")
  );
  tray = new Tray(icon.isEmpty() ? nativeImage.createEmpty() : icon.resize({ width: 16 }));

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
