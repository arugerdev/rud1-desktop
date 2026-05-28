// Env: RUD1_APP_URL, RUD1_APP_ORIGIN (comma-separated), RUD1_DEV_TOOLS=1.
import {
  app,
  BrowserWindow,
  shell,
  Menu,
  Tray,
  nativeTheme,
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
import {
  computeTrayState,
  formatTrayTooltipWithVpn,
  type TrayVpnHealth,
} from "./tray-attention";
import { createTray as createTrayInstance, setTrayIcon } from "./tray";
import {
  VersionCheckManager,
  buildVersionCheckMenuItems,
  applySignatureFetchGate,
  type VersionCheckState,
} from "./version-check-manager";
import {
  buildSettingsWindowHtmlWithRuntimeVersion,
} from "./settings-window-html";
import { buildDriverInstallWindowHtml } from "./vpn-driver-install-html";
import { detectOpenVpnRuntime, openvpnRuntimeDir } from "./openvpn-installer";
import {
  PREFERENCES_FILENAME,
  getPreferences,
  isNotificationEnabled,
  loadPreferences,
  type ThemePreference,
} from "./preferences-manager";
import { NotificationStreamManager } from "./notification-stream-manager";
import { notifyDeviceReady } from "./notifications";
import { destroyToastOverlay, onToastAction, pushToast } from "./toast-overlay";
import {
  USB_SESSION_FILENAME,
  addSession as addUsbSessionEntry,
  loadSessions as loadUsbSessions,
  removeSessionByBusId as removeUsbSessionByBusId,
  removeSessionByPort as removeUsbSessionByPort,
  saveSessions as saveUsbSessions,
  type AttachedUsbSession,
} from "./usb-session-state";
import { usbAttach } from "./usb-manager";
import {
  isAutoUpdateEnabled,
  isRolloutForceEnabled,
  isSigStrictEnabled,
  isSigVerifyEnabled,
  parseSigFetchTimeoutMs,
  parseSigPubkey,
  startBackgroundDownload,
  applyAndRestart,
  configureAutoUpdaterRuntime,
  getAutoUpdateState,
  subscribeAutoUpdate,
  resetAutoUpdateState,
} from "./auto-updater";
import {
  DeviceListManager,
  statusGlyph,
  type DeviceSummary,
} from "./device-list-manager";

const APP_URL = process.env.RUD1_APP_URL ?? "https://www.rud1.es/dashboard";
const OPEN_DEV_TOOLS = process.env.RUD1_DEV_TOOLS === "1";
const VERSION_MANIFEST_URL =
  process.env.RUD1_VERSION_MANIFEST_URL ?? "https://rud1.es/desktop/manifest.json";
const FIRMWARE_PROBE_INTERVAL_MS = 60_000;

let mainWindow: BrowserWindow | null = null;
let dedupeWindow: BrowserWindow | null = null;
let notificationStream: NotificationStreamManager | null = null;
let settingsWindow: BrowserWindow | null = null;
let driverInstallWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let lastFirmwareProbe: FirmwareProbeResult | null = null;
let firmwareProbeTimer: NodeJS.Timeout | null = null;
let notifiedHosts: NotifiedHost[] = [];
let dedupeFilepath: string | null = null;
let usbSessions: AttachedUsbSession[] = [];
let usbSessionFilepath: string | null = null;
let trayAttentionCount = 0;
let versionCheckManager: VersionCheckManager | null = null;
let lastVersionCheckState: VersionCheckState = { kind: "idle" };
let deviceListManager: DeviceListManager | null = null;
let lastManifestSha256: string | null = null;
let lastManifestVersion: number | null = null;

// Win32 tray ContextMenu no se puede tematizar (lo renderiza el OS).
function applyThemeFromPreference(pref: ThemePreference): void {
  nativeTheme.themeSource = pref;
}

function resolveAppIconPath(): string | null {
  const baseDir = app.isPackaged
    ? process.resourcesPath
    : path.join(app.getAppPath(), "resources");
  const candidates =
    process.platform === "win32"
      ? ["icon.ico", "icon.png"]
      : process.platform === "darwin"
      ? ["icon.icns", "icon.png"]
      : ["icon.png"];
  for (const name of candidates) {
    const candidate = path.join(baseDir, name);
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const fs = require("fs") as typeof import("fs");
      if (fs.existsSync(candidate)) return candidate;
    } catch {
      /* defensive */
    }
  }
  return null;
}

function createWindow(): BrowserWindow {
  const iconPath = resolveAppIconPath();
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    title: "rud1",
    backgroundColor: nativeTheme.shouldUseDarkColors ? "#0a0e17" : "#f4f6fa",
    ...(iconPath ? { icon: iconPath } : {}),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  // setMenuBarVisibility(false) bloquea que ALT haga emerger la barra.
  win.setMenuBarVisibility(false);

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

function showOrCreateMainWindow(): void {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.show();
    return;
  }
  mainWindow = createWindow();
}

function createTray(): void {
  tray = createTrayInstance();
  rebuildTrayMenu();
  tray.on("click", () => { showOrCreateMainWindow(); });
}

function rebuildTrayMenu(): void {
  if (!tray) return;
  const items: Electron.MenuItemConstructorOptions[] = [
    { label: `rud1 v${app.getVersion()}`, enabled: false },
    { type: "separator" },
    { label: "Open rud1", click: () => { showOrCreateMainWindow(); } },
  ];

  appendMyDevicesSubmenu(items);
  if (lastFirmwareProbe && isFirstBoot(lastFirmwareProbe)) {
    const url = lastFirmwareProbe.setupUrl;
    items.push({ type: "separator" });
    items.push({
      label: `Configure local rud1 (${lastFirmwareProbe.host})`,
      click: () => { void shell.openExternal(url); },
    });
  } else if (lastFirmwareProbe && lastFirmwareProbe.reachable) {
    items.push({ type: "separator" });
    items.push({
      label: `Open local rud1 panel (${lastFirmwareProbe.host})`,
      click: () => { void shell.openExternal(lastFirmwareProbe!.panelUrl); },
    });
  }
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
  const autoForMenu = isAutoUpdateEnabled() ? getAutoUpdateState() : undefined;
  for (const it of buildVersionCheckMenuItems(
    lastVersionCheckState,
    {
      openExternal: (u) => { void shell.openExternal(u); },
      recheck: () => { void versionCheckManager?.checkOnce(); },
      startDownload: (u, sha) => {
        if (!isSigStrictEnabled()) {
          void startBackgroundDownload(u, { sha256: sha });
          return;
        }
        void (async () => {
          const verifyEnabled = isSigVerifyEnabled();
          const parsedPub = verifyEnabled ? parseSigPubkey() : null;
          const signedData =
            typeof lastManifestSha256 === "string" && lastManifestSha256.length > 0
              ? Buffer.from(lastManifestSha256, "utf8")
              : null;
          const gated = await applySignatureFetchGate(lastVersionCheckState, {
            manifestUrl: VERSION_MANIFEST_URL,
            fetchTimeoutMs: parseSigFetchTimeoutMs(),
            verifyEnabled,
            verifyPubkey: parsedPub != null ? parsedPub.pubkey : null,
            verifySignedData: signedData,
            manifestVersion: lastManifestVersion,
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
  items.push({ type: "separator" });
  items.push({
    label: "Settings & About…",
    click: () => { showSettingsWindow(); },
  });
  items.push({ type: "separator" });
  items.push({ label: "Quit", click: () => app.quit() });
  tray.setContextMenu(Menu.buildFromTemplate(items));
}

function appendMyDevicesSubmenu(
  items: Electron.MenuItemConstructorOptions[],
): void {
  const state = deviceListManager?.getState() ?? { kind: "idle" as const };
  const lastDevices = deviceListManager?.getLastDevices() ?? null;

  if (state.kind === "idle" || state.kind === "loading") {
    if (lastDevices == null) {
      items.push({ type: "separator" });
      items.push({ label: "Loading devices…", enabled: false });
      return;
    }
  }
  if (state.kind === "error") {
    items.push({ type: "separator" });
    if (state.reason === "signed-out") {
      items.push({
        label: "Sign in to view your devices",
        click: () => { showOrCreateMainWindow(); },
      });
      return;
    }
    items.push({
      label: `Couldn't load devices (${state.reason})`,
      enabled: false,
    });
    items.push({
      label: "Retry now",
      click: () => { void deviceListManager?.refreshNow(); },
    });
    if (lastDevices == null) return;
  }

  const devices = lastDevices ?? [];
  if (devices.length === 0) {
    items.push({ type: "separator" });
    items.push({ label: "No devices yet", enabled: false });
    items.push({
      label: "Open dashboard to add one",
      click: () => { showOrCreateMainWindow(); },
    });
    return;
  }

  const MAX_VISIBLE = 12;
  const visible = devices.slice(0, MAX_VISIBLE);
  const onlineCount = devices.filter((d) => d.status === "ONLINE").length;

  items.push({ type: "separator" });
  items.push({
    label: `My devices — ${onlineCount}/${devices.length} online`,
    submenu: [
      ...visible.map<Electron.MenuItemConstructorOptions>((d) => ({
        label: `${d.name}  ·  ${statusGlyph(d.status)}`,
        toolTip: `${d.organization.name} · ${d.id}`,
        click: () => openDeviceInMainWindow(d),
      })),
      ...(devices.length > MAX_VISIBLE
        ? [
            { type: "separator" as const },
            {
              label: `…and ${devices.length - MAX_VISIBLE} more`,
              enabled: false,
            },
          ]
        : []),
      { type: "separator" },
      {
        label: "View all in dashboard",
        click: () => {
          if (mainWindow) {
            showOrCreateMainWindow();
            void mainWindow.webContents.loadURL(`${APP_URL.replace(/\/dashboard.*$/, "")}/dashboard/devices`);
          } else {
            showOrCreateMainWindow();
          }
        },
      },
      {
        label: "Refresh now",
        click: () => { void deviceListManager?.refreshNow(); },
      },
    ],
  });
}

function openDeviceInMainWindow(d: DeviceSummary): void {
  showOrCreateMainWindow();
  if (!mainWindow) return;
  const origin = APP_URL.replace(/\/dashboard.*$/, "");
  void mainWindow.webContents.loadURL(`${origin}/dashboard/devices/${d.id}`);
}

// setTitle es macOS-only; Win/Linux usa tooltip + icono.
function setTrayAttention(count: number): void {
  if (!tray) return;
  const transition = computeTrayState(trayAttentionCount, count);
  if (!transition.changed) return;
  trayAttentionCount = transition.next.count;
  if (process.platform === "darwin") {
    tray.setTitle(transition.next.title);
  }
  tray.setToolTip(formatTrayTooltipWithVpn(transition.next.count, trayVpnHealth));
  setTrayIcon(transition.next.count > 0 ? "attention" : "idle");
}

let trayVpnHealth: TrayVpnHealth = "unknown";

function setTrayVpnHealth(health: TrayVpnHealth): void {
  trayVpnHealth = health;
  if (!tray) return;
  tray.setToolTip(formatTrayTooltipWithVpn(trayAttentionCount, trayVpnHealth));
}

function countFirstBootHosts(): number {
  return lastFirmwareProbe && isFirstBoot(lastFirmwareProbe) ? 1 : 0;
}

function startFirmwareProbeLoop(): void {
  void runFirmwareProbe();
  firmwareProbeTimer = setInterval(() => {
    void runFirmwareProbe();
  }, FIRMWARE_PROBE_INTERVAL_MS);
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

  if (prev && isFirstBoot(prev) && !isFirstBoot(next)) {
    const before = notifiedHosts.length;
    notifiedHosts = dedupeRemoveHost(notifiedHosts, prev.host);
    if (notifiedHosts.length !== before && dedupeFilepath) {
      void saveNotifiedHosts(dedupeFilepath, notifiedHosts);
    }
  }

  if (!shouldNotifyFirstBoot(prev, next)) return;
  // 30-day TTL persisted gate (suprime aunque rising-edge diga yes).
  if (isHostNotified(notifiedHosts, next.host, new Date())) return;

  notifyFirstBootDevice(next);
  notifiedHosts = dedupeAddHost(notifiedHosts, next.host, new Date());
  if (dedupeFilepath) {
    void saveNotifiedHosts(dedupeFilepath, notifiedHosts);
  }
}

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

async function clearAllNotifiedHosts(): Promise<void> {
  notifiedHosts = [];
  if (dedupeFilepath) {
    await saveNotifiedHosts(dedupeFilepath, notifiedHosts);
  }
  rebuildTrayMenu();
  broadcastDedupeUpdate();
}

function broadcastDedupeUpdate(): void {
  if (!dedupeWindow || dedupeWindow.isDestroyed()) return;
  dedupeWindow.webContents.send(
    "firstBootDedupe:update",
    notifiedHosts.map((h) => ({ ...h })),
  );
}

// Replay attaches en serie post-VPN connect; kernel re-numera ports en reattach.
async function reattachStoredUsbSessions(): Promise<void> {
  if (usbSessions.length === 0) return;
  const snapshot = [...usbSessions];
  for (const session of snapshot) {
    try {
      const port = await usbAttach(session.host, session.busId);
      usbSessions = addUsbSessionEntry(usbSessions, {
        host: session.host,
        busId: session.busId,
        label: session.label,
        port,
        attachedAt: new Date().toISOString(),
      });
    } catch (err) {
      console.warn(
        "[usb-session-state] reattach failed:",
        session.busId,
        err instanceof Error ? err.message : err,
      );
    }
  }
  if (usbSessionFilepath) {
    void saveUsbSessions(usbSessionFilepath, usbSessions);
  }
}

function showDedupeWindow(): void {
  if (dedupeWindow && !dedupeWindow.isDestroyed()) {
    dedupeWindow.focus();
    return;
  }
  dedupeWindow = new BrowserWindow({
    width: 540,
    height: 480,
    title: "rud1 — First-boot notifications",
    backgroundColor: nativeTheme.shouldUseDarkColors ? "#0a0e17" : "#f4f6fa",
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
  // `data:` origin nunca pasaría isOriginAllowed — trust bridge explícito.
  const trustedId = dedupeWindow.webContents.id;
  markWebContentsTrusted(trustedId);
  dedupeWindow.loadURL(buildDedupeWindowHtml());
  dedupeWindow.on("closed", () => {
    unmarkWebContentsTrusted(trustedId);
    dedupeWindow = null;
  });
}

function buildDedupeWindowHtml(): string {
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none';" />
<title>rud1 — First-boot notifications</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f4f6fa;
    --fg: #1a2030;
    --muted-fg: #6b7588;
    --surface: rgba(255, 255, 255, 0.62);
    --surface-strong: rgba(255, 255, 255, 0.82);
    --border: rgba(180, 195, 220, 0.55);
    --shadow: rgba(60, 80, 120, 0.18);
    --row-divider: rgba(180, 195, 220, 0.4);
    --danger-fg: #b54f47;
    --danger-bg: rgba(241, 144, 138, 0.18);
    --danger-border: rgba(241, 144, 138, 0.5);
    --mesh-1: rgba(189, 219, 255, 0.5);
    --mesh-2: rgba(228, 207, 255, 0.45);
    --mesh-3: rgba(196, 240, 224, 0.4);
    --mesh-4: rgba(255, 226, 197, 0.4);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0a0e17;
      --fg: #e6eaf2;
      --muted-fg: #93a0b8;
      --surface: rgba(28, 36, 50, 0.55);
      --surface-strong: rgba(28, 36, 50, 0.78);
      --border: rgba(120, 140, 175, 0.22);
      --shadow: rgba(0, 0, 0, 0.55);
      --row-divider: rgba(120, 140, 175, 0.18);
      --danger-fg: #f3bcb7;
      --danger-bg: rgba(241, 144, 138, 0.18);
      --danger-border: rgba(241, 144, 138, 0.4);
      --mesh-1: rgba(40, 80, 130, 0.36);
      --mesh-2: rgba(80, 60, 130, 0.32);
      --mesh-3: rgba(40, 110, 95, 0.28);
      --mesh-4: rgba(130, 80, 50, 0.28);
    }
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "Segoe UI", "SF Pro Text", Inter, Roboto, sans-serif;
    background: var(--bg);
    background-image:
      radial-gradient(at 18% 12%, var(--mesh-1), transparent 55%),
      radial-gradient(at 85% 8%, var(--mesh-2), transparent 55%),
      radial-gradient(at 70% 90%, var(--mesh-3), transparent 55%),
      radial-gradient(at 12% 85%, var(--mesh-4), transparent 55%);
    background-attachment: fixed;
    color: var(--fg);
    margin: 0;
    padding: 18px;
    font-size: 13px;
    -webkit-font-smoothing: antialiased;
  }
  h1 { font-size: 16px; font-weight: 600; margin: 0 0 8px 0; letter-spacing: -0.01em; }
  p.help { font-size: 12px; color: var(--muted-fg); margin: 0 0 16px 0; }
  table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    font-size: 12px;
    border-radius: 14px;
    overflow: hidden;
    background: var(--surface);
    border: 1px solid var(--border);
    backdrop-filter: blur(20px) saturate(170%);
    -webkit-backdrop-filter: blur(20px) saturate(170%);
    box-shadow: 0 4px 18px var(--shadow);
  }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--row-divider); vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  th { color: var(--muted-fg); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
  td.host { font-family: ui-monospace, "SF Mono", Consolas, monospace; }
  td.when { color: var(--muted-fg); }
  button {
    background: var(--surface);
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 5px 12px;
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    backdrop-filter: blur(12px) saturate(160%);
    -webkit-backdrop-filter: blur(12px) saturate(160%);
    transition: background 0.15s ease, transform 0.1s ease;
  }
  button:hover { background: var(--surface-strong); }
  button:active { transform: scale(0.97); }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  button.danger {
    color: var(--danger-fg);
    background: var(--danger-bg);
    border-color: var(--danger-border);
  }
  button.danger:hover { filter: brightness(1.05); }
  .footer { display: flex; justify-content: space-between; align-items: center; margin-top: 16px; }
  .empty { color: var(--muted-fg); font-style: italic; padding: 32px 12px; text-align: center; }
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 999px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--muted-fg); }
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

function broadcastVersionCheckUpdate(state: VersionCheckState): void {
  if (!settingsWindow || settingsWindow.isDestroyed()) return;
  // Defensive clone vía JSON round-trip evita aliasing desde renderer.
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
    backgroundColor: nativeTheme.shouldUseDarkColors ? "#0a0e17" : "#f4f6fa",
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
  const trustedId = settingsWindow.webContents.id;
  markWebContentsTrusted(trustedId);
  settingsWindow.loadURL(
    buildSettingsWindowHtmlWithRuntimeVersion(
      app.getVersion(),
      getPreferences().theme,
    ),
  );
  settingsWindow.on("closed", () => {
    unmarkWebContentsTrusted(trustedId);
    settingsWindow = null;
  });
}

/**
 * Liquid Glass "install VPN driver" pre-elevation modal. Opened from
 * the main panel via the `vpn:openDriverInstall` IPC channel when the
 * connect call returns `{tapDriverMissing: true}`. Trusted webContents
 * bypass so the data:-URL CSP-allowed origin can still call the
 * `vpn.installTapDriver` IPC channel.
 */
function showDriverInstallWindow(): void {
  if (driverInstallWindow && !driverInstallWindow.isDestroyed()) {
    driverInstallWindow.focus();
    return;
  }
  driverInstallWindow = new BrowserWindow({
    width: 560,
    height: 520,
    title: "rud1 — Install VPN driver",
    backgroundColor: nativeTheme.shouldUseDarkColors ? "#0a0e17" : "#f4f6fa",
    minimizable: false,
    maximizable: false,
    resizable: false,
    parent: mainWindow ?? undefined,
    modal: false,
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  driverInstallWindow.setMenu(null);
  const trustedId = driverInstallWindow.webContents.id;
  markWebContentsTrusted(trustedId);

  // We don't compute the exact bundled file paths here — the modal
  // displays them as transparency rather than load-bearing detail.
  // openvpnRuntimeDir() returns the parent folder; the modal lists
  // the well-known filenames so a missing file doesn't crash the UI.
  const dir = openvpnRuntimeDir();
  const wellKnownBundle: readonly string[] = dir
    ? [
        path.join(dir, "openvpn.exe"),
        path.join(dir, "tapctl.exe"),
        path.join(dir, "libssl-3-x64.dll"),
        path.join(dir, "libcrypto-3-x64.dll"),
        path.join(dir, "driver", "OemVista.inf"),
        path.join(dir, "driver", "tap0901.cat"),
        path.join(dir, "driver", "tap0901.sys"),
      ]
    : [];
  driverInstallWindow.loadURL(
    buildDriverInstallWindowHtml({
      currentTheme: getPreferences().theme,
      bundledFiles: wellKnownBundle,
    }),
  );
  driverInstallWindow.on("closed", () => {
    unmarkWebContentsTrusted(trustedId);
    driverInstallWindow = null;
  });
}

function notifyFirstBootDevice(probe: FirmwareProbeResult): void {
  if (!isNotificationEnabled("firstBoot")) return;
  // Route through the Liquid Glass toast overlay so the visual language
  // matches the rest of the app. A CTA opens the setup URL just like
  // the old native-notification click handler did.
  const channel = "first-boot:open-wizard:" + probe.host;
  const autoDismissMs = 12_000;
  pushToast({
    kind: "info",
    title: "rud1 device ready to configure",
    body: `A first-boot device is on the LAN at ${probe.host}. Open the setup wizard to claim it.`,
    autoDismissMs,
    action: { label: "Open wizard", channel },
  });
  const off = onToastAction(
    channel,
    () => {
      void shell.openExternal(probe.setupUrl);
      mainWindow?.show();
      off();
    },
    { ttlMs: autoDismissMs + 1_000 },
  );
}

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);

  // Arranca el cliente headless de VirtualHere en background. Sin
  // ventana ni tray icon: queda como daemon controlable via comandos
  // CLI (-t "<cmd>") que los IPC handlers de virtualhere:* invocan.
  void import("./virtualhere-manager").then((vh) => {
    const res = vh.startVirtualHereDaemon();
    if (!res.ok) {
      // No es fatal — el user verá un mensaje en la UI cuando intente
      // attach. Si el binary no está bundled tampoco rompemos el boot.
      console.warn("[virtualhere] daemon failed to start:", res.error);
    }
  });

  registerIpcHandlers({
    firstBootDedupe: {
      list: () => notifiedHosts,
      clearHost: (host) => clearNotifiedHost(host),
      clearAll: () => clearAllNotifiedHosts(),
    },
    onPreferencesUpdated: (prefs) => {
      applyThemeFromPreference(prefs.theme);
    },
    versionCheck: {
      getState: () =>
        versionCheckManager ? versionCheckManager.getState() : lastVersionCheckState,
      recheck: () => {
        void versionCheckManager?.checkOnce();
      },
    },
    vpnHealth: {
      onTransition: (event) => {
        setTrayVpnHealth(event.transition);
        if (mainWindow && !mainWindow.isDestroyed()) {
          try {
            // Re-pack explícito por si VpnHealthChangeEvent gana campos no-clonables.
            mainWindow.webContents.send("vpn:health", {
              transition: event.transition,
              snapshot: event.snapshot,
              diagnostic: event.diagnostic,
              consecutiveFailures: event.consecutiveFailures,
              at: event.at,
            });
          } catch {
            /* closed window; harmless */
          }
        }
      },
    },
    vpnDriverInstallUi: {
      show: () => { showDriverInstallWindow(); },
    },
    usbSessionState: {
      recordAttach: async (entry) => {
        usbSessions = addUsbSessionEntry(usbSessions, {
          host: entry.host,
          busId: entry.busId,
          label: entry.label,
          port: entry.port,
          attachedAt: new Date().toISOString(),
        });
        if (usbSessionFilepath) {
          await saveUsbSessions(usbSessionFilepath, usbSessions);
        }
      },
      recordDetachByPort: async (port) => {
        const before = usbSessions.length;
        usbSessions = removeUsbSessionByPort(usbSessions, port);
        if (usbSessions.length !== before && usbSessionFilepath) {
          await saveUsbSessions(usbSessionFilepath, usbSessions);
        }
      },
      recordDetachByBusId: async (busId) => {
        const before = usbSessions.length;
        usbSessions = removeUsbSessionByBusId(usbSessions, busId);
        if (usbSessions.length !== before && usbSessionFilepath) {
          await saveUsbSessions(usbSessionFilepath, usbSessions);
        }
      },
      onVpnConnected: async () => {
        await reattachStoredUsbSessions();
      },
    },
  });
  mainWindow = createWindow();
  createTray();

  try {
    const origin = new URL(APP_URL).origin;
    notificationStream = new NotificationStreamManager({
      baseUrl: origin,
      onNotificationClick: (url: string) => {
        if (mainWindow) {
          if (mainWindow.isMinimized()) mainWindow.restore();
          mainWindow.show();
          mainWindow.focus();
          void mainWindow.webContents.loadURL(url);
        }
      },
    });
    notificationStream.start();
  } catch {
    /* malformed APP_URL */
  }

  dedupeFilepath = path.join(app.getPath("userData"), DEDUPE_FILENAME);
  usbSessionFilepath = path.join(app.getPath("userData"), USB_SESSION_FILENAME);
  const preferencesPath = path.join(app.getPath("userData"), PREFERENCES_FILENAME);
  void loadPreferences(preferencesPath).then((prefs) => {
    applyThemeFromPreference(prefs.theme);
  });
  void loadUsbSessions(usbSessionFilepath, new Date()).then((loaded) => {
    usbSessions = loaded;
  });
  void loadNotifiedHosts(dedupeFilepath, new Date()).then((loaded) => {
    notifiedHosts = loaded;
    rebuildTrayMenu();
    broadcastDedupeUpdate();
  });
  startFirmwareProbeLoop();

  // installId estable por host (hostname local, no exfiltrado; bucket sha256 en [1,100]).
  const installId = `${app.getName()}:${os.hostname()}`;

  versionCheckManager = new VersionCheckManager({
    manifestUrl: VERSION_MANIFEST_URL,
    currentVersion: app.getVersion(),
    installId,
    forceRollout: () => isRolloutForceEnabled(),
    onStateChange: (state) => {
      lastVersionCheckState = state;
      rebuildTrayMenu();
      broadcastVersionCheckUpdate(state);
    },
    onManifestParsed: (manifest) => {
      lastManifestSha256 = manifest.sha256;
      lastManifestVersion = manifest.manifestVersion;
    },
  });
  versionCheckManager.start();

  configureAutoUpdaterRuntime({});
  subscribeAutoUpdate(() => { rebuildTrayMenu(); });

  try {
    const cloudOrigin = new URL(APP_URL).origin;
    deviceListManager = new DeviceListManager({
      baseUrl: cloudOrigin,
      onStateChange: () => { rebuildTrayMenu(); },
      onDeviceReady: (device) => { notifyDeviceReady(device.name); },
    });
    deviceListManager.start();
  } catch {
    deviceListManager = null;
  }

  void resumeAutoSnapshotFromDisk().catch(() => {
    /* ignore — surfaced on next status query */
  });

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) mainWindow = createWindow();
  });
});

app.on("window-all-closed", () => {
  // Win/Linux: stay in tray.
});

// Lifecycle: when the user quits (tray menu → Quit, Cmd+Q on macOS,
// taskbar close on Windows when in single-window mode), tear down the
// VPN child process FIRST so openvpn.exe doesn't orphan. The Electron
// `before-quit` event is the latest async-capable hook before exit —
// we preventDefault + run cleanup + quit() to give the kill enough time.
let isQuitting = false;
app.on("before-quit", (event) => {
  if (isQuitting) return;
  event.preventDefault();
  isQuitting = true;

  if (firmwareProbeTimer) {
    clearInterval(firmwareProbeTimer);
    firmwareProbeTimer = null;
  }
  versionCheckManager?.stop();
  deviceListManager?.stop();
  notificationStream?.stop();
  tray?.destroy();
  destroyToastOverlay();

  // Block the quit on the VPN tear-down. killRunning() has its own 3-5s
  // timeouts so this can't hang indefinitely.
  void (async () => {
    // Stop VirtualHere daemon — los devices attached caen al closing
    // del proceso. El user lo abrirá de nuevo cuando reabre la app.
    try {
      const { stopVirtualHereDaemon } = await import("./virtualhere-manager");
      stopVirtualHereDaemon();
    } catch {
      /* best-effort */
    }
    // Detach USB sessions FIRST while the tunnel still routes — the vpn:disconnect
    // IPC handler does this too, but before-quit calls vpnDisconnect() directly
    // and would otherwise leave an orphan VHCI port + bound device on the Pi.
    try {
      const { usbDetachAll } = await import("./usb-manager");
      await usbDetachAll();
    } catch (err) {
      console.warn("[lifecycle] usbDetachAll on quit failed:", err);
    }
    try {
      const { vpnDisconnect } = await import("./vpn-manager");
      await vpnDisconnect();
    } catch (err) {
      // Don't block exit on this — log and proceed.
      console.warn("[lifecycle] vpnDisconnect on quit failed:", err);
    }
    app.exit(0);
  })();
});

// Synchronous safety net: if the OS kills us (task manager, shutdown,
// power off) Electron may fire `quit` directly without before-quit. Best-
// effort: send SIGKILL to the tracked child so it doesn't orphan.
app.on("quit", () => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { killRunningSync } = require("./vpn-manager") as typeof import("./vpn-manager");
    killRunningSync();
  } catch {
    /* module already torn down */
  }
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
