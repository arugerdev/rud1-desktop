// Env: RUD1_APP_URL, RUD1_APP_ORIGIN (comma-separated), RUD1_DEV_TOOLS=1.
// app-target MUST be imported first: it pins RUD1_APP_ORIGIN and the
// secure-origin switch before ipc-handlers / app-ready consume them.
import { APP_URL } from "./app-target";
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
import {
  buildUpdateDialogHtml,
  type UpdaterDialogState,
} from "./update-dialog-html";
import { buildDriverInstallWindowHtml } from "./vpn-driver-install-html";
import { detectOpenVpnRuntime, openvpnRuntimeDir } from "./openvpn-installer";
import {
  PREFERENCES_FILENAME,
  getPreferences,
  isNotificationEnabled,
  loadPreferences,
  type ThemePreference,
} from "./preferences-manager";
import { detectLocale, getLocale, setLocale, t } from "./i18n";
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

const OPEN_DEV_TOOLS = process.env.RUD1_DEV_TOOLS === "1";
const VERSION_MANIFEST_URL =
  process.env.RUD1_VERSION_MANIFEST_URL ?? "https://rud1.es/desktop/manifest.json";
const FIRMWARE_PROBE_INTERVAL_MS = 60_000;
// Hard cap on how long the launch-time update gate waits for the first
// manifest check before giving up and opening the main window. Keeps a
// slow / offline network from stalling startup; the regular hourly poll
// still surfaces updates later via the tray.
const LAUNCH_GATE_TIMEOUT_MS = 6_000;
const AUTO_UPDATE_CONFIG_FILE = "auto-update-config.json";

let mainWindow: BrowserWindow | null = null;
let dedupeWindow: BrowserWindow | null = null;
let notificationStream: NotificationStreamManager | null = null;
let settingsWindow: BrowserWindow | null = null;
let updateDialogWindow: BrowserWindow | null = null;
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

// Armed by the launch gate (auto mode) so a "ready-to-apply" produced by
// THAT download triggers the openPath+restart. In-session downloads (tray
// "Update available", Settings "Download and install") never arm it, so they
// surface the manual "Restart and install" affordance instead of force-
// quitting a running session.
let autoApplyArmed = false;
// Resolves with the first terminal (non-checking) version-check verdict so
// the launch gate can decide whether to prompt before opening the app.
let firstVersionCheckSettled = false;
let resolveFirstVersionCheck: ((s: VersionCheckState) => void) | null = null;
const firstVersionCheckPromise = new Promise<VersionCheckState>((res) => {
  resolveFirstVersionCheck = res;
});

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
    { label: t("app.versionLabel", { version: app.getVersion() }), enabled: false },
    { type: "separator" },
    { label: t("tray.open"), click: () => { showOrCreateMainWindow(); } },
  ];

  appendMyDevicesSubmenu(items);
  if (lastFirmwareProbe && isFirstBoot(lastFirmwareProbe)) {
    const url = lastFirmwareProbe.setupUrl;
    items.push({ type: "separator" });
    items.push({
      label: t("tray.configureLocal", { host: lastFirmwareProbe.host }),
      click: () => { void shell.openExternal(url); },
    });
  } else if (lastFirmwareProbe && lastFirmwareProbe.reachable) {
    items.push({ type: "separator" });
    items.push({
      label: t("tray.openLocalPanel", { host: lastFirmwareProbe.host }),
      click: () => { void shell.openExternal(lastFirmwareProbe!.panelUrl); },
    });
  }
  items.push({ type: "separator" });
  items.push({
    label: t("firstBoot.menuTitle", { count: notifiedHosts.length }),
    submenu: [
      {
        label: t("firstBoot.showHosts", { count: notifiedHosts.length }),
        click: () => { showDedupeWindow(); },
      },
      {
        label: t("firstBoot.clearAll"),
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
    label: t("tray.settings"),
    click: () => { showSettingsWindow(); },
  });
  items.push({ type: "separator" });
  items.push({ label: t("tray.quit"), click: () => app.quit() });
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
      items.push({ label: t("devices.loading"), enabled: false });
      return;
    }
  }
  if (state.kind === "error") {
    items.push({ type: "separator" });
    if (state.reason === "signed-out") {
      items.push({
        label: t("devices.signIn"),
        click: () => { showOrCreateMainWindow(); },
      });
      return;
    }
    items.push({
      label: t("devices.loadFailed", { reason: state.reason }),
      enabled: false,
    });
    items.push({
      label: t("devices.retry"),
      click: () => { void deviceListManager?.refreshNow(); },
    });
    if (lastDevices == null) return;
  }

  const devices = lastDevices ?? [];
  if (devices.length === 0) {
    items.push({ type: "separator" });
    items.push({ label: t("devices.none"), enabled: false });
    items.push({
      label: t("devices.openDashboardToAdd"),
      click: () => { showOrCreateMainWindow(); },
    });
    return;
  }

  const MAX_VISIBLE = 12;
  const visible = devices.slice(0, MAX_VISIBLE);
  const onlineCount = devices.filter((d) => d.status === "ONLINE").length;

  items.push({ type: "separator" });
  items.push({
    label: t("devices.myDevices", { online: onlineCount, total: devices.length }),
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
              label: t("devices.andMore", { count: devices.length - MAX_VISIBLE }),
              enabled: false,
            },
          ]
        : []),
      { type: "separator" },
      {
        label: t("devices.viewAll"),
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
        label: t("devices.refresh"),
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
    title: t("firstBoot.windowTitle"),
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
  const lang = getLocale();
  // i18n strings consumed by the inline render() script — JSON-encoded so
  // quotes / accents survive the data: URL round-trip safely.
  const L = JSON.stringify({
    empty: t("firstBoot.empty"),
    clear: t("firstBoot.clear"),
    clearAll: t("firstBoot.clearAllBtn"),
    colHost: t("firstBoot.colHost"),
    colNotified: t("firstBoot.colNotified"),
    countOne: t("firstBoot.hostCountOne"),
    countMany: t("firstBoot.hostCountMany", { count: "{count}" }),
    confirmClearAll: t("firstBoot.confirmClearAll"),
  });
  const html = `<!doctype html>
<html lang="${lang}">
<head>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none';" />
<title>${t("firstBoot.windowTitle")}</title>
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
  <h1>${t("firstBoot.heading")}</h1>
  <p class="help">${t("firstBoot.help")}</p>
  <div id="list"></div>
  <div class="footer">
    <span id="status"></span>
    <button id="clear-all" class="danger" disabled>${t("firstBoot.clearAllBtn")}</button>
  </div>
<script>
  const L = ${L};
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
      listEl.innerHTML = '<div class="empty">' + escape(L.empty) + '</div>';
      clearAllBtn.disabled = true;
      statusEl.textContent = '';
      return;
    }
    clearAllBtn.disabled = false;
    statusEl.textContent = hosts.length === 1
      ? L.countOne
      : L.countMany.replace('{count}', String(hosts.length));
    var rows = hosts.map(function(h) {
      return '<tr>' +
        '<td class="host">' + escape(h.host) + '</td>' +
        '<td class="when" title="' + escape(h.notifiedAt) + '">' + escape(relativeTime(h.notifiedAt)) + '</td>' +
        '<td style="text-align:right;"><button data-host="' + escape(h.host) + '" class="row-clear">' + escape(L.clear) + '</button></td>' +
      '</tr>';
    }).join('');
    listEl.innerHTML = '<table><thead><tr><th>' + escape(L.colHost) + '</th><th>' + escape(L.colNotified) + '</th><th></th></tr></thead><tbody>' + rows + '</tbody></table>';
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
    if (!confirm(L.confirmClearAll)) return;
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

// ─── Update dialog (launch-time prompt + visual download progress) ──────────
//
// Combines the live VersionCheckState + AutoUpdateState + the `autoUpdate`
// preference into the single shape the dialog renderer maps to a card. The
// renderer computes elapsed/ETA/speed itself from the pushed byte counts, so
// nothing wall-clock has to live in the state machine.
function computeUpdaterDialogState(): UpdaterDialogState {
  const auto = getAutoUpdateState();
  const vc = lastVersionCheckState;
  const autoUpdate = getPreferences().autoUpdate;
  let current = app.getVersion();
  let latest = current;
  let downloadUrl: string | null = null;
  if (vc.kind === "update-available") {
    current = vc.current;
    latest = vc.latest;
    downloadUrl = vc.downloadUrl;
  } else if (vc.kind === "up-to-date") {
    current = vc.current;
    latest = vc.latest;
  }

  // An in-flight / finished download takes priority over the verdict — the
  // operator wants progress on the running download, not "v1.4 available".
  if (auto.kind === "downloading") {
    return {
      phase: "downloading",
      current,
      latest,
      downloadUrl,
      bytesReceived: auto.bytesReceived,
      totalBytes: auto.totalBytes,
      message: "",
      autoUpdate,
    };
  }
  if (auto.kind === "ready-to-apply") {
    return { phase: "ready", current, latest, downloadUrl, bytesReceived: 0, totalBytes: null, message: "", autoUpdate };
  }
  if (auto.kind === "error") {
    return { phase: "error", current, latest, downloadUrl, bytesReceived: 0, totalBytes: null, message: auto.message, autoUpdate };
  }
  // Auto-updater idle → derive from the version-check verdict.
  const base = { current, latest, downloadUrl, bytesReceived: 0, totalBytes: null as number | null, message: "", autoUpdate };
  switch (vc.kind) {
    case "update-available":
      return { ...base, phase: "available" };
    case "up-to-date":
      return { ...base, phase: "up-to-date" };
    case "error":
      return { ...base, phase: "error", message: vc.message };
    case "update-blocked-by-min-bootstrap":
      return { ...base, phase: "error", message: t("updates.summaryBlockedBootstrap", { version: vc.requiredMinVersion }) };
    case "update-blocked-by-signature-fetch":
      return { ...base, phase: "error", message: t("updates.summaryBlockedSignature", { reason: vc.reason }) };
    default:
      return { ...base, phase: "checking" };
  }
}

function broadcastUpdaterState(): void {
  if (!updateDialogWindow || updateDialogWindow.isDestroyed()) return;
  try {
    const snapshot = JSON.parse(JSON.stringify(computeUpdaterDialogState())) as UpdaterDialogState;
    updateDialogWindow.webContents.send("updater:state", snapshot);
  } catch {
    // best-effort
  }
}

function showUpdateDialog(): void {
  if (updateDialogWindow && !updateDialogWindow.isDestroyed()) {
    updateDialogWindow.focus();
    return;
  }
  updateDialogWindow = new BrowserWindow({
    width: 460,
    height: 440,
    title: t("updateDialog.windowTitle"),
    backgroundColor: nativeTheme.shouldUseDarkColors ? "#0a0e17" : "#f4f6fa",
    minimizable: false,
    maximizable: false,
    resizable: false,
    parent: mainWindow ?? undefined,
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  updateDialogWindow.setMenu(null);
  const trustedId = updateDialogWindow.webContents.id;
  markWebContentsTrusted(trustedId);
  updateDialogWindow.loadURL(buildUpdateDialogHtml(getPreferences().theme, getLocale()));
  updateDialogWindow.on("closed", () => {
    unmarkWebContentsTrusted(trustedId);
    updateDialogWindow = null;
    // Never strand the app with zero windows: if the dialog was the only
    // surface (launch gate) and we're not mid-quit, fall through to the
    // main window so closing the dialog "X" still opens rud1.
    if (!isQuitting && (!mainWindow || mainWindow.isDestroyed())) {
      showOrCreateMainWindow();
    }
  });
}

function closeUpdateDialogAndShowMain(): void {
  const w = updateDialogWindow;
  updateDialogWindow = null;
  if (w && !w.isDestroyed()) {
    try { w.close(); } catch { /* already gone */ }
  }
  showOrCreateMainWindow();
}

// Begin the in-app background download of the available update. Opens the
// progress dialog first (so a Settings-initiated "Download and install" has
// somewhere to render). When the manifest carries no in-app artifact URL we
// fall back to opening the public download page in the browser.
function startUpdateDownload(): void {
  const vc = lastVersionCheckState;
  if (vc.kind !== "update-available") return;
  if (!updateDialogWindow || updateDialogWindow.isDestroyed()) {
    showUpdateDialog();
  }
  const url = vc.downloadUrl;
  if (!url) {
    const ext =
      vc.releaseNotesUrl ??
      `https://rud1.es/desktop/download?version=${encodeURIComponent(vc.latest)}`;
    void shell.openExternal(ext);
    return;
  }
  // Sig-strict (opt-in, off by default) keeps its dedicated gate on the tray
  // path; the dialog download is the plain artifact fetch.
  void startBackgroundDownload(url, { sha256: lastManifestSha256 });
  broadcastUpdaterState();
}

// Mirror the `autoUpdate` preference into auto-update-config.json so the
// tray's isAutoUpdateEnabled() gate (which reads that file in packaged
// builds) stays consistent with the Settings toggle. Read-merge-write so
// sibling keys (strict, sigStrict, …) are preserved.
function mirrorAutoUpdateConfig(enabled: boolean): void {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const fs = require("fs") as typeof import("fs");
    const dir = app.getPath("userData");
    const p = path.join(dir, AUTO_UPDATE_CONFIG_FILE);
    let cfg: Record<string, unknown> = {};
    try {
      const parsed = JSON.parse(fs.readFileSync(p, "utf8"));
      if (parsed && typeof parsed === "object") cfg = parsed as Record<string, unknown>;
    } catch {
      /* missing / malformed — start fresh */
    }
    cfg.autoUpdate = enabled;
    fs.mkdirSync(dir, { recursive: true });
    // Atomic tmp+rename (matches preferences-manager.persist) so a crash
    // mid-write can't corrupt the shared config that also holds the
    // strict / sigStrict / rolloutForce / sigVerify gates.
    const tmp = `${p}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2), "utf8");
    fs.renameSync(tmp, p);
  } catch (err) {
    console.warn(
      "[auto-update] mirror config failed:",
      err instanceof Error ? err.message : err,
    );
  }
}

// Launch gate: show "Checking for updates…", await the first verdict (with a
// timeout so a slow network can't stall startup), then either prompt / auto-
// download or fall through to the main window.
async function runLaunchUpdateGate(): Promise<void> {
  const prefs = getPreferences();
  showUpdateDialog();
  versionCheckManager?.start();
  const winner = await Promise.race<VersionCheckState | null>([
    firstVersionCheckPromise,
    new Promise<null>((r) => setTimeout(() => r(null), LAUNCH_GATE_TIMEOUT_MS)),
  ]);
  if (winner && winner.kind === "update-available") {
    if (prefs.autoUpdate) {
      // Auto mode: arm auto-apply for THIS launch-gate download only, then
      // download. `autoApplyArmed` scopes the openPath+restart to the gate
      // so an in-session tray download never force-quits a running session.
      autoApplyArmed = true;
      startUpdateDownload();
    }
    broadcastUpdaterState();
    // Leave the main window closed: the dialog drives the decision (and the
    // app restarts on apply, or opens the main window on "Not now").
  } else {
    closeUpdateDialogAndShowMain();
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
    title: t("settings.windowTitle"),
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
      getPreferences().language,
      getLocale(),
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
    title: t("vpnDriver.windowTitle"),
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
      locale: getLocale(),
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
    title: t("firstBoot.toastTitle"),
    body: t("firstBoot.toastBody", { host: probe.host }),
    autoDismissMs,
    action: { label: t("firstBoot.openWizard"), channel },
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

app.whenReady().then(async () => {
  Menu.setApplicationMenu(null);

  registerIpcHandlers({
    firstBootDedupe: {
      list: () => notifiedHosts,
      clearHost: (host) => clearNotifiedHost(host),
      clearAll: () => clearAllNotifiedHosts(),
    },
    onPreferencesUpdated: (prefs) => {
      applyThemeFromPreference(prefs.theme);
      // Re-resolve the locale (the language preference may have changed)
      // and rebuild the tray + menus so the new language takes effect
      // without an app restart. Open data-URL windows render the locale
      // baked at open time; they pick up the change on next open.
      setLocale(detectLocale());
      rebuildTrayMenu();
      // Keep the tray's isAutoUpdateEnabled() gate consistent with the
      // Settings toggle.
      mirrorAutoUpdateConfig(prefs.autoUpdate);
    },
    versionCheck: {
      getState: () =>
        versionCheckManager ? versionCheckManager.getState() : lastVersionCheckState,
      recheck: () => {
        void versionCheckManager?.checkOnce();
      },
    },
    updater: {
      getState: () => computeUpdaterDialogState(),
      start: () => { startUpdateDownload(); },
      apply: () => { void applyAndRestart(); },
      later: () => { closeUpdateDialogAndShowMain(); },
      recheck: () => { void versionCheckManager?.checkOnce(); },
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
  // The main window is opened by the launch update gate at the end of
  // whenReady (after the first version check), so an available update can
  // prompt "before opening" per the operator-facing contract.
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
  // Await preferences before the launch gate so the dialog renders in the
  // pinned theme + locale and the gate can read the `autoUpdate` flag.
  // detectLocale() reads the preference (es/en pin) or falls back to
  // app.getLocale() (es-first).
  const bootPrefs = await loadPreferences(preferencesPath);
  applyThemeFromPreference(bootPrefs.theme);
  setLocale(detectLocale());
  rebuildTrayMenu();
  // Reconcile auto-update-config.json with the just-loaded preference so the
  // tray's isAutoUpdateEnabled() gate and the launch gate start from the same
  // value even if the config file drifted (hand-edit, deletion, prior failed
  // mirror write).
  mirrorAutoUpdateConfig(bootPrefs.autoUpdate);
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
      broadcastUpdaterState();
      // Settle the launch gate on the first terminal (non-checking) verdict.
      if (
        !firstVersionCheckSettled &&
        state.kind !== "checking" &&
        state.kind !== "idle"
      ) {
        firstVersionCheckSettled = true;
        resolveFirstVersionCheck?.(state);
      }
    },
    onManifestParsed: (manifest) => {
      lastManifestSha256 = manifest.sha256;
      lastManifestVersion = manifest.manifestVersion;
    },
  });
  // NB: start() is deferred to runLaunchUpdateGate() so the dialog paints
  // "Checking…" before the first fetch resolves.

  configureAutoUpdaterRuntime({});
  subscribeAutoUpdate((auto) => {
    rebuildTrayMenu();
    broadcastUpdaterState();
    // Auto mode (opt-in): once the launch-gate artifact is staged, verify +
    // install without waiting for a click. Scoped to `autoApplyArmed` so an
    // in-session tray / Settings download shows the manual "Restart and
    // install" button instead of force-quitting the running session. Gated
    // on app.isPackaged so a dev build can preview the download flow without
    // openPath+quit on a non-installer .bin.
    if (auto.kind === "ready-to-apply" && autoApplyArmed) {
      autoApplyArmed = false;
      if (app.isPackaged) void applyAndRestart();
    }
  });

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

  // Show "Checking for updates…", await the first verdict (with a timeout),
  // then prompt / auto-download or fall through to the main window.
  await runLaunchUpdateGate();
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
    // Detach USB sessions FIRST while the tunnel still routes — the vpn:disconnect
    // IPC handler does this too, but before-quit calls vpnDisconnect() directly
    // and would otherwise leave an orphan VHCI port + bound device on the Pi.
    try {
      const { usbDetachAll } = await import("./usb-manager");
      await usbDetachAll();
    } catch (err) {
      console.warn("[lifecycle] usbDetachAll on quit failed:", err);
    }
    // Kill any rud1-bridge subprocesses + release their Pi-side slots
    // while the tunnel still routes, so we don't strand a serial session.
    try {
      const { serialBridgeCloseAll } = await import("./serial-bridge-manager");
      await serialBridgeCloseAll();
    } catch (err) {
      console.warn("[lifecycle] serialBridgeCloseAll on quit failed:", err);
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
