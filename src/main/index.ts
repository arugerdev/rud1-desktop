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
import { registerIpcHandlers } from "./ipc-handlers";
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

const APP_URL = process.env.RUD1_APP_URL ?? "https://rud1.es";
const OPEN_DEV_TOOLS = process.env.RUD1_DEV_TOOLS === "1";
// Recheck cadence for the LAN firmware probe. 60s is short enough that an
// operator who plugs a device in during a session sees the tray entry
// within a minute, but long enough that the probe is invisible on the
// network.
const FIRMWARE_PROBE_INTERVAL_MS = 60_000;

let mainWindow: BrowserWindow | null = null;
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
// first-boot device is on the LAN). Setting tooltip + context menu is
// idempotent so we don't bother diffing.
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
  items.push({ type: "separator" });
  items.push({ label: "Quit", click: () => app.quit() });
  tray.setContextMenu(Menu.buildFromTemplate(items));
  const tip =
    lastFirmwareProbe && isFirstBoot(lastFirmwareProbe)
      ? "rud1 Desktop — first-boot device on LAN"
      : "rud1 Desktop";
  tray.setToolTip(tip);
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
  registerIpcHandlers();
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
