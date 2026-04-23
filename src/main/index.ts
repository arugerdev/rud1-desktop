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

import { app, BrowserWindow, shell, Menu, Tray, nativeImage } from "electron";
import path from "path";
import { registerIpcHandlers } from "./ipc-handlers";
import { resumeAutoSnapshotFromDisk } from "./auto-snapshot-manager";

const APP_URL = process.env.RUD1_APP_URL ?? "https://rud1.es";
const OPEN_DEV_TOOLS = process.env.RUD1_DEV_TOOLS === "1";

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;

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

  const menu = Menu.buildFromTemplate([
    { label: "Open rud1", click: () => { mainWindow?.show() ?? createWindow(); } },
    { type: "separator" },
    { label: "Quit", click: () => app.quit() },
  ]);

  tray.setToolTip("rud1 Desktop");
  tray.setContextMenu(menu);
  tray.on("click", () => { mainWindow?.show() ?? createWindow(); });
}

// ─── App lifecycle ────────────────────────────────────────────────────────────

app.whenReady().then(() => {
  registerIpcHandlers();
  mainWindow = createWindow();
  createTray();

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
