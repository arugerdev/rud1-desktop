/**
 * rud1 Desktop — Electron main process.
 *
 * Loads the rud1.es web app in a BrowserWindow and injects the native bridge
 * (VPN, USB/IP) via the preload script. The web app detects that it's running
 * in Electron via window.electronAPI and enables native controls.
 *
 * Configuration (env vars or defaults):
 *   RUD1_APP_URL      — URL to load (default: https://www.rud1.es/dashboard).
 *                       The cloud's auth middleware redirects unauthenticated
 *                       users to /login; landing on /dashboard rather than
 *                       the marketing root means a logged-in user goes
 *                       straight to their devices and a logged-out user
 *                       lands on a sign-in form, never on the marketing site.
 *   RUD1_APP_ORIGIN   — allowed origin(s) for IPC, comma-separated
 *                       (default: https://rud1.es,https://www.rud1.es)
 *   RUD1_DEV_TOOLS    — open DevTools on start (set to "1" for debugging)
 */

import {
  app,
  BrowserWindow,
  shell,
  Menu,
  Notification,
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
import { computeTrayState } from "./tray-attention";
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
  PREFERENCES_FILENAME,
  getPreferences,
  isNotificationEnabled,
  loadPreferences,
} from "./preferences-manager";
import { NotificationStreamManager } from "./notification-stream-manager";
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
let notificationStream: NotificationStreamManager | null = null;
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
// Persisted USB/IP attach state (iter 7) — driven by usb:attach /
// usb:detach IPC handlers. Replayed on every successful vpn:connect
// so a transient tunnel drop doesn't force the user to re-attach
// every device by hand. Atomic disk writes go through saveUsbSessions.
let usbSessions: AttachedUsbSession[] = [];
let usbSessionFilepath: string | null = null;
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
// Polls /api/user/devices on the cloud so the tray submenu stays fresh
// without the renderer doing it. Started in app.whenReady() after the
// main window is created (the cookie jar is shared via the default
// session, so net.fetch carries auth automatically).
let deviceListManager: DeviceListManager | null = null;
// Iter 30 — captured from the last successful manifest fetch (when present)
// so `applyAndRestart` can verify the downloaded artifact's SHA-256.
// Iter 51 — both this AND the new `lastManifestVersion` are populated
// via the version-check manager's `onManifestParsed` callback (added in
// the same iter). Until iter 51 they were declared but never written —
// the iter-49 caveat called this out as a known follow-up. Now the
// iter-49 minisign signed-data, the iter-48 sig-fetch gate, and the
// signature-not-supported diagnostics envelope all read the real
// values from the most-recent successful manifest fetch.
let lastManifestSha256: string | null = null;
// Iter 51 — manifest schema version (1, 2, or 3). Threaded into
// `applySignatureFetchGate` as `options.manifestVersion`; the gate uses
// it to distinguish "v1/v2 manifest can't carry a signatureUrl"
// (`signature-not-supported-by-manifest-version`) from "v3 manifest
// signatureUrl unreachable / empty / verification mismatched". Without
// this, the diagnostics envelope's `manifestVersion` field rendered
// `null` for every blocked verdict — operators couldn't tell from a
// support blob whether the publisher needed to upgrade to v3 or fix
// their existing v3 sidecar.
let lastManifestVersion: number | null = null;

// Resuelve el icono empaquetado para la BrowserWindow + taskbar.
//   Dev:    resources/<platform>/  →  <repo>/resources/icon.{ico,png}
//   Prod:   process.resourcesPath  →  <app>/resources/icon.{ico,png}
// Devuelve null cuando no hay icono — Electron entonces cae al icono
// por defecto, sin romper nada. Los iconos los genera el script
// `scripts/generate-app-icons.py` a partir del favicon de rud1-es,
// y se cablean en el packaging vía `win.icon` / `linux.icon` /
// `mac.icon` del package.json.
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
      // Sync existsSync deliberately — solo se llama una vez al
      // crear ventana; no hay loop ni hot path aquí.
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const fs = require("fs") as typeof import("fs");
      if (fs.existsSync(candidate)) return candidate;
    } catch {
      // Defensive: un fallo del fs no debe impedir abrir la ventana.
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
    // Icono explícito en lugar de depender solo del manifest del .exe.
    // Sin esto, el icono de la barra de tareas durante una sesión `npm
    // run dev` cae al icono por defecto de Electron — el packaging lo
    // arreglaba pero los desarrolladores veían el "átomo" de Electron
    // todo el rato.
    ...(iconPath ? { icon: iconPath } : {}),
    // Oculta la barra de menú nativa (File / Edit / View / …). El
    // operador final no necesita esos atajos — esto es una "real app"
    // que carga rud1.es, no un editor. La barra de título estándar (con
    // los botones minimizar/maximizar/cerrar) se mantiene porque al
    // ponerla en false además se quitan esos controles, y los usuarios
    // de Windows esperan poder arrastrar la ventana por su título.
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  // setMenuBarVisibility(false) extra para que ALT no la haga emerger.
  // autoHideMenuBar sólo la oculta hasta que el usuario pulsa Alt; aquí
  // queremos que NUNCA aparezca.
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

// Show the main window if it already exists; otherwise create a new one
// and capture the reference so the next click reuses it. The earlier
// `mainWindow?.show() ?? createWindow()` shape was wrong: `show()` returns
// `undefined`, so the `??` always fell through to `createWindow()` and a
// duplicate window appeared on every tray click while a window was already
// open.
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

// rebuildTrayMenu refreshes the context menu using the cached
// `lastFirmwareProbe`. Called both at tray-creation time AND whenever the
// background probe finishes — `lastFirmwareProbe.reachable` deciding the
// shape of the menu (a "Configure local rud1" entry appears only when a
// first-boot device is on the LAN). Setting context menu is idempotent so
// we don't bother diffing. Tooltip is owned by setTrayAttention (iter 28)
// so the badge state machine is the sole writer.
function rebuildTrayMenu(): void {
  if (!tray) return;
  // Header: product + version as a disabled label so the tray identifies
  // itself even on a packed taskbar. Common Electron-app pattern;
  // operators expect the first row to be informational, not actionable.
  const items: Electron.MenuItemConstructorOptions[] = [
    { label: `rud1 v${app.getVersion()}`, enabled: false },
    { type: "separator" },
    { label: "Open rud1", click: () => { showOrCreateMainWindow(); } },
  ];

  // My devices submenu — the operator's full device roster across every
  // org they're a member of, with at-a-glance ONLINE/OFFLINE state.
  // Click jumps the main window to that device's detail page.
  appendMyDevicesSubmenu(items);
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
          // Iter 49 — sig-VERIFY (independent of iter-48 sig-strict).
          // When SIG_VERIFY=1 we additionally crypto-verify the
          // sidecar bytes against the publisher's ed25519 pubkey.
          // The signed-data is the manifest's pinned sha256 hex
          // string (from iter-31). When SIG_VERIFY is OFF this
          // collapses to a byte-identical iter-48 fetch-only
          // gate invocation.
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
            // Iter 51 — pass the captured manifestVersion through so the
            // gate's "manifest < v3 ⇒ signature-not-supported" branch
            // fires when appropriate. The gate's diagnostics envelope
            // reads back state.manifestVersion which now lands on the
            // blocked verdict.
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
 * Append the "My devices" submenu using the latest poll from
 * `deviceListManager`. Three shapes:
 *
 *   - no manager yet / loading on first start → "Loading devices…" (disabled)
 *   - signed out (HTTP 401) → "Sign in to view your devices" (opens the
 *     main window so the user can authenticate)
 *   - other error → "Couldn't load devices (reason)" + a recheck entry
 *   - success → 1 disabled summary row + 1 row per device, plus a
 *     "View all in dashboard" anchor at the bottom
 *
 * Capped at 12 visible device rows to keep the submenu navigable; the
 * "View all" entry routes users with bigger fleets to the dashboard.
 */
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
    // Fall through with the last successful snapshot to avoid a blink.
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
    // else fall through — still render the cached list below
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
  // Strip whatever trailing path APP_URL pointed at (probably /dashboard)
  // and route to the device detail page directly.
  const origin = APP_URL.replace(/\/dashboard.*$/, "");
  void mainWindow.webContents.loadURL(`${origin}/dashboard/devices/${d.id}`);
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
 * Iter 7 — replay every persisted USB/IP attach after a successful
 * VPN connect. Each attach runs in series so the kernel doesn't see
 * a burst of `usbip attach` calls; per-device failures are logged
 * and the rest of the sweep continues. Successes refresh the row's
 * port (the kernel re-numbers freely on reattach).
 */
async function reattachStoredUsbSessions(): Promise<void> {
  if (usbSessions.length === 0) return;
  const snapshot = [...usbSessions];
  for (const session of snapshot) {
    try {
      const port = await usbAttach(session.host, session.busId);
      // Refresh the port + attachedAt so the file reflects the live
      // state after the sweep. The dedupe via (host, busId) keeps the
      // row count stable.
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
  /*
   * rud1 Liquid Glass — dedupe inspector.
   * Light + dark via prefers-color-scheme; pastel palette aligned
   * with the Settings panel and the rest of the rud1 design system.
   */
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

// Iter 37 — Settings/About inspector. Shows live VersionCheckState
// (incl. iter-36 update-blocked verdicts) using the iter-28 data:-URL
// + trustedWebContentsIds pattern. Two IPC ops: clipboard:writeText
// (data: origins lack navigator.clipboard) and shell:openExternal
// (http/https allowlist on main).

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
  // Same trust-bridge rationale as the dedupe inspector: the panel loads
  // from a `data:` URL whose origin would never pass `isOriginAllowed`,
  // so we register its webContents id in the trusted set. The main
  // process opened this window and controls its HTML byte-for-byte.
  const trustedId = settingsWindow.webContents.id;
  markWebContentsTrusted(trustedId);
  // Iter 44+46 — go through the named-wrapper helper so app.getVersion()
  // gets baked into all four diagnostic surfaces (inline APP_VERSION +
  // the three renderer-side rebuilds for error/blocked/update-available);
  // the raw buildSettingsWindowHtml lets a call site forget one. Safe
  // here: app.whenReady() has resolved by the time the tray opens.
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

// notifyFirstBootDevice — single OS notification when a first-boot rud1
// appears on LAN; click opens the setup URL (same destination as the
// tray entry). Notification.isSupported() is false on Linux without
// libnotify, Windows with toasts disabled, and prod builds missing an
// AppUserModelID — we swallow silently because the tray surfaces the
// same affordance (graceful degradation, not an error).
function notifyFirstBootDevice(probe: FirmwareProbeResult): void {
  if (!Notification.isSupported()) return;
  // Per-category mute. The lifecycle still drives the tray badge + dedupe
  // file regardless; only the OS toast is suppressed.
  if (!isNotificationEnabled("firstBoot")) return;
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
  // Apaga el menú nativo (File / Edit / View / Help). Combinado con
  // `autoHideMenuBar: true` y `setMenuBarVisibility(false)` en la
  // ventana principal, esto garantiza que ni siquiera la pulsación de
  // ALT pueda hacer aparecer la barra. La app se comporta como una
  // aplicación de escritorio dedicada (estilo Slack / Discord) en
  // lugar de un browser ligero.
  Menu.setApplicationMenu(null);

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
    // Iter 7 — USB/IP auto-reattach. The IPC handlers call into these
    // closures so the in-memory `usbSessions` array (mutated only here
    // in main) stays the source of truth, and disk writes are
    // serialised through saveUsbSessions.
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

  // Cloud→Desktop SSE stream for native OS notifications. The
  // dashboard cookie session is shared via Electron's default session,
  // so net.fetch carries auth automatically — no extra wiring beyond
  // resolving the origin from APP_URL.
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
    // Malformed APP_URL — skip the stream rather than crash the boot.
  }

  // Resolve userData and prime the persisted first-boot dedupe set BEFORE
  // the probe loop fires. If the load is slow (cold disk, network drive)
  // the loop still starts on time — a cache miss just means the very first
  // tick after launch may re-notify a host we already knew about, which is
  // strictly better than blocking startup on disk I/O.
  dedupeFilepath = path.join(app.getPath("userData"), DEDUPE_FILENAME);
  usbSessionFilepath = path.join(app.getPath("userData"), USB_SESSION_FILENAME);
  // Load persisted user preferences (theme + per-category notification
  // toggles) before notifications start firing. The Settings window
  // reads/writes through this same module via IPC.
  const preferencesPath = path.join(app.getPath("userData"), PREFERENCES_FILENAME);
  void loadPreferences(preferencesPath);
  // Hydrate the persisted USB/IP attach state. Best-effort: a parse
  // failure leaves `usbSessions` empty, the auto-reattach feature
  // simply no-ops until the user attaches something fresh.
  void loadUsbSessions(usbSessionFilepath, new Date()).then((loaded) => {
    usbSessions = loaded;
  });
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
    // Iter 51 — capture the parsed manifest's sha256 + manifestVersion
    // on every successful fetch so the iter-49 sig-VERIFY plumbing and
    // the iter-48 sig-fetch gate can read the live values. Before this
    // wire-up both module-level vars stayed permanently null (declared
    // but never assigned), which silently degraded the verifySignedData
    // path to "empty buffer ⇒ verify rejects" and forced every blocked
    // verdict's diagnostics envelope to render manifestVersion=null.
    onManifestParsed: (manifest) => {
      lastManifestSha256 = manifest.sha256;
      lastManifestVersion = manifest.manifestVersion;
    },
  });
  versionCheckManager.start();

  // Iter 30 — wire the auto-updater module's Electron-side handles so
  // its env-flag gate and download/apply path can run when the operator
  // has opted in. Subscribing to its state machine triggers tray menu
  // rebuilds on every "downloading… 42%" tick.
  configureAutoUpdaterRuntime({});
  subscribeAutoUpdate(() => { rebuildTrayMenu(); });

  // Devices submenu on the tray. Cloud URL origin only — we strip any
  // trailing /dashboard from APP_URL so the API call lands on the same
  // origin the BrowserWindow loaded (cookie scope match).
  try {
    const cloudOrigin = new URL(APP_URL).origin;
    deviceListManager = new DeviceListManager({
      baseUrl: cloudOrigin,
      onStateChange: () => { rebuildTrayMenu(); },
    });
    deviceListManager.start();
  } catch {
    // Malformed APP_URL — skip the devices submenu rather than crash.
    deviceListManager = null;
  }

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
  deviceListManager?.stop();
  notificationStream?.stop();
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
