/**
 * Minimal i18n for the Electron main process. Spanish-first (the product
 * is es-default; the web + on-device panel are bilingual es/en).
 *
 * Design:
 *   - `translations` holds the full es/en key trees, organised by area.
 *     Both trees MUST mirror each other key-for-key (a vitest test pins
 *     this so a forgotten translation is caught at CI, not at runtime).
 *   - `t(key, vars)` does a dot-path lookup into the CURRENT locale.
 *     Missing keys fall back to English, then to the raw key — `t` never
 *     throws. `{name}`-style placeholders are interpolated from `vars`.
 *   - The module-level locale starts as "en" so pure helpers exercised by
 *     the vitest suite (which never calls `setLocale`) keep returning the
 *     English copy their byte-for-byte assertions pin. At runtime
 *     `index.ts` calls `setLocale(detectLocale())` early in `whenReady`,
 *     which resolves to "es" by default (Spanish-first) — see
 *     `detectLocale`.
 *
 * Do NOT route log lines, error stacks, IPC channel names, file paths,
 * binary names or env vars through here — only user-facing UI copy.
 */

export type Locale = "es" | "en";

type TranslationTree = { [key: string]: string | TranslationTree };

export const translations: Record<Locale, TranslationTree> = {
  es: {
    app: {
      versionLabel: "rud1 v{version}",
    },
    tray: {
      open: "Abrir rud1",
      settings: "Ajustes y acerca de…",
      quit: "Salir",
      configureLocal: "Configurar rud1 local ({host})",
      openLocalPanel: "Abrir panel rud1 local ({host})",
      tooltipBase: "rud1 Desktop",
      tooltipOneDevice: "rud1 Desktop — 1 dispositivo listo para configurar",
      tooltipManyDevices: "rud1 Desktop — {count} dispositivos listos para configurar",
      vpnDown: "VPN desconectada",
      vpnRecovering: "VPN reconectando…",
    },
    devices: {
      loading: "Cargando dispositivos…",
      signIn: "Inicia sesión para ver tus dispositivos",
      loadFailed: "No se pudieron cargar los dispositivos ({reason})",
      retry: "Reintentar ahora",
      none: "Aún no hay dispositivos",
      openDashboardToAdd: "Abre el panel para añadir uno",
      myDevices: "Mis dispositivos — {online}/{total} en línea",
      andMore: "…y {count} más",
      viewAll: "Ver todos en el panel",
      refresh: "Actualizar ahora",
    },
    firstBoot: {
      menuTitle: "Notificaciones de primer arranque ({count})",
      showHosts: "Ver hosts notificados ({count})",
      clearAll: "Borrar todos los hosts notificados",
      windowTitle: "rud1 — Notificaciones de primer arranque",
      heading: "Notificaciones de primer arranque",
      help: "Hosts sobre los que la app de escritorio ya te ha notificado. Las entradas caducan automáticamente a los 30 días; un host que se finalizó y se reflasheó volverá a notificar en su próxima detección de primer arranque.",
      colHost: "Host",
      colNotified: "Notificado",
      empty: "No hay hosts notificados.",
      clear: "Borrar",
      clearAllBtn: "Borrar todo",
      hostCountOne: "1 host notificado",
      hostCountMany: "{count} hosts notificados",
      confirmClearAll: "¿Borrar todos los hosts notificados? Volverán a notificar en la próxima detección de primer arranque.",
      toastTitle: "Dispositivo rud1 listo para configurar",
      toastBody: "Hay un dispositivo de primer arranque en la LAN en {host}. Abre el asistente de configuración para reclamarlo.",
      openWizard: "Abrir asistente",
    },
    updates: {
      downloadingPct: "Descargando actualización… {pct}%",
      downloadingBytes: "Descargando actualización… {bytes}",
      readyRestart: "Descarga lista — Reinicia para instalar",
      downloadFailed: "Error al descargar la actualización: {message}",
      resetAndRetry: "Restablecer y reintentar la comprobación",
      available: "▲ Actualización disponible — v{latest}",
      currentlyInstalled: "Instalada actualmente: v{current}",
      whatsNew: "Novedades — ver notas de la versión",
      checkNow: "Buscar actualizaciones ahora",
      upToDate: "Actualizado (v{current})",
      manualInstallRequired: "La actualización requiere instalación manual: descarga v{version} primero",
      targetVersion: "Versión objetivo: v{version}",
      blockedSignature: "Actualización bloqueada: no se pudo verificar la firma ({reason})",
      checkFailed: "No se pudieron buscar actualizaciones: {message}",
      retryCheck: "Reintentar la comprobación",
      summaryIdle: "La comprobación de actualizaciones aún no se ha ejecutado.",
      summaryChecking: "Buscando actualizaciones…",
      summaryUpToDate: "Actualizado (v{current}).",
      summaryAvailable: "Actualización disponible — v{latest} (actualmente v{current}).",
      summaryBlockedBootstrap: "Actualización bloqueada: instala v{version} manualmente primero.",
      summaryBlockedSignature: "Actualización bloqueada por sig-strict: {reason}.",
      summaryError: "No se pudieron buscar actualizaciones: {message}",
      bannerDownloadManual: "Descarga v{version} manualmente primero para seguir recibiendo actualizaciones",
      lineCurrentlyInstalled: "Instalada actualmente: v{version}",
      lineTarget: "Objetivo: v{version}",
      hintManualDownload: "Descarga manual necesaria para v{version}",
      hintReason: "Motivo: {reason}",
    },
    notifications: {
      vpnConnectedTitle: "VPN conectada",
      vpnConnectedBodyNamed: "Túnel activo hacia {name}.",
      vpnConnectedBody: "El túnel está activo.",
      vpnCgnatTitle: "VPN conectando (CGNAT detectado)",
      vpnCgnatBodyNamed: "{name} parece estar detrás de un NAT de operador (CGNAT). El cliente OpenVPN abre una conexión TLS saliente, así que esto suele funcionar igualmente.",
      vpnCgnatBody: "Se ha detectado un NAT de operador (CGNAT) en el lado del dispositivo. El cliente OpenVPN abre una conexión TLS saliente, así que esto suele funcionar igualmente.",
      vpnTapTitle: "Se requiere el controlador TAP",
      vpnTapBody: "rud1 necesita instalar el controlador TAP-Windows V9. Pulsa Conectar y acepta el aviso de elevación.",
      vpnDisconnectedTitle: "VPN desconectada",
      vpnDisconnectedTunnelTo: "El túnel hacia {name} se ha caído",
      vpnDisconnectedTunnelDown: "El túnel está caído",
      vpnDisconnectedAfter: " tras {uptime}",
      vpnErrorTitle: "Error de VPN",
      usbAttachedTitle: "USB conectado",
      usbAttachedBody: "{subject} ya está montado en este equipo.",
      usbDetachedTitle: "USB desconectado",
      usbDetachedBody: "{subject} se ha desmontado.",
      usbFallback: "USB {busId}",
      deviceReadyTitle: "{name} conectado",
      deviceReadyBody: "{name} está en línea y listo para usar.",
      deviceFallback: "Dispositivo",
      cloudOpen: "Abrir",
    },
    settings: {
      windowTitle: "rud1 — Ajustes y acerca de",
      heading: "Ajustes y acerca de",
      subtitle: "rud1 desktop — controles de operador y estado de actualización.",
      updatesHeading: "Actualizaciones",
      loading: "Cargando…",
      appearanceHeading: "Apariencia",
      themeLabel: "Tema",
      themeHint: "Elige cómo se ve el panel de ajustes. Las demás superficies siguen al panel en la nube.",
      themeSystem: "Sistema",
      themeLight: "Claro",
      themeDark: "Oscuro",
      languageLabel: "Idioma",
      languageHint: "Idioma de los menús, avisos y ventanas de rud1.",
      languageSystem: "Sistema",
      languageEs: "Español",
      languageEn: "English",
      notificationsHeading: "Notificaciones",
      notifFirstBootLabel: "Dispositivos de primer arranque",
      notifFirstBootHint: "Aviso cuando un rud1 recién flasheado aparece en la LAN.",
      notifVpnLabel: "Eventos de VPN",
      notifVpnHint: "Avisos de conexión / desconexión / advertencia CGNAT del túnel.",
      notifUsbLabel: "Eventos de USB",
      notifUsbHint: "Avisos de conexión / desconexión tras un cambio de sesión USB/IP.",
      startupHeading: "Inicio",
      autoStartLabel: "Iniciar rud1 al iniciar sesión",
      autoStartWin: "rud1 se inicia minimizado en la bandeja al iniciar sesión en Windows.",
      autoStartMac: "rud1 arranca oculto al iniciar sesión en macOS (elemento de inicio).",
      autoStartLinux: "Gestiona una entrada en ~/.config/autostart/. Efectivo en el próximo inicio de sesión.",
      autoStartUnsupported: "El inicio automático no está disponible en esta compilación.",
      autoStartStateUnavailable: "Estado del inicio automático no disponible.",
      autoStartApiUnavailable: "API de inicio automático no disponible en esta compilación.",
      autoStartEnabled: "Inicio automático activado",
      autoStartDisabled: "Inicio automático desactivado",
      autoStartChangeFailed: "No se pudo cambiar el inicio automático: {error}",
      firstBootHeading: "Notificaciones de primer arranque",
      firstBootHelp: "Gestiona los hosts sobre los que la app de escritorio ya te ha notificado.",
      openInspector: "Abrir inspector de hosts notificados…",
      statusUnavailable: "Estado de actualización no disponible.",
      currentlyInstalled: "Instalada actualmente",
      targetVersionRow: "Versión objetivo",
      requiredIntermediate: "Intermedia requerida",
      reasonRow: "Motivo",
      signatureUrlRow: "URL de firma",
      httpStatusRow: "Estado HTTP",
      expectedSha: "SHA-256 esperado",
      verifyHashHelp: "Verifica el hash antes de ejecutar el instalador — {winCmd} en Windows o {unixCmd} en macOS / Linux.",
      copyDownloadUrl: "Copiar URL de descarga",
      copyExpectedSha: "Copiar sha256 esperado",
      copyDiagnostics: "Copiar diagnóstico",
      copiedDownloadUrl: "URL de descarga copiada al portapapeles",
      copiedExpectedSha: "sha256 esperado copiado al portapapeles",
      copiedDiagnostics: "Diagnóstico copiado al portapapeles",
      copyFailed: "Error al copiar: {error}",
      recheckToast: "Volviendo a buscar actualizaciones…",
      themeToast: "Tema: {theme}",
      themeSaveFailed: "No se pudo guardar el tema: {error}",
      languageToast: "Idioma: {language}",
      languageSaveFailed: "No se pudo guardar el idioma: {error}",
      notifSavedOn: "Notificaciones de {key}: activadas",
      notifSavedOff: "Notificaciones de {key}: desactivadas",
      saveFailed: "No se pudo guardar: {error}",
      openFromTray: "Ábrelo desde el menú de la bandeja → Notificaciones de primer arranque",
      unknownError: "desconocido",
    },
    vpnDriver: {
      windowTitle: "rud1 — Instalar controlador VPN",
      heading: "Instalar el controlador VPN",
      badge: "Configuración única",
      intro: "rud1 necesita instalar el controlador de kernel TAP-Windows V9 para que el cliente OpenVPN pueda exponer un adaptador de red virtual a tus herramientas de ingeniería (TIA Portal, Codesys, descubrimiento OPC UA, etc).",
      introMuted: "Windows te pedirá aprobar la instalación. El controlador está firmado por OpenVPN Inc. y viene incluido con rud1 — no se requiere ninguna descarga externa.",
      step1Prefix: "Pulsa ",
      step1Bold: "Instalar controlador",
      step1Suffix: " abajo.",
      step2: "Aprueba el aviso de elevación del sistema (Control de cuentas de usuario).",
      step3Prefix: "Pulsa ",
      step3Bold: "Conectar",
      step3Suffix: " en la página del dispositivo en rud1.",
      filesSummary: "Archivos instalados (firmados por OpenVPN Inc.)",
      cancel: "Cancelar",
      install: "Instalar controlador",
      done: "Listo",
      bridgeUnavailable: "Puente no disponible. Reinicia rud1 e inténtalo de nuevo.",
      waitingElevation: "Esperando el aviso de elevación del sistema…",
      installedOk: "Controlador instalado. Puedes cerrar esta ventana y pulsar Conectar.",
      installCancelled: "La instalación del controlador se canceló o falló.",
      installFailed: "La instalación del controlador falló.",
    },
    toast: {
      regionLabel: "notificaciones de rud1",
      dismiss: "Descartar",
    },
  },
  en: {
    app: {
      versionLabel: "rud1 v{version}",
    },
    tray: {
      open: "Open rud1",
      settings: "Settings & About…",
      quit: "Quit",
      configureLocal: "Configure local rud1 ({host})",
      openLocalPanel: "Open local rud1 panel ({host})",
      tooltipBase: "rud1 Desktop",
      tooltipOneDevice: "rud1 Desktop — 1 device ready to configure",
      tooltipManyDevices: "rud1 Desktop — {count} devices ready to configure",
      vpnDown: "VPN disconnected",
      vpnRecovering: "VPN reconnecting…",
    },
    devices: {
      loading: "Loading devices…",
      signIn: "Sign in to view your devices",
      loadFailed: "Couldn't load devices ({reason})",
      retry: "Retry now",
      none: "No devices yet",
      openDashboardToAdd: "Open dashboard to add one",
      myDevices: "My devices — {online}/{total} online",
      andMore: "…and {count} more",
      viewAll: "View all in dashboard",
      refresh: "Refresh now",
    },
    firstBoot: {
      menuTitle: "First-boot notifications ({count})",
      showHosts: "Show notified hosts ({count})",
      clearAll: "Clear all notified hosts",
      windowTitle: "rud1 — First-boot notifications",
      heading: "First-boot notifications",
      help: "Hosts the desktop app has already notified you about. Entries expire automatically after 30 days; a host that was finished and re-flashed will re-notify on its next first-boot detection.",
      colHost: "Host",
      colNotified: "Notified",
      empty: "No notified hosts.",
      clear: "Clear",
      clearAllBtn: "Clear all",
      hostCountOne: "1 notified host",
      hostCountMany: "{count} notified hosts",
      confirmClearAll: "Clear all notified hosts? They will re-notify on the next first-boot detection.",
      toastTitle: "rud1 device ready to configure",
      toastBody: "A first-boot device is on the LAN at {host}. Open the setup wizard to claim it.",
      openWizard: "Open wizard",
    },
    updates: {
      downloadingPct: "Downloading update… {pct}%",
      downloadingBytes: "Downloading update… {bytes}",
      readyRestart: "Download ready — Restart to install",
      downloadFailed: "Update download failed: {message}",
      resetAndRetry: "Reset and retry update check",
      available: "▲ Update available — v{latest}",
      currentlyInstalled: "Currently installed: v{current}",
      whatsNew: "What's new — view release notes",
      checkNow: "Check for updates now",
      upToDate: "Up to date (v{current})",
      manualInstallRequired: "Update requires manual install: download v{version} first",
      targetVersion: "Target version: v{version}",
      blockedSignature: "Update blocked: signature could not be verified ({reason})",
      checkFailed: "Couldn't check for updates: {message}",
      retryCheck: "Retry update check",
      summaryIdle: "Update check has not run yet.",
      summaryChecking: "Checking for updates…",
      summaryUpToDate: "Up to date (v{current}).",
      summaryAvailable: "Update available — v{latest} (currently v{current}).",
      summaryBlockedBootstrap: "Update blocked: install v{version} manually first.",
      summaryBlockedSignature: "Update blocked by sig-strict: {reason}.",
      summaryError: "Couldn't check for updates: {message}",
      bannerDownloadManual: "Download v{version} manually first to continue receiving updates",
      lineCurrentlyInstalled: "Currently installed: v{version}",
      lineTarget: "Target: v{version}",
      hintManualDownload: "Manual download required for v{version}",
      hintReason: "Reason: {reason}",
    },
    notifications: {
      vpnConnectedTitle: "VPN Connected",
      vpnConnectedBodyNamed: "Tunnel up to {name}.",
      vpnConnectedBody: "Tunnel is up.",
      vpnCgnatTitle: "VPN connecting (CGNAT detected)",
      vpnCgnatBodyNamed: "{name} appears to be behind carrier-grade NAT. The OpenVPN client opens an outbound TLS connection, so this typically still works.",
      vpnCgnatBody: "Carrier-grade NAT was detected on the device side. The OpenVPN client opens an outbound TLS connection, so this typically still works.",
      vpnTapTitle: "TAP driver required",
      vpnTapBody: "rud1 needs to install the TAP-Windows V9 driver. Click Connect and accept the elevation prompt.",
      vpnDisconnectedTitle: "VPN Disconnected",
      vpnDisconnectedTunnelTo: "Tunnel to {name} dropped",
      vpnDisconnectedTunnelDown: "Tunnel is down",
      vpnDisconnectedAfter: " after {uptime}",
      vpnErrorTitle: "VPN Error",
      usbAttachedTitle: "USB Attached",
      usbAttachedBody: "{subject} is now mounted on this machine.",
      usbDetachedTitle: "USB Detached",
      usbDetachedBody: "{subject} was unmounted.",
      usbFallback: "USB {busId}",
      deviceReadyTitle: "{name} connected",
      deviceReadyBody: "{name} is online and ready to use.",
      deviceFallback: "Device",
      cloudOpen: "Open",
    },
    settings: {
      windowTitle: "rud1 — Settings & About",
      heading: "Settings & About",
      subtitle: "rud1 desktop — operator controls and update status.",
      updatesHeading: "Updates",
      loading: "Loading…",
      appearanceHeading: "Appearance",
      themeLabel: "Theme",
      themeHint: "Pick how the Settings panel looks. Other surfaces follow the cloud dashboard.",
      themeSystem: "System",
      themeLight: "Light",
      themeDark: "Dark",
      languageLabel: "Language",
      languageHint: "Language for rud1's menus, prompts and windows.",
      languageSystem: "System",
      languageEs: "Español",
      languageEn: "English",
      notificationsHeading: "Notifications",
      notifFirstBootLabel: "First-boot devices",
      notifFirstBootHint: "Toast when a freshly-flashed rud1 appears on the LAN.",
      notifVpnLabel: "VPN events",
      notifVpnHint: "Tunnel connect / disconnect / CGNAT-warning toasts.",
      notifUsbLabel: "USB events",
      notifUsbHint: "Device attach / detach toasts after a USB/IP session change.",
      startupHeading: "Startup",
      autoStartLabel: "Launch rud1 at login",
      autoStartWin: "rud1 launches minimized into the tray on Windows sign-in.",
      autoStartMac: "rud1 starts hidden on macOS login (Login Items entry).",
      autoStartLinux: "Manages an entry in ~/.config/autostart/. Effective on next login.",
      autoStartUnsupported: "Auto-start is not available on this build.",
      autoStartStateUnavailable: "Auto-start state unavailable.",
      autoStartApiUnavailable: "Auto-start API unavailable in this build.",
      autoStartEnabled: "Auto-start enabled",
      autoStartDisabled: "Auto-start disabled",
      autoStartChangeFailed: "Could not change auto-start: {error}",
      firstBootHeading: "First-boot notifications",
      firstBootHelp: "Manage hosts the desktop app has already notified you about.",
      openInspector: "Open notified-hosts inspector…",
      statusUnavailable: "Update status unavailable.",
      currentlyInstalled: "Currently installed",
      targetVersionRow: "Target version",
      requiredIntermediate: "Required intermediate",
      reasonRow: "Reason",
      signatureUrlRow: "Signature URL",
      httpStatusRow: "HTTP status",
      expectedSha: "Expected SHA-256",
      verifyHashHelp: "Verify hash before running installer — {winCmd} on Windows or {unixCmd} on macOS / Linux.",
      copyDownloadUrl: "Copy download URL",
      copyExpectedSha: "Copy expected sha256",
      copyDiagnostics: "Copy diagnostics",
      copiedDownloadUrl: "Copied download URL to clipboard",
      copiedExpectedSha: "Copied expected sha256 to clipboard",
      copiedDiagnostics: "Copied diagnostics to clipboard",
      copyFailed: "Copy failed: {error}",
      recheckToast: "Re-checking for updates…",
      themeToast: "Theme: {theme}",
      themeSaveFailed: "Could not save theme: {error}",
      languageToast: "Language: {language}",
      languageSaveFailed: "Could not save language: {error}",
      notifSavedOn: "{key} notifications: on",
      notifSavedOff: "{key} notifications: off",
      saveFailed: "Could not save: {error}",
      openFromTray: "Open from the tray menu → First-boot notifications",
      unknownError: "unknown",
    },
    vpnDriver: {
      windowTitle: "rud1 — Install VPN driver",
      heading: "Install the VPN driver",
      badge: "One-time setup",
      intro: "rud1 needs to install the TAP-Windows V9 kernel driver so the OpenVPN client can expose a virtual network adapter to your engineering tools (TIA Portal, Codesys, OPC UA discovery, etc).",
      introMuted: "Windows will ask you to approve the install. The driver is signed by OpenVPN Inc. and bundled with rud1 — no external download is required.",
      step1Prefix: "Click ",
      step1Bold: "Install driver",
      step1Suffix: " below.",
      step2: "Approve the OS elevation prompt (User Account Control).",
      step3Prefix: "Click ",
      step3Bold: "Connect",
      step3Suffix: " on the device page in rud1.",
      filesSummary: "Files installed (signed by OpenVPN Inc.)",
      cancel: "Cancel",
      install: "Install driver",
      done: "Done",
      bridgeUnavailable: "Bridge unavailable. Please relaunch rud1 and try again.",
      waitingElevation: "Waiting for the OS elevation prompt…",
      installedOk: "Driver installed. You can close this window and click Connect.",
      installCancelled: "The driver install was cancelled or failed.",
      installFailed: "The driver install failed.",
    },
    toast: {
      regionLabel: "rud1 notifications",
      dismiss: "Dismiss",
    },
  },
};

const FALLBACK_LOCALE: Locale = "en";
const DEFAULT_LOCALE: Locale = "es";

// Starts as "en" so the vitest suite (which never calls setLocale) keeps
// seeing the English copy its byte-for-byte assertions pin. Runtime sets
// this to detectLocale() (Spanish-first) early in app whenReady.
let currentLocale: Locale = "en";

export function setLocale(l: Locale): void {
  if (l === "es" || l === "en") currentLocale = l;
}

export function getLocale(): Locale {
  return currentLocale;
}

function lookup(tree: TranslationTree, key: string): string | undefined {
  const parts = key.split(".");
  let node: string | TranslationTree | undefined = tree;
  for (const part of parts) {
    if (node == null || typeof node !== "object") return undefined;
    node = (node as TranslationTree)[part];
  }
  return typeof node === "string" ? node : undefined;
}

function interpolate(template: string, vars?: Record<string, string | number>): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (match, name: string) => {
    const v = vars[name];
    return v == null ? match : String(v);
  });
}

/**
 * Dot-path lookup into the current locale. Falls back to English, then to
 * the raw key. Never throws. `{name}` placeholders are filled from `vars`.
 */
export function t(key: string, vars?: Record<string, string | number>): string {
  const fromCurrent = lookup(translations[currentLocale], key);
  if (fromCurrent != null) return interpolate(fromCurrent, vars);
  const fromFallback = lookup(translations[FALLBACK_LOCALE], key);
  if (fromFallback != null) return interpolate(fromFallback, vars);
  return key;
}

/**
 * Resolve the locale from the persisted `language` preference. "es"/"en"
 * win outright. "system" (or unset / unknown) consults Electron's
 * `app.getLocale()` (BCP-47, e.g. "es-ES"): a value starting with "es"
 * maps to "es", anything else to "en". When `app.getLocale()` is
 * unavailable (non-Electron context, app not ready) the default is "es"
 * — the product is Spanish-first.
 */
export function detectLocale(): Locale {
  let pref: string | undefined;
  try {
    // Lazy require so this module is importable from a non-Electron
    // vitest run without pulling preferences-manager's fs side-effects
    // into every test that touches i18n.
    const { getPreferences } = require("./preferences-manager") as typeof import("./preferences-manager");
    pref = getPreferences().language;
  } catch {
    pref = undefined;
  }
  if (pref === "es" || pref === "en") return pref;

  let osLocale: string | undefined;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { app } = require("electron") as typeof import("electron");
    osLocale = app?.getLocale?.();
  } catch {
    osLocale = undefined;
  }
  if (typeof osLocale === "string" && osLocale.length > 0) {
    return osLocale.toLowerCase().startsWith("es") ? "es" : "en";
  }
  return DEFAULT_LOCALE;
}
