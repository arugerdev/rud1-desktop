// Renderer carga via data: URL en sandboxed BrowserWindow; CSP default-src 'none'.
import { t, type Locale } from "./i18n";
import type { LanguagePreference } from "./preferences-manager";

export function buildSettingsWindowHtml(
  currentVersion: string,
  currentTheme: "system" | "light" | "dark" = "system",
  currentLanguage: LanguagePreference = "system",
  locale: Locale = "en",
): string {
  // CSP mirrors the dedupe inspector — deny everything by default,
  // allow inline scripts/styles only (the bridge runs in the isolated
  // preload context unaffected by document CSP). No connect-src — the
  // renderer talks only via IPC.
  // Iter 44 — `currentVersion` is JSON-encoded into the inline script
  // as a constant so the `error`-verdict diagnostics envelope carries
  // the running app's version (the error state shape doesn't carry it,
  // so the renderer can't read it off `state`). Mirrors the iter-43
  // helper contract in version-check-manager.ts byte-for-byte.
  const currentVersionLiteral = JSON.stringify(currentVersion);
  // Initial theme attribute — "system" omits the attribute so the OS
  // `prefers-color-scheme` query drives the theme. "light"/"dark" pin
  // the rendered theme regardless of OS appearance.
  const themeAttr =
    currentTheme === "light" || currentTheme === "dark"
      ? ` data-theme="${currentTheme}"`
      : "";
  const initialThemeLiteral = JSON.stringify(currentTheme);
  const initialLanguageLiteral = JSON.stringify(currentLanguage);
  // Localized strings consumed by the inline renderer JS. `t()` reads the
  // module-level locale, which the runtime sets to `locale` before calling
  // this builder (and which defaults to "en" in the vitest suite — keeping
  // the byte-for-byte HTML pins green). JSON-encoded so accents survive
  // the data: URL round-trip.
  const L = JSON.stringify({
    statusUnavailable: t("settings.statusUnavailable"),
    currentlyInstalled: t("settings.currentlyInstalled"),
    targetVersion: t("settings.targetVersionRow"),
    requiredIntermediate: t("settings.requiredIntermediate"),
    reason: t("settings.reasonRow"),
    signatureUrl: t("settings.signatureUrlRow"),
    httpStatus: t("settings.httpStatusRow"),
    expectedSha: t("settings.expectedSha"),
    verifyHashHelp: t("settings.verifyHashHelp", {
      winCmd: "<code>Get-FileHash -Algorithm SHA256 &lt;file&gt;</code>",
      unixCmd: "<code>shasum -a 256 &lt;file&gt;</code>",
    }),
    copyDownloadUrl: t("settings.copyDownloadUrl"),
    copyExpectedSha: t("settings.copyExpectedSha"),
    copyDiagnostics: t("settings.copyDiagnostics"),
    copiedDownloadUrl: t("settings.copiedDownloadUrl"),
    copiedExpectedSha: t("settings.copiedExpectedSha"),
    copiedDiagnostics: t("settings.copiedDiagnostics"),
    copyFailedPrefix: t("settings.copyFailed", { error: "" }),
    recheckToast: t("settings.recheckToast"),
    checkNow: t("updates.checkNow"),
    whatsNew: t("updates.whatsNew"),
    bannerDownloadManual: t("updates.bannerDownloadManual", { version: "{version}" }),
    blockedSignature: t("updates.blockedSignature", { reason: "{reason}" }),
    summaryIdle: t("updates.summaryIdle"),
    summaryChecking: t("updates.summaryChecking"),
    summaryUpToDate: t("updates.summaryUpToDate", { current: "{current}" }),
    summaryAvailable: t("updates.summaryAvailable", { latest: "{latest}", current: "{current}" }),
    summaryError: t("updates.summaryError", { message: "{message}" }),
    autoStartWin: t("settings.autoStartWin"),
    autoStartMac: t("settings.autoStartMac"),
    autoStartLinux: t("settings.autoStartLinux"),
    autoStartUnsupported: t("settings.autoStartUnsupported"),
    autoStartStateUnavailable: t("settings.autoStartStateUnavailable"),
    autoStartApiUnavailable: t("settings.autoStartApiUnavailable"),
    autoStartEnabled: t("settings.autoStartEnabled"),
    autoStartDisabled: t("settings.autoStartDisabled"),
    autoStartChangeFailedPrefix: t("settings.autoStartChangeFailed", { error: "" }),
    themeToastPrefix: t("settings.themeToast", { theme: "" }),
    themeSaveFailedPrefix: t("settings.themeSaveFailed", { error: "" }),
    languageToastPrefix: t("settings.languageToast", { language: "" }),
    languageSaveFailedPrefix: t("settings.languageSaveFailed", { error: "" }),
    notifSavedOn: t("settings.notifSavedOn", { key: "{key}" }),
    notifSavedOff: t("settings.notifSavedOff", { key: "{key}" }),
    saveFailedPrefix: t("settings.saveFailed", { error: "" }),
    openFromTray: t("settings.openFromTray"),
    unknownError: t("settings.unknownError"),
    autoUpdateLabel: t("settings.autoUpdateLabel"),
    autoUpdateHint: t("settings.autoUpdateHint"),
    autoUpdateOn: t("settings.autoUpdateOn"),
    autoUpdateOff: t("settings.autoUpdateOff"),
    updateNow: t("settings.updateNow"),
  });
  const html = `<!doctype html>
<html lang="${locale}"${themeAttr}>
<head>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none';" />
<title>${t("settings.windowTitle")}</title>
<style>
  /*
   * rud1 Liquid Glass — Settings panel.
   * Light + dark themes driven by prefers-color-scheme so the panel
   * follows the OS appearance without needing a toggle (the window
   * is a small modal opened from the tray; no chrome to host one).
   * Pastel palette mirrors rud1-es / rud1-app for cross-surface parity.
   */
  :root {
    color-scheme: light dark;

    --bg: #f4f6fa;
    --fg: #1a2030;
    --muted-fg: #6b7588;
    --surface: rgba(255, 255, 255, 0.62);
    --surface-strong: rgba(255, 255, 255, 0.82);
    --edge: rgba(255, 255, 255, 0.85);
    --border: rgba(180, 195, 220, 0.55);
    --shadow: rgba(60, 80, 120, 0.18);

    /* Primary pinned to the rud1.es design-system pastel-blue
     * (#A8C4FF) with the accent (#86A8FF) reserved for hover /
     * pressed states. Matches rud1-es + rud1-app for cross-surface
     * brand parity — keep this in sync when the cloud palette
     * evolves. */
    --primary: #a8c4ff;
    --primary-accent: #86a8ff;
    --primary-soft: #e0eaff;
    --primary-fg: #122a55;

    --success-bg: #c8efd9;
    --success-border: #8fd6b0;
    --success-fg: #0e3f25;

    --warning-bg: #fde6c2;
    --warning-border: #f5b962;
    --warning-fg: #4a2d0a;

    --danger-bg: #fbd5d0;
    --danger-border: #f1908a;
    --danger-fg: #5a1a17;

    --hash-fg: #b87a16;
    --link: #5a87e8;
    --link-hover: #3d6cd0;

    /* Mesh tints — light. Pastel-blue dominates so the panel reads
     * as a coherent extension of the rud1.es marketing surface. */
    --mesh-1: rgba(168, 196, 255, 0.55);
    --mesh-2: rgba(208, 195, 255, 0.5);
    --mesh-3: rgba(196, 240, 224, 0.45);
    --mesh-4: rgba(255, 226, 197, 0.45);
  }

  /*
   * Dark theme — applied when EITHER:
   *   - the OS is in dark mode AND the user hasn't pinned light
   *     (prefers-color-scheme: dark + :root:not([data-theme="light"]))
   *   - the user pinned the dark override (:root[data-theme="dark"])
   * The vars duplicate by selector because CSS can't combine an at-rule
   * with a regular selector in one block. The light vars on :root
   * above stay the default for "system" + "light" + an OS in light mode.
   */
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #0a0e17;
      --fg: #e6eaf2;
      --muted-fg: #93a0b8;
      --surface: rgba(28, 36, 50, 0.55);
      --surface-strong: rgba(28, 36, 50, 0.78);
      --edge: rgba(180, 200, 230, 0.12);
      --border: rgba(120, 140, 175, 0.22);
      --shadow: rgba(0, 0, 0, 0.55);

      --primary: #a8c4ff;
      --primary-accent: #86a8ff;
      --primary-soft: rgba(168, 196, 255, 0.28);
      --primary-fg: #0e1a2a;

      --success-bg: rgba(143, 214, 176, 0.22);
      --success-border: rgba(143, 214, 176, 0.45);
      --success-fg: #b9ecd0;

      --warning-bg: rgba(245, 185, 98, 0.22);
      --warning-border: rgba(245, 185, 98, 0.45);
      --warning-fg: #f4d59c;

      --danger-bg: rgba(241, 144, 138, 0.22);
      --danger-border: rgba(241, 144, 138, 0.45);
      --danger-fg: #f3bcb7;

      --hash-fg: #f4d59c;
      --link: #a8c4ff;
      --link-hover: #c8e2ff;

      /* Mesh tints — dark */
      --mesh-1: rgba(40, 80, 130, 0.4);
      --mesh-2: rgba(80, 60, 130, 0.36);
      --mesh-3: rgba(40, 110, 95, 0.32);
      --mesh-4: rgba(130, 80, 50, 0.32);
    }
  }
  :root[data-theme="dark"] {
    --bg: #0a0e17;
    --fg: #e6eaf2;
    --muted-fg: #93a0b8;
    --surface: rgba(28, 36, 50, 0.55);
    --surface-strong: rgba(28, 36, 50, 0.78);
    --edge: rgba(180, 200, 230, 0.12);
    --border: rgba(120, 140, 175, 0.22);
    --shadow: rgba(0, 0, 0, 0.55);

    --primary: #a8c4ff;
    --primary-accent: #86a8ff;
    --primary-soft: rgba(168, 196, 255, 0.28);
    --primary-fg: #0e1a2a;

    --success-bg: rgba(143, 214, 176, 0.22);
    --success-border: rgba(143, 214, 176, 0.45);
    --success-fg: #b9ecd0;

    --warning-bg: rgba(245, 185, 98, 0.22);
    --warning-border: rgba(245, 185, 98, 0.45);
    --warning-fg: #f4d59c;

    --danger-bg: rgba(241, 144, 138, 0.22);
    --danger-border: rgba(241, 144, 138, 0.45);
    --danger-fg: #f3bcb7;

    --hash-fg: #f4d59c;
    --link: #a8c4ff;
    --link-hover: #c8e2ff;

    --mesh-1: rgba(40, 80, 130, 0.4);
    --mesh-2: rgba(80, 60, 130, 0.36);
    --mesh-3: rgba(40, 110, 95, 0.32);
    --mesh-4: rgba(130, 80, 50, 0.32);
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
    padding: 24px;
    font-size: 13px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
  }
  h1 { font-size: 17px; font-weight: 600; margin: 0 0 6px 0; letter-spacing: -0.01em; }
  h2 { font-size: 11px; font-weight: 600; margin: 26px 0 10px 0; color: var(--muted-fg); text-transform: uppercase; letter-spacing: 0.08em; }
  p { margin: 0 0 8px 0; }
  .muted { color: var(--muted-fg); font-size: 12px; }
  .banner {
    background: var(--danger-bg);
    color: var(--danger-fg);
    padding: 12px 14px;
    border-radius: 14px;
    border: 1px solid var(--danger-border);
    margin: 0 0 14px 0;
    font-weight: 500;
    backdrop-filter: blur(14px) saturate(160%);
    -webkit-backdrop-filter: blur(14px) saturate(160%);
  }
  .banner.warn { background: var(--warning-bg); color: var(--warning-fg); border-color: var(--warning-border); }
  .banner.ok { background: var(--success-bg); color: var(--success-fg); border-color: var(--success-border); }
  .summary {
    padding: 12px 14px;
    margin: 0 0 12px 0;
    border-radius: 14px;
    border: 1px solid var(--border);
    background: var(--surface);
    backdrop-filter: blur(20px) saturate(170%);
    -webkit-backdrop-filter: blur(20px) saturate(170%);
    box-shadow: 0 4px 18px var(--shadow);
  }
  .row { display: flex; justify-content: space-between; gap: 12px; padding: 4px 0; }
  .row .k { color: var(--muted-fg); }
  .row .v { font-family: ui-monospace, "SF Mono", Consolas, monospace; text-align: right; word-break: break-all; }
  .chip {
    display: inline-block;
    background: var(--primary-soft);
    color: var(--primary-fg);
    border: 1px solid var(--border);
    border-radius: 9999px;
    padding: 3px 10px;
    font-size: 11px;
    font-family: ui-monospace, "SF Mono", Consolas, monospace;
    margin: 8px 0 0 0;
  }
  @media (prefers-color-scheme: dark) {
    .chip { color: var(--primary); }
  }
  button {
    background: var(--surface);
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 7px 14px;
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    font-family: inherit;
    backdrop-filter: blur(14px) saturate(160%);
    -webkit-backdrop-filter: blur(14px) saturate(160%);
    transition: background 0.15s ease, transform 0.1s ease;
  }
  button:hover { background: var(--surface-strong); }
  button:active { transform: scale(0.98); }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  button.primary {
    background: var(--primary);
    border-color: var(--primary);
    color: var(--primary-fg);
    font-weight: 600;
    box-shadow: 0 4px 16px rgba(109, 179, 245, 0.35);
  }
  button.primary:hover { filter: brightness(1.05); }
  .actions { display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap; }
  a { color: var(--link); cursor: pointer; text-decoration: none; border-bottom: 1px dashed currentColor; padding-bottom: 1px; }
  a:hover { color: var(--link-hover); }
  .toast {
    position: fixed;
    bottom: 16px;
    right: 16px;
    background: var(--primary);
    color: var(--primary-fg);
    padding: 10px 14px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 500;
    opacity: 0;
    transition: opacity 0.25s ease;
    pointer-events: none;
    box-shadow: 0 8px 28px rgba(109, 179, 245, 0.35);
  }
  .toast.show { opacity: 1; }
  code {
    font-family: ui-monospace, "SF Mono", Consolas, monospace;
    background: var(--primary-soft);
    color: var(--primary-fg);
    padding: 2px 6px;
    border-radius: 6px;
    font-size: 12px;
  }
  @media (prefers-color-scheme: dark) {
    code { color: var(--primary); }
  }
  code.hash { word-break: break-all; font-size: 11px; color: var(--hash-fg); background: transparent; padding: 0; }
  .hash-help { margin: 8px 0 4px 0; }

  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 999px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--muted-fg); }

  /* Theme picker — pastel segmented control (Liquid Glass). */
  .theme-picker {
    display: inline-flex;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 3px;
    gap: 2px;
    backdrop-filter: blur(14px) saturate(160%);
    -webkit-backdrop-filter: blur(14px) saturate(160%);
  }
  .theme-picker label {
    cursor: pointer;
    padding: 6px 12px;
    border-radius: 9px;
    font-size: 12px;
    font-weight: 500;
    color: var(--muted-fg);
    transition: background 0.15s ease, color 0.15s ease;
  }
  .theme-picker input { display: none; }
  .theme-picker label:hover { color: var(--fg); }
  /* Language picker hosts 12 options — let it wrap instead of overflowing
     the narrow Settings modal. */
  .lang-picker { flex-wrap: wrap; justify-content: flex-end; max-width: 60%; }
  .theme-picker input:checked + span {
    color: var(--primary-fg);
  }
  .theme-picker label:has(input:checked) {
    background: var(--primary);
    color: var(--primary-fg);
    box-shadow: 0 2px 8px rgba(109, 179, 245, 0.28);
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) .theme-picker label:has(input:checked) {
      color: var(--primary-fg);
    }
  }
  :root[data-theme="dark"] .theme-picker label:has(input:checked) {
    color: var(--primary-fg);
  }

  /* Pastel-pill toggle (iOS-style) used by the Auto-start preference. */
  .pref-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 12px 14px;
    margin: 0 0 12px 0;
    border-radius: 14px;
    border: 1px solid var(--border);
    background: var(--surface);
    backdrop-filter: blur(20px) saturate(170%);
    -webkit-backdrop-filter: blur(20px) saturate(170%);
    box-shadow: 0 4px 18px var(--shadow);
  }
  .pref-row .pref-text { flex: 1; min-width: 0; }
  .pref-row .pref-text .label { font-weight: 500; color: var(--fg); }
  .pref-row .pref-text .hint {
    font-size: 12px;
    color: var(--muted-fg);
    margin-top: 2px;
    line-height: 1.4;
  }
  .toggle {
    position: relative;
    display: inline-block;
    width: 42px;
    height: 24px;
    flex-shrink: 0;
  }
  .toggle input {
    opacity: 0;
    width: 0;
    height: 0;
    margin: 0;
  }
  .toggle .slider {
    position: absolute;
    inset: 0;
    background: var(--border);
    border-radius: 999px;
    cursor: pointer;
    transition: background 0.15s ease;
  }
  .toggle .slider::before {
    content: "";
    position: absolute;
    height: 18px;
    width: 18px;
    left: 3px;
    top: 3px;
    background: #ffffff;
    border-radius: 999px;
    transition: transform 0.15s ease;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.18);
  }
  .toggle input:checked + .slider { background: var(--primary); }
  .toggle input:checked + .slider::before { transform: translateX(18px); }
  .toggle input:disabled + .slider { opacity: 0.5; cursor: not-allowed; }
  .toggle input:focus-visible + .slider {
    outline: 2px solid var(--primary);
    outline-offset: 2px;
  }
</style>
</head>
<body>
  <h1>${t("settings.heading")}</h1>
  <p class="muted">${t("settings.subtitle")}</p>

  <h2>${t("settings.updatesHeading")}</h2>
  <div id="updates"><p class="muted">${t("settings.loading")}</p></div>
  <div class="pref-row">
    <div class="pref-text">
      <div class="label">${t("settings.autoUpdateLabel")}</div>
      <div class="hint">${t("settings.autoUpdateHint")}</div>
    </div>
    <label class="toggle" aria-label="${t("settings.autoUpdateLabel")}">
      <input type="checkbox" id="auto-update-toggle" />
      <span class="slider"></span>
    </label>
  </div>

  <h2>${t("settings.appearanceHeading")}</h2>
  <div class="pref-row">
    <div class="pref-text">
      <div class="label">${t("settings.themeLabel")}</div>
      <div class="hint">${t("settings.themeHint")}</div>
    </div>
    <div class="theme-picker" role="radiogroup" aria-label="${t("settings.themeLabel")}">
      <label><input type="radio" name="theme-pick" value="system" /><span>${t("settings.themeSystem")}</span></label>
      <label><input type="radio" name="theme-pick" value="light" /><span>${t("settings.themeLight")}</span></label>
      <label><input type="radio" name="theme-pick" value="dark" /><span>${t("settings.themeDark")}</span></label>
    </div>
  </div>
  <div class="pref-row">
    <div class="pref-text">
      <div class="label">${t("settings.languageLabel")}</div>
      <div class="hint">${t("settings.languageHint")}</div>
    </div>
    <div class="theme-picker lang-picker" role="radiogroup" aria-label="${t("settings.languageLabel")}">
      <label><input type="radio" name="lang-pick" value="system" /><span>${t("settings.languageSystem")}</span></label>
      <label><input type="radio" name="lang-pick" value="es" /><span>Español</span></label>
      <label><input type="radio" name="lang-pick" value="en" /><span>English</span></label>
      <label><input type="radio" name="lang-pick" value="fr" /><span>Français</span></label>
      <label><input type="radio" name="lang-pick" value="it" /><span>Italiano</span></label>
      <label><input type="radio" name="lang-pick" value="de" /><span>Deutsch</span></label>
      <label><input type="radio" name="lang-pick" value="ptBR" /><span>Português (BR)</span></label>
      <label><input type="radio" name="lang-pick" value="zh" /><span>简体中文</span></label>
      <label><input type="radio" name="lang-pick" value="ja" /><span>日本語</span></label>
      <label><input type="radio" name="lang-pick" value="ko" /><span>한국어</span></label>
      <label><input type="radio" name="lang-pick" value="ru" /><span>Русский</span></label>
      <label><input type="radio" name="lang-pick" value="ar" /><span>العربية</span></label>
    </div>
  </div>

  <h2>${t("settings.notificationsHeading")}</h2>
  <div class="pref-row">
    <div class="pref-text">
      <div class="label">${t("settings.notifFirstBootLabel")}</div>
      <div class="hint">${t("settings.notifFirstBootHint")}</div>
    </div>
    <label class="toggle" aria-label="${t("settings.notifFirstBootLabel")}">
      <input type="checkbox" id="notif-firstBoot" />
      <span class="slider"></span>
    </label>
  </div>
  <div class="pref-row">
    <div class="pref-text">
      <div class="label">${t("settings.notifVpnLabel")}</div>
      <div class="hint">${t("settings.notifVpnHint")}</div>
    </div>
    <label class="toggle" aria-label="${t("settings.notifVpnLabel")}">
      <input type="checkbox" id="notif-vpn" />
      <span class="slider"></span>
    </label>
  </div>
  <div class="pref-row">
    <div class="pref-text">
      <div class="label">${t("settings.notifUsbLabel")}</div>
      <div class="hint">${t("settings.notifUsbHint")}</div>
    </div>
    <label class="toggle" aria-label="${t("settings.notifUsbLabel")}">
      <input type="checkbox" id="notif-usb" />
      <span class="slider"></span>
    </label>
  </div>

  <h2>${t("settings.startupHeading")}</h2>
  <div id="auto-start" class="pref-row">
    <div class="pref-text">
      <div class="label">${t("settings.autoStartLabel")}</div>
      <div class="hint" id="auto-start-hint">${t("settings.loading")}</div>
    </div>
    <label class="toggle" aria-label="${t("settings.autoStartLabel")}">
      <input type="checkbox" id="auto-start-toggle" disabled />
      <span class="slider"></span>
    </label>
  </div>

  <h2>${t("settings.firstBootHeading")}</h2>
  <p class="muted">${t("settings.firstBootHelp")}</p>
  <div class="actions">
    <button id="open-dedupe">${t("settings.openInspector")}</button>
  </div>

  <div id="toast" class="toast" aria-live="polite"></div>
  <div id="diag" class="muted" style="margin-top:18px;font-size:11px;color:var(--danger-fg);"></div>

<script>
  // Safety net: any uncaught error in this inline script (which tsc does NOT
  // type-check — it's a string template) would otherwise silently strand the
  // panel. Surface it in the diag line instead of leaving controls dead.
  window.addEventListener('error', function(ev) {
    var d = document.getElementById('diag');
    if (d) d.textContent = 'Error en el panel: ' + ((ev && ev.message) ? ev.message : 'desconocido');
  });
  function setDiag(msg) {
    var d = document.getElementById('diag');
    if (d) d.textContent = msg || '';
  }
  // Settings/About panel renderer. Talks to main exclusively through
  // window.electronAPI.{versionCheck,clipboard,shell} which are wired up
  // in preload/index.ts (iter 37).
  // Iter 44 — APP_VERSION is the value of app.getVersion() at the time
  // the panel was opened, JSON-encoded by the main process at HTML build
  // time. Used by the "Copy diagnostics" rebuild for the error verdict
  // (the error state union does not carry current, so the renderer
  // cannot read it off state). Mirrors buildErrorDiagnosticsBlob in
  // version-check-manager.ts byte-for-byte.
  var APP_VERSION = ${currentVersionLiteral};
  var L = ${L};
  var INITIAL_LANGUAGE = ${initialLanguageLiteral};
  function fmt(template, vars) {
    return String(template).replace(/\\{(\\w+)\\}/g, function (m, k) {
      return Object.prototype.hasOwnProperty.call(vars, k) ? String(vars[k]) : m;
    });
  }
  var updatesEl = document.getElementById('updates');
  var toastEl = document.getElementById('toast');
  var toastTimer = null;
  function escape(s) {
    return String(s).replace(/[&<>"']/g, function(c) {
      return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c];
    });
  }
  function toast(msg) {
    toastEl.textContent = msg;
    toastEl.classList.add('show');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function() {
      toastEl.classList.remove('show');
    }, 2200);
  }

  function renderBlocked(state) {
    // Mirrors formatBlockedStateMessage + formatBlockedHashHint in
    // version-check-manager.ts. Kept inline so the renderer is
    // self-contained inside the data URL — the formatters' contracts
    // are what's tested in the main-process suite; this script only
    // handles the DOM mapping.
    var banner = fmt(L.bannerDownloadManual, { version: escape(state.requiredMinVersion) });
    var notes = state.releaseNotesUrl
      ? '<p><a id="rn-link">' + escape(L.whatsNew) + '</a></p>'
      : '';
    // Iter 41 — surface the optional bridgeSha256 hex inline so the
    // operator can verify the artifact integrity after manual download.
    // Defensive: re-run the SHA-256 shape gate (mirrors formatBlockedHashHint
    // in version-check-manager.ts) so a state object that bypassed
    // parse-time validation cannot leak a malformed hex into the panel.
    var rawHash = state.bridgeSha256;
    var hashHex = (typeof rawHash === 'string' && /^[0-9a-f]{64}$/i.test(rawHash))
      ? rawHash.toLowerCase()
      : null;
    var hashRow = hashHex
      ? '<div class="row"><span class="k">' + escape(L.expectedSha) + '</span>' +
          '<span class="v"><code class="hash" id="bridge-hash">' + escape(hashHex) + '</code></span>' +
        '</div>'
      : '';
    var hashHelp = hashHex
      ? '<p class="muted hash-help" id="bridge-hash-help">' + L.verifyHashHelp + '</p>'
      : '';
    var hashBtn = hashHex
      ? '<button id="copy-hash" aria-describedby="bridge-hash-help">' + escape(L.copyExpectedSha) + '</button>'
      : '';
    updatesEl.innerHTML =
      '<div class="banner">' + banner + '</div>' +
      '<div class="summary">' +
        '<div class="row"><span class="k">' + escape(L.currentlyInstalled) + '</span><span class="v">v' + escape(state.currentVersion) + '</span></div>' +
        '<div class="row"><span class="k">' + escape(L.targetVersion) + '</span><span class="v">v' + escape(state.targetVersion) + '</span></div>' +
        '<div class="row"><span class="k">' + escape(L.requiredIntermediate) + '</span><span class="v">v' + escape(state.requiredMinVersion) + '</span></div>' +
        hashRow +
      '</div>' +
      hashHelp +
      notes +
      '<div class="actions">' +
        '<button id="copy-url" class="primary"' + (hashHex ? ' aria-describedby="bridge-hash-help"' : '') + '>' + escape(L.copyDownloadUrl) + '</button>' +
        hashBtn +
        // Iter 42 — copy a JSON diagnostics envelope (capturedAt + all
        // blocked-state fields + resolved download URL via pickDownloadUrl
        // precedence) for support tickets. Mirrors the rud1-app iter-42
        // pattern on the AuditForwardStatusCard. Always rendered: the
        // envelope is always meaningful (versions are guaranteed
        // populated by parseManifest) regardless of optional fields.
        '<button id="copy-diagnostics">' + escape(L.copyDiagnostics) + '</button>' +
        '<button id="recheck">' + escape(L.checkNow) + '</button>' +
      '</div>';

    document.getElementById('copy-url').addEventListener('click', function() {
      // Precedence (iter 39):
      //   1. bridgeDownloadUrls[requiredMinVersion] (keyed map, iter 39)
      //   2. bridgeDownloadUrl                       (scalar fallback, iter 38)
      //   3. releaseNotesUrl                         (iter 33 / iter 37 fallback)
      //   4. synthesized URL
      // Each candidate URL is re-validated through the same allowlist
      // used at parse time so an upstream regression cannot leak an
      // unsafe scheme to clipboard via the panel.
      function isAllowed(u) {
        if (typeof u !== 'string' || u.length === 0 || u.length > 2048) return false;
        if (/[\\x00-\\x1f\\x7f\\s"<>\\\\^\`{|}]/.test(u)) return false;
        try {
          var parsed = new URL(u);
          return parsed.protocol === 'https:' && parsed.username === '' && parsed.password === '';
        } catch (e) { return false; }
      }
      var keyed = null;
      var map = state.bridgeDownloadUrls;
      var minV = state.requiredMinVersion;
      if (map && typeof map === 'object' && typeof minV === 'string' && minV.length > 0 &&
          Object.prototype.hasOwnProperty.call(map, minV) && isAllowed(map[minV])) {
        keyed = map[minV];
      }
      var scalar = state.bridgeDownloadUrl;
      var url;
      if (keyed) {
        url = keyed;
      } else if (scalar && isAllowed(scalar)) {
        url = scalar;
      } else if (state.releaseNotesUrl) {
        url = state.releaseNotesUrl;
      } else {
        url = 'https://rud1.es/desktop/download?version=' + encodeURIComponent(minV);
      }
      // Iter 41 — when the manifest carries a bridgeSha256, append the
      // hex as a verification hint after two spaces. The operator can
      // copy-paste a single line that includes both the URL and the
      // expected hash (formatted "URL  (sha256: <hex>)") and verify with
      // Get-FileHash / shasum -a 256 after download. Pure additive: when
      // no hash is present, the iter-39 plain-URL behaviour is preserved
      // byte-for-byte.
      var clip = hashHex ? (url + '  (sha256: ' + hashHex + ')') : url;
      window.electronAPI.clipboard.writeText(clip).then(function(res) {
        if (res && res.ok) toast(L.copiedDownloadUrl);
        else toast(L.copyFailedPrefix + (res && res.error ? res.error : L.unknownError));
      });
    });
    if (hashHex) {
      document.getElementById('copy-hash').addEventListener('click', function() {
        window.electronAPI.clipboard.writeText(hashHex).then(function(res) {
          if (res && res.ok) toast(L.copiedExpectedSha);
          else toast(L.copyFailedPrefix + (res && res.error ? res.error : L.unknownError));
        });
      });
    }
    // Iter 42 — copy diagnostics JSON envelope. Mirrors the
    // buildBlockedDiagnosticsBlob contract pinned by the main-process
    // suite (version-check-manager.test.ts). We rebuild the envelope
    // inline rather than IPC-fetching it because the panel already has
    // the full blocked-state object in scope and an extra IPC roundtrip
    // would only add latency. Key order matches the helper byte-for-byte
    // — a regression here surfaces as the iter-42 "key ordering" test
    // failing in the main-process suite (the helper is what's tested).
    document.getElementById('copy-diagnostics').addEventListener('click', function() {
      function isAllowed2(u) {
        if (typeof u !== 'string' || u.length === 0 || u.length > 2048) return false;
        if (/[\\x00-\\x1f\\x7f\\s"<>\\\\^\`{|}]/.test(u)) return false;
        try {
          var p = new URL(u);
          return p.protocol === 'https:' && p.username === '' && p.password === '';
        } catch (e) { return false; }
      }
      var keyed2 = null;
      var map2 = state.bridgeDownloadUrls;
      var minV2 = state.requiredMinVersion;
      if (map2 && typeof map2 === 'object' && typeof minV2 === 'string' && minV2.length > 0 &&
          Object.prototype.hasOwnProperty.call(map2, minV2) && isAllowed2(map2[minV2])) {
        keyed2 = map2[minV2];
      }
      var url2;
      if (keyed2) url2 = keyed2;
      else if (state.bridgeDownloadUrl && isAllowed2(state.bridgeDownloadUrl)) url2 = state.bridgeDownloadUrl;
      else if (state.releaseNotesUrl) url2 = state.releaseNotesUrl;
      else url2 = 'https://rud1.es/desktop/download?version=' + encodeURIComponent(minV2);
      // Iter 45 — currentVersion sourced from APP_VERSION (threaded
      // through from app.getVersion() at HTML build time) when
      // available, falling back to state.currentVersion for parity
      // with the helper's legacy behaviour. Same rationale as the
      // iter-44 error-verdict thread: the stored state value is what
      // the version-check stored at fetch time, which under iter-30+
      // bridge-only update paths can drift from the running app's
      // actual version. The defensive fallback keeps the iter-42
      // key-ordering pin holding byte-for-byte even when APP_VERSION
      // is somehow null/empty (shouldn't happen in production but
      // protects against a bad HTML rebuild).
      var currentVersion2 = (typeof APP_VERSION === 'string' && APP_VERSION.length > 0)
        ? APP_VERSION
        : state.currentVersion;
      // Iter 47 — defensively re-validate state.signatureUrl mirroring
      // validateSignatureUrl in version-check-manager.ts. Only append
      // when the URL passes the same allow-list (http(s)://, ends in
      // .sig/.minisig/.asc, length-capped, no js:/data:). When absent
      // / rejected the field is OMITTED from the envelope so the
      // iter-42 byte-for-byte key-ordering pin holds for v2-passthrough
      // operators (no new key appears in the JSON).
      function isSigUrlAllowed(u) {
        if (typeof u !== 'string' || u.length === 0 || u.length > 2048) return false;
        if (/[\\x00-\\x1f\\x7f\\s"<>\\\\^\`{|}]/.test(u)) return false;
        try {
          var p = new URL(u);
          var pr = (p.protocol || '').toLowerCase();
          if (pr === 'javascript:' || pr === 'data:') return false;
          if (pr !== 'http:' && pr !== 'https:') return false;
          if (p.username !== '' || p.password !== '') return false;
          return /\\.(sig|minisig|asc)$/i.test(p.pathname);
        } catch (e) { return false; }
      }
      var sigUrl2 = isSigUrlAllowed(state.signatureUrl) ? state.signatureUrl : null;
      var envelope = {
        capturedAt: new Date().toISOString(),
        kind: 'update-blocked-by-min-bootstrap',
        currentVersion: currentVersion2,
        targetVersion: state.targetVersion,
        requiredMinVersion: state.requiredMinVersion,
        downloadUrl: url2,
        bridgeSha256: hashHex || null,
        releaseNotesUrl: state.releaseNotesUrl || null,
        manifestVersion: state.manifestVersion != null ? state.manifestVersion : null,
      };
      if (sigUrl2 != null) {
        envelope.signatureUrl = sigUrl2;
      }
      var blob = JSON.stringify(envelope, null, 2);
      window.electronAPI.clipboard.writeText(blob).then(function(res) {
        if (res && res.ok) toast(L.copiedDiagnostics);
        else toast(L.copyFailedPrefix + (res && res.error ? res.error : L.unknownError));
      });
    });
    document.getElementById('recheck').addEventListener('click', function() {
      window.electronAPI.versionCheck.recheck();
      toast(L.recheckToast);
    });
    if (state.releaseNotesUrl) {
      document.getElementById('rn-link').addEventListener('click', function() {
        window.electronAPI.shell.openExternal(state.releaseNotesUrl);
      });
    }
  }

  function renderBlockedBySignatureFetch(state) {
    // Iter 48 — sig-strict gate fired. Mirrors renderBlocked's overall
    // shape (banner + summary rows + actions) but the operator-facing
    // copy is pinned to the iter-48 reason vocabulary. The "Copy
    // diagnostics" button's envelope key ordering MUST match
    // buildBlockedBySignatureFetchDiagnosticsBlob in
    // version-check-manager.ts byte-for-byte — the iter-48 helper test
    // is the ground truth.
    var reason = String(state.reason || '');
    var banner = fmt(L.blockedSignature, { reason: escape(reason) });
    var sigRow = state.signatureUrl
      ? '<div class="row"><span class="k">' + escape(L.signatureUrl) + '</span>' +
          '<span class="v"><code>' + escape(state.signatureUrl) + '</code></span></div>'
      : '';
    var statusRow = (typeof state.httpStatus === 'number')
      ? '<div class="row"><span class="k">' + escape(L.httpStatus) + '</span><span class="v">' + escape(state.httpStatus) + '</span></div>'
      : '';
    // Iter 54 — small chip surfacing the iter-53 signedDataMode label.
    // Mirrors formatVerifyModeChip in version-check-manager.ts:
    //   "manifest-bytes"      → "verify mode: manifest-body" (prose)
    //   "manifest-sha256-hex" → "verify mode: manifest-sha256-hex"
    //   anything else literal → forwarded verbatim (forward-compat)
    //   missing/null/empty    → chip omitted (defensive — legacy iter
    //                          ≤52 verdicts pre-date the field; we
    //                          don't fabricate a default in the
    //                          renderer, the iter-53 gate-side default
    //                          fallback is what populates fresh
    //                          verdicts).
    var rawMode = state.signedDataMode;
    var chipText = null;
    if (typeof rawMode === 'string' && rawMode.length > 0) {
      if (rawMode === 'manifest-bytes') {
        chipText = 'verify mode: manifest-body';
      } else {
        chipText = 'verify mode: ' + rawMode;
      }
    }
    var chipRow = chipText
      ? '<div class="chip" id="verify-mode-chip">' + escape(chipText) + '</div>'
      : '';
    var notes = state.releaseNotesUrl
      ? '<p><a id="rn-link">' + escape(L.whatsNew) + '</a></p>'
      : '';
    updatesEl.innerHTML =
      '<div class="banner">' + banner + '</div>' +
      '<div class="summary">' +
        '<div class="row"><span class="k">' + escape(L.currentlyInstalled) + '</span><span class="v">v' + escape(state.currentVersion) + '</span></div>' +
        '<div class="row"><span class="k">' + escape(L.targetVersion) + '</span><span class="v">v' + escape(state.targetVersion) + '</span></div>' +
        '<div class="row"><span class="k">' + escape(L.reason) + '</span><span class="v">' + escape(reason) + '</span></div>' +
        sigRow +
        statusRow +
        chipRow +
      '</div>' +
      notes +
      '<div class="actions">' +
        '<button id="copy-diagnostics">' + escape(L.copyDiagnostics) + '</button>' +
        '<button id="recheck">' + escape(L.checkNow) + '</button>' +
      '</div>';

    document.getElementById('copy-diagnostics').addEventListener('click', function() {
      // Mirrors buildBlockedBySignatureFetchDiagnosticsBlob in
      // version-check-manager.ts byte-for-byte. Key order:
      //   capturedAt → kind → currentVersion → targetVersion → reason
      //   → signatureUrl → httpStatus? → downloadUrl → releaseNotesUrl
      //   → manifestVersion
      // httpStatus is OMITTED (not null) when not present — the iter-48
      // helper test pins the byte shape.
      function isSigUrlAllowed(u) {
        if (typeof u !== 'string' || u.length === 0 || u.length > 2048) return false;
        if (/[\\x00-\\x1f\\x7f\\s"<>\\\\^\`{|}]/.test(u)) return false;
        try {
          var p = new URL(u);
          var pr = (p.protocol || '').toLowerCase();
          if (pr === 'javascript:' || pr === 'data:') return false;
          if (pr !== 'http:' && pr !== 'https:') return false;
          if (p.username !== '' || p.password !== '') return false;
          return /\\.(sig|minisig|asc)$/i.test(p.pathname);
        } catch (e) { return false; }
      }
      var validatedSig = (state.signatureUrl != null && isSigUrlAllowed(state.signatureUrl))
        ? state.signatureUrl
        : null;
      // Iter 48 — currentVersion sourced from APP_VERSION (threaded
      // through from app.getVersion() at HTML build time) when
      // available, falling back to state.currentVersion. Same
      // rationale as iter-44/45: state.currentVersion is what the
      // version-check stored at fetch time, which can drift from
      // the running app's actual version.
      var currentVersion4 = (typeof APP_VERSION === 'string' && APP_VERSION.length > 0)
        ? APP_VERSION
        : state.currentVersion;
      var envelope = {
        capturedAt: new Date().toISOString(),
        kind: 'update-blocked-by-signature-fetch',
        currentVersion: currentVersion4,
        targetVersion: state.targetVersion,
        reason: state.reason,
        signatureUrl: validatedSig,
      };
      if (typeof state.httpStatus === 'number' && isFinite(state.httpStatus)) {
        envelope.httpStatus = state.httpStatus;
      }
      envelope.downloadUrl = state.downloadUrl != null ? state.downloadUrl : null;
      envelope.releaseNotesUrl = state.releaseNotesUrl != null ? state.releaseNotesUrl : null;
      envelope.manifestVersion = state.manifestVersion != null ? state.manifestVersion : null;
      var blob = JSON.stringify(envelope, null, 2);
      window.electronAPI.clipboard.writeText(blob).then(function(res) {
        if (res && res.ok) toast(L.copiedDiagnostics);
        else toast(L.copyFailedPrefix + (res && res.error ? res.error : L.unknownError));
      });
    });
    document.getElementById('recheck').addEventListener('click', function() {
      window.electronAPI.versionCheck.recheck();
      toast(L.recheckToast);
    });
    if (state.releaseNotesUrl) {
      document.getElementById('rn-link').addEventListener('click', function() {
        window.electronAPI.shell.openExternal(state.releaseNotesUrl);
      });
    }
  }

  function renderState(state) {
    if (!state) {
      updatesEl.innerHTML = '<p class="muted">' + escape(L.statusUnavailable) + '</p>';
      return;
    }
    if (state.kind === 'update-blocked-by-min-bootstrap') {
      renderBlocked(state);
      return;
    }
    if (state.kind === 'update-blocked-by-signature-fetch') {
      renderBlockedBySignatureFetch(state);
      return;
    }
    var summary = '';
    var bannerCls = '';
    if (state.kind === 'idle') summary = escape(L.summaryIdle);
    else if (state.kind === 'checking') summary = escape(L.summaryChecking);
    else if (state.kind === 'up-to-date') {
      summary = fmt(L.summaryUpToDate, { current: escape(state.current) });
      bannerCls = 'ok';
    }
    else if (state.kind === 'update-available') {
      summary = fmt(L.summaryAvailable, { latest: escape(state.latest), current: escape(state.current) });
      bannerCls = 'warn';
    }
    else if (state.kind === 'error') summary = fmt(L.summaryError, { message: escape(state.message) });
    var banner = bannerCls ? '<div class="banner ' + bannerCls + '">' + summary + '</div>' : '<p>' + summary + '</p>';
    // Iter 43 — extend iter-42 "Copy diagnostics" coverage to the three
    // non-blocked verdicts (up-to-date, update-available, error) so a
    // support reader gets the same envelope shape regardless of verdict.
    // The idle and checking transient states have no meaningful envelope
    // to dump (no version comparison happened yet), so the button is
    // omitted there. Each verdict envelope is built inline below in the
    // click handler — key order matches the buildVersionDiagnosticsBlob
    // helpers byte-for-byte; the iter-43 "key ordering" tests in the
    // main-process suite are the ground truth.
    var diagBtn = (state.kind === 'up-to-date' ||
                   state.kind === 'update-available' ||
                   state.kind === 'error')
      ? '<button id="copy-diagnostics">' + escape(L.copyDiagnostics) + '</button>'
      : '';
    // When an update is available, surface a primary "Download and install"
    // CTA that opens the visual progress dialog and begins the download.
    var updateBtn = state.kind === 'update-available'
      ? '<button id="update-now" class="primary">' + escape(L.updateNow) + '</button>'
      : '';
    updatesEl.innerHTML = banner +
      '<div class="actions">' +
        updateBtn +
        diagBtn +
        '<button id="recheck">' + escape(L.checkNow) + '</button>' +
      '</div>';
    if (updateBtn) {
      document.getElementById('update-now').addEventListener('click', function() {
        if (window.electronAPI && window.electronAPI.updater) {
          window.electronAPI.updater.start();
        }
      });
    }
    if (diagBtn) {
      document.getElementById('copy-diagnostics').addEventListener('click', function() {
        // Mirrors the buildVersionDiagnosticsBlob contract in
        // version-check-manager.ts. We rebuild inline rather than IPC-
        // fetching the blob because the renderer already has the full
        // state in scope. Key order MUST match the helper byte-for-byte
        // — a regression here surfaces as the iter-43 key ordering
        // tests failing in the main-process suite.
        var envelope;
        if (state.kind === 'up-to-date') {
          envelope = {
            capturedAt: new Date().toISOString(),
            kind: 'up-to-date',
            currentVersion: state.current,
            releaseNotesUrl: state.releaseNotesUrl != null ? state.releaseNotesUrl : null,
            manifestVersion: state.manifestVersion != null ? state.manifestVersion : null,
          };
        } else if (state.kind === 'update-available') {
          // Re-run the iter-39 precedence chain (keyed map → scalar →
          // releaseNotes → synthesized) for parity with the operator's
          // mental model. The update-available state today only carries
          // the iter-30 scalar downloadUrl; the keyed-map branch is
          // wired through for future-proofing.
          function isAllowed3(u) {
            if (typeof u !== 'string' || u.length === 0 || u.length > 2048) return false;
            if (/[\\x00-\\x1f\\x7f\\s"<>\\\\^\`{|}]/.test(u)) return false;
            try {
              var p = new URL(u);
              return p.protocol === 'https:' && p.username === '' && p.password === '';
            } catch (e) { return false; }
          }
          var keyed3 = null;
          var map3 = state.bridgeDownloadUrls;
          var minV3 = state.latest;
          if (map3 && typeof map3 === 'object' && typeof minV3 === 'string' && minV3.length > 0 &&
              Object.prototype.hasOwnProperty.call(map3, minV3) && isAllowed3(map3[minV3])) {
            keyed3 = map3[minV3];
          }
          var url3;
          if (keyed3) url3 = keyed3;
          else if (state.downloadUrl && isAllowed3(state.downloadUrl)) url3 = state.downloadUrl;
          else if (state.releaseNotesUrl) url3 = state.releaseNotesUrl;
          else url3 = 'https://rud1.es/desktop/download?version=' + encodeURIComponent(minV3 || '');
          var rawHash3 = state.bridgeSha256;
          var hashHex3 = (typeof rawHash3 === 'string' && /^[0-9a-f]{64}$/i.test(rawHash3))
            ? rawHash3.toLowerCase()
            : null;
          // Iter 45 — currentVersion sourced from APP_VERSION
          // (threaded through from app.getVersion() at HTML build
          // time) when available, falling back to state.current for
          // parity with the helper's legacy behaviour. Same rationale
          // as the iter-44 error-verdict thread: state.current is the
          // version the manifest fetch saw, which can drift from the
          // running app's actual version under bridge-only updates.
          var currentVersion3 = (typeof APP_VERSION === 'string' && APP_VERSION.length > 0)
            ? APP_VERSION
            : state.current;
          // Iter 47 — defensive .sig URL re-validation; same contract as
          // the blocked-state path. Append-only key (omitted when
          // absent / rejected) so iter-43 update-available key ordering
          // holds byte-for-byte when no signatureUrl is in play.
          function isSigUrlAllowed3(u) {
            if (typeof u !== 'string' || u.length === 0 || u.length > 2048) return false;
            if (/[\\x00-\\x1f\\x7f\\s"<>\\\\^\`{|}]/.test(u)) return false;
            try {
              var p = new URL(u);
              var pr = (p.protocol || '').toLowerCase();
              if (pr === 'javascript:' || pr === 'data:') return false;
              if (pr !== 'http:' && pr !== 'https:') return false;
              if (p.username !== '' || p.password !== '') return false;
              return /\\.(sig|minisig|asc)$/i.test(p.pathname);
            } catch (e) { return false; }
          }
          var sigUrl3 = isSigUrlAllowed3(state.signatureUrl) ? state.signatureUrl : null;
          envelope = {
            capturedAt: new Date().toISOString(),
            kind: 'update-available',
            currentVersion: currentVersion3,
            targetVersion: state.latest,
            downloadUrl: url3,
            bridgeSha256: hashHex3,
            releaseNotesUrl: state.releaseNotesUrl != null ? state.releaseNotesUrl : null,
            manifestVersion: state.manifestVersion != null ? state.manifestVersion : null,
          };
          if (sigUrl3 != null) {
            envelope.signatureUrl = sigUrl3;
          }
        } else {
          // error
          // Iter 44 — currentVersion sourced from APP_VERSION (threaded
          // through from app.getVersion() at HTML build time) rather
          // than state.current. The error state shape does not carry
          // current, so reading it off state always yielded null;
          // APP_VERSION fixes that without changing the envelope key
          // ordering. Mirrors buildErrorDiagnosticsBlob in
          // version-check-manager.ts byte-for-byte.
          envelope = {
            capturedAt: new Date().toISOString(),
            kind: 'error',
            currentVersion: APP_VERSION != null ? APP_VERSION : null,
            errorMessage: state.message,
            manifestVersion: state.manifestVersion != null ? state.manifestVersion : null,
          };
        }
        var blob = JSON.stringify(envelope, null, 2);
        window.electronAPI.clipboard.writeText(blob).then(function(res) {
          if (res && res.ok) toast(L.copiedDiagnostics);
          else toast(L.copyFailedPrefix + (res && res.error ? res.error : L.unknownError));
        });
      });
    }
    document.getElementById('recheck').addEventListener('click', function() {
      window.electronAPI.versionCheck.recheck();
      toast(L.recheckToast);
    });
  }

  // Initial fetch + subscribe to push updates from main. Guarded so a
  // missing namespace (older preload, sandbox hiccup) degrades to an
  // honest "unavailable" message instead of throwing and stranding the
  // rest of the panel's wiring at "Loading…".
  if (window.electronAPI && window.electronAPI.versionCheck) {
    window.electronAPI.versionCheck.state().then(function(res) {
      if (res && res.ok) renderState(res.result);
      else renderState(null);
    }).catch(function() { renderState(null); });
    if (typeof window.electronAPI.versionCheck.onUpdate === 'function') {
      window.electronAPI.versionCheck.onUpdate(function(state) { renderState(state); });
    }
  } else {
    renderState(null);
  }

  // Dedupe inspector launcher — this just opens the existing iter-28
  // window. There is no IPC for "open dedupe inspector" today, so we
  // fall back to listing + offering a hint if the inspector isn't
  // accessible from here.
  document.getElementById('open-dedupe').addEventListener('click', function() {
    // No direct IPC: surface a hint that the inspector is on the tray
    // submenu. This is honest about the iter-28 boundary without
    // pretending we can launch it from a sibling panel.
    toast(L.openFromTray);
  });

  // Auto-start preference. The toggle reflects the OS state — we read
  // it on mount and re-read after every flip so a sandbox / permission
  // refusal snaps the switch back instead of leaving it lying.
  var autoStartToggle = document.getElementById('auto-start-toggle');
  var autoStartHint = document.getElementById('auto-start-hint');
  function autoStartHintFor(state) {
    if (state.unsupported) {
      // Use the localized copy rather than the main-process reason string
      // (which is English) so the row stays in the panel's language.
      return L.autoStartUnsupported;
    }
    if (state.platform === 'win32') {
      return L.autoStartWin;
    }
    if (state.platform === 'darwin') {
      return L.autoStartMac;
    }
    if (state.platform === 'linux') {
      return L.autoStartLinux;
    }
    return '';
  }
  function applyAutoStart(state) {
    autoStartToggle.checked = !!state.enabled;
    autoStartToggle.disabled = !!state.unsupported;
    autoStartHint.textContent = autoStartHintFor(state);
  }
  if (window.electronAPI && window.electronAPI.app && typeof window.electronAPI.app.getAutoStart === 'function') {
    // Guarantee the hint never stays at "Loading…": a rejected invoke
    // (handler not registered in an older build) without a .catch, or a
    // never-settling promise, would otherwise strand it. The fallback timer
    // flips it to "unavailable" if nothing resolved; both settle paths clear it.
    var autoStartSettled = false;
    var autoStartFallback = setTimeout(function() {
      if (!autoStartSettled) autoStartHint.textContent = L.autoStartStateUnavailable;
    }, 4000);
    function settleAutoStart() {
      autoStartSettled = true;
      clearTimeout(autoStartFallback);
    }
    window.electronAPI.app.getAutoStart().then(function(res) {
      settleAutoStart();
      if (res && res.ok) applyAutoStart(res.result);
      else autoStartHint.textContent = L.autoStartStateUnavailable;
    }).catch(function() {
      settleAutoStart();
      autoStartHint.textContent = L.autoStartStateUnavailable;
    });
    autoStartToggle.addEventListener('change', function() {
      var desired = !!autoStartToggle.checked;
      autoStartToggle.disabled = true;
      window.electronAPI.app.setAutoStart(desired).then(function(res) {
        if (res && res.ok) {
          applyAutoStart(res.result);
          toast(res.result.enabled ? L.autoStartEnabled : L.autoStartDisabled);
        } else {
          // Revert optimistic flip; surface the underlying error.
          autoStartToggle.checked = !desired;
          autoStartToggle.disabled = false;
          toast(L.autoStartChangeFailedPrefix + (res && res.error ? res.error : L.unknownError));
        }
      });
    });
  } else {
    autoStartHint.textContent = L.autoStartApiUnavailable;
  }

  // Persisted preferences (theme + per-category notification toggles).
  // INITIAL_THEME is baked at HTML build time so the very first paint
  // matches the user's pinned theme without a flash; the JS below
  // reconciles with the IPC-fetched canonical state and wires the
  // controls.
  var INITIAL_THEME = ${initialThemeLiteral};
  function applyThemeToDom(theme) {
    if (theme === 'light' || theme === 'dark') {
      document.documentElement.setAttribute('data-theme', theme);
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
  }
  function syncThemePicker(theme) {
    var radios = document.querySelectorAll('input[name="theme-pick"]');
    for (var i = 0; i < radios.length; i++) {
      radios[i].checked = radios[i].value === theme;
    }
  }
  function syncNotifToggles(notifs) {
    document.getElementById('notif-firstBoot').checked = !!notifs.firstBoot;
    document.getElementById('notif-vpn').checked = !!notifs.vpn;
    document.getElementById('notif-usb').checked = !!notifs.usb;
  }
  function syncLangPicker(language) {
    var radios = document.querySelectorAll('input[name="lang-pick"]');
    for (var i = 0; i < radios.length; i++) {
      radios[i].checked = radios[i].value === language;
    }
  }
  syncThemePicker(INITIAL_THEME);
  syncLangPicker(INITIAL_LANGUAGE);

  if (window.electronAPI && window.electronAPI.app && typeof window.electronAPI.app.getPreferences === 'function') {
    window.electronAPI.app.getPreferences().then(function(res) {
      if (!res || !res.ok) {
        // IPC reachable but the main process rejected it (e.g. the sender
        // wasn't recognised as trusted). Surface the real reason rather
        // than silently keeping the baked-in defaults.
        setDiag('No se pudieron cargar los ajustes: ' + ((res && res.error) ? res.error : 'respuesta inválida'));
        return;
      }
      setDiag('');
      applyThemeToDom(res.result.theme);
      syncThemePicker(res.result.theme);
      syncLangPicker(res.result.language);
      syncNotifToggles(res.result.notifications);
      var autoUpd = document.getElementById('auto-update-toggle');
      if (autoUpd) autoUpd.checked = !!res.result.autoUpdate;
    }).catch(function(e) {
      setDiag('Ajustes sin respuesta del proceso principal: ' + ((e && e.message) ? e.message : 'IPC rechazado'));
    });

    var themeRadios = document.querySelectorAll('input[name="theme-pick"]');
    for (var i = 0; i < themeRadios.length; i++) {
      themeRadios[i].addEventListener('change', function(e) {
        var nextTheme = e.target.value;
        applyThemeToDom(nextTheme);
        window.electronAPI.app.setPreferences({ theme: nextTheme }).then(function(res) {
          if (res && res.ok) {
            // Server-confirmed value wins — usually identical to the
            // optimistic flip, but a malformed value would snap back.
            applyThemeToDom(res.result.theme);
            syncThemePicker(res.result.theme);
            toast(L.themeToastPrefix + res.result.theme);
          } else {
            toast(L.themeSaveFailedPrefix + (res && res.error ? res.error : L.unknownError));
          }
        });
      });
    }

    // Language picker. Changing the language re-renders main-process
    // chrome (tray, menus) via the onPreferencesUpdated hook; this panel
    // keeps its baked-at-open-time copy until reopened, so we surface a
    // toast confirming the saved value.
    var langRadios = document.querySelectorAll('input[name="lang-pick"]');
    for (var j = 0; j < langRadios.length; j++) {
      langRadios[j].addEventListener('change', function(e) {
        var nextLang = e.target.value;
        syncLangPicker(nextLang);
        window.electronAPI.app.setPreferences({ language: nextLang }).then(function(res) {
          if (res && res.ok) {
            syncLangPicker(res.result.language);
            toast(L.languageToastPrefix + res.result.language);
          } else {
            toast(L.languageSaveFailedPrefix + (res && res.error ? res.error : L.unknownError));
          }
        });
      });
    }

    function bindNotifToggle(id, key) {
      var el = document.getElementById(id);
      el.addEventListener('change', function() {
        var desired = !!el.checked;
        var patch = { notifications: {} };
        patch.notifications[key] = desired;
        el.disabled = true;
        window.electronAPI.app.setPreferences(patch).then(function(res) {
          el.disabled = false;
          if (res && res.ok) {
            syncNotifToggles(res.result.notifications);
            toast(fmt(res.result.notifications[key] ? L.notifSavedOn : L.notifSavedOff, { key: key }));
          } else {
            // Revert optimistic flip.
            el.checked = !desired;
            toast(L.saveFailedPrefix + (res && res.error ? res.error : L.unknownError));
          }
        });
      });
    }
    bindNotifToggle('notif-firstBoot', 'firstBoot');
    bindNotifToggle('notif-vpn', 'vpn');
    bindNotifToggle('notif-usb', 'usb');

    // Auto-update opt-in. Reflects the OS-confirmed post-merge value so a
    // rejected save snaps the switch back instead of leaving it lying.
    var autoUpdateToggle = document.getElementById('auto-update-toggle');
    if (autoUpdateToggle) {
      autoUpdateToggle.addEventListener('change', function() {
        var desired = !!autoUpdateToggle.checked;
        autoUpdateToggle.disabled = true;
        window.electronAPI.app.setPreferences({ autoUpdate: desired }).then(function(res) {
          autoUpdateToggle.disabled = false;
          if (res && res.ok) {
            autoUpdateToggle.checked = !!res.result.autoUpdate;
            toast(res.result.autoUpdate ? L.autoUpdateOn : L.autoUpdateOff);
          } else {
            autoUpdateToggle.checked = !desired;
            toast(L.saveFailedPrefix + (res && res.error ? res.error : L.unknownError));
          }
        });
      });
    }
  } else {
    setDiag('El puente electronAPI.app no está disponible (preload no cargado). Reinstala/relanza la app desde un build actual.');
  }
</script>
</body>
</html>`;
  return "data:text/html;charset=utf-8," + encodeURIComponent(html);
}

/**
 * Iter 46 — thin wrapper that bakes the runtime app version override
 * into `buildSettingsWindowHtml`.
 *
 * Why a wrapper instead of a default-arg or rename:
 *   - The iter-44 `buildSettingsWindowHtml(currentVersion)` signature
 *     is positional and easy to forget about — a future caller
 *     reaching `buildSettingsWindowHtml` directly (a test harness, a
 *     non-renderer surface like a hypothetical PDF export, etc.) has
 *     to remember that the parameter is "the running app's version
 *     at panel-open time, fed from `app.getVersion()`." Naming the
 *     wrapper `…WithRuntimeVersion` makes that contract explicit at
 *     the call site.
 *   - The wrapper baking the override means the `runtimeAppVersion`
 *     value flows uniformly into ALL FOUR surfaces the panel exposes:
 *       1. the inline `APP_VERSION` JS constant (consumed by all three
 *          renderer-side "Copy diagnostics" rebuilds)
 *       2. the `error` diagnostics envelope (via `APP_VERSION` →
 *          mirrors `buildErrorDiagnosticsBlob`'s `state.current`)
 *       3. the `blocked` diagnostics envelope (via `APP_VERSION`
 *          override of `state.currentVersion` — mirrors the iter-45
 *          `runtimeAppVersion` parameter on
 *          `buildBlockedDiagnosticsBlob`)
 *       4. the `update-available` diagnostics envelope (same shape
 *          via `state.current` — mirrors the iter-45 parameter on
 *          `buildUpdateAvailableDiagnosticsBlob`)
 *   - Existing direct callers of `buildSettingsWindowHtml` keep
 *     working byte-for-byte; the wrapper is purely additive.
 *
 * Today the wrapper is a single-line passthrough — APP_VERSION IS
 * the entire mechanism by which the runtime version reaches the
 * three blob rebuilds. If a future iteration moves any of the blob
 * builders main-side (e.g. a synchronous "build at click time" IPC
 * round-trip that calls the helpers in `version-check-manager.ts`
 * directly), this wrapper becomes the single seam where the
 * `runtimeAppVersion` argument gets threaded into those calls.
 *
 * `runtimeAppVersion` is typed as `string` (not `string | null`) at
 * the wrapper boundary — callers must commit to a value. The inline
 * renderer's defensive `typeof + length>0` guard handles the
 * pathological case at runtime, but the type system here pushes
 * back on intentional omission so the call site stays loud.
 */
export function buildSettingsWindowHtmlWithRuntimeVersion(
  runtimeAppVersion: string,
  initialTheme: "system" | "light" | "dark" = "system",
  initialLanguage: LanguagePreference = "system",
  locale: Locale = "en",
): string {
  return buildSettingsWindowHtml(
    runtimeAppVersion,
    initialTheme,
    initialLanguage,
    locale,
  );
}
