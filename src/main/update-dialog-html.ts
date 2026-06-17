// Ventana de actualización (data: URL, sandboxed). Estilo Liquid Glass como
// el resto del ecosistema rud1. Habla con main vía window.electronAPI.updater.
import { t, type Locale } from "./i18n";

/**
 * Combined updater state pushed to the dialog renderer. Computed in
 * index.ts from the live VersionCheckState + AutoUpdateState + the
 * `autoUpdate` preference. The renderer maps `phase` to a card; the
 * `installing` phase is set optimistically renderer-side on the restart
 * click (the process quits right after `apply()`).
 */
export type UpdaterDialogPhase =
  | "checking"
  | "available"
  | "downloading"
  | "ready"
  | "error"
  | "up-to-date";

export interface UpdaterDialogState {
  phase: UpdaterDialogPhase;
  current: string;
  latest: string;
  downloadUrl: string | null;
  bytesReceived: number;
  totalBytes: number | null;
  message: string;
  autoUpdate: boolean;
}

export function buildUpdateDialogHtml(
  currentTheme: "system" | "light" | "dark" = "system",
  locale: Locale = "en",
): string {
  const themeAttr =
    currentTheme === "light" || currentTheme === "dark"
      ? ` data-theme="${currentTheme}"`
      : "";
  // Localized strings consumed by the inline renderer. JSON-encoded so
  // accents / CJK survive the data: URL round-trip.
  const L = JSON.stringify({
    checkingHeading: t("updateDialog.checkingHeading"),
    checkingBody: t("updateDialog.checkingBody"),
    availableHeading: t("updateDialog.availableHeading"),
    availableBody: t("updateDialog.availableBody", { latest: "{latest}", current: "{current}" }),
    yes: t("updateDialog.yes"),
    later: t("updateDialog.later"),
    downloadingHeading: t("updateDialog.downloadingHeading"),
    elapsed: t("updateDialog.elapsed"),
    remaining: t("updateDialog.remaining"),
    speed: t("updateDialog.speed"),
    preparing: t("updateDialog.preparing"),
    calculating: t("updateDialog.calculating"),
    readyHeading: t("updateDialog.readyHeading"),
    readyBody: t("updateDialog.readyBody"),
    restartNow: t("updateDialog.restartNow"),
    installing: t("updateDialog.installing"),
    errorHeading: t("updateDialog.errorHeading"),
    retry: t("updateDialog.retry"),
    upToDateHeading: t("updateDialog.upToDateHeading"),
  });
  const html = `<!doctype html>
<html lang="${locale}"${themeAttr}>
<head>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none';" />
<title>${t("updateDialog.windowTitle")}</title>
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
    --primary: #a8c4ff;
    --primary-accent: #86a8ff;
    --primary-soft: #e0eaff;
    --primary-fg: #122a55;
    --track: rgba(140, 160, 200, 0.28);
    --danger-bg: #fbd5d0;
    --danger-border: #f1908a;
    --danger-fg: #5a1a17;
    --success-fg: #0e3f25;
    --mesh-1: rgba(168, 196, 255, 0.55);
    --mesh-2: rgba(208, 195, 255, 0.5);
    --mesh-3: rgba(196, 240, 224, 0.45);
    --mesh-4: rgba(255, 226, 197, 0.45);
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #0a0e17;
      --fg: #e6eaf2;
      --muted-fg: #93a0b8;
      --surface: rgba(28, 36, 50, 0.55);
      --surface-strong: rgba(28, 36, 50, 0.78);
      --border: rgba(120, 140, 175, 0.22);
      --shadow: rgba(0, 0, 0, 0.55);
      --primary: #a8c4ff;
      --primary-accent: #86a8ff;
      --primary-soft: rgba(168, 196, 255, 0.28);
      --primary-fg: #0e1a2a;
      --track: rgba(120, 140, 175, 0.25);
      --danger-bg: rgba(241, 144, 138, 0.22);
      --danger-border: rgba(241, 144, 138, 0.45);
      --danger-fg: #f3bcb7;
      --success-fg: #b9ecd0;
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
    --border: rgba(120, 140, 175, 0.22);
    --shadow: rgba(0, 0, 0, 0.55);
    --primary: #a8c4ff;
    --primary-accent: #86a8ff;
    --primary-soft: rgba(168, 196, 255, 0.28);
    --primary-fg: #0e1a2a;
    --track: rgba(120, 140, 175, 0.25);
    --danger-bg: rgba(241, 144, 138, 0.22);
    --danger-border: rgba(241, 144, 138, 0.45);
    --danger-fg: #f3bcb7;
    --success-fg: #b9ecd0;
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
    padding: 26px;
    font-size: 13px;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    min-height: 100vh;
    display: flex;
    align-items: center;
  }
  .card {
    width: 100%;
    border-radius: 18px;
    border: 1px solid var(--border);
    background: var(--surface);
    backdrop-filter: blur(22px) saturate(170%);
    -webkit-backdrop-filter: blur(22px) saturate(170%);
    box-shadow: 0 10px 36px var(--shadow);
    padding: 24px;
  }
  .icon {
    width: 46px; height: 46px; border-radius: 14px;
    display: flex; align-items: center; justify-content: center;
    background: var(--primary-soft);
    margin: 0 0 14px 0;
    font-size: 24px;
  }
  h1 { font-size: 18px; font-weight: 650; margin: 0 0 8px 0; letter-spacing: -0.01em; }
  p { margin: 0 0 10px 0; color: var(--muted-fg); }
  p.strong { color: var(--fg); }
  .spinner {
    width: 22px; height: 22px; border-radius: 50%;
    border: 3px solid var(--track);
    border-top-color: var(--primary-accent);
    animation: spin 0.8s linear infinite;
    display: inline-block; vertical-align: middle; margin-right: 10px;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .progress-wrap { margin: 18px 0 14px 0; }
  .bar {
    height: 12px; border-radius: 999px; background: var(--track);
    overflow: hidden; position: relative;
  }
  .bar > .fill {
    height: 100%; width: 0%;
    background: linear-gradient(90deg, var(--primary), var(--primary-accent));
    border-radius: 999px;
    transition: width 0.25s ease;
  }
  .bar.indeterminate > .fill {
    width: 35% !important;
    position: absolute;
    animation: slide 1.2s ease-in-out infinite;
  }
  @keyframes slide { 0% { left: -35%; } 100% { left: 100%; } }
  .pct { text-align: right; font-size: 12px; color: var(--muted-fg); margin-top: 6px; font-variant-numeric: tabular-nums; }
  .stats { display: flex; justify-content: space-between; gap: 12px; margin-top: 12px; }
  .stat { flex: 1; text-align: center; padding: 10px 6px; border-radius: 12px; background: var(--surface-strong); border: 1px solid var(--border); }
  .stat .k { font-size: 10px; text-transform: uppercase; letter-spacing: 0.07em; color: var(--muted-fg); }
  .stat .v { font-size: 14px; font-weight: 600; color: var(--fg); margin-top: 3px; font-variant-numeric: tabular-nums; }
  .actions { display: flex; gap: 10px; margin-top: 20px; }
  button {
    flex: 1;
    background: var(--surface);
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 11px 16px;
    font-size: 13px;
    font-weight: 550;
    cursor: pointer;
    font-family: inherit;
    transition: background 0.15s ease, transform 0.1s ease, filter 0.15s ease;
  }
  button:hover { background: var(--surface-strong); }
  button:active { transform: scale(0.98); }
  button.primary {
    background: var(--primary);
    border-color: var(--primary);
    color: var(--primary-fg);
    font-weight: 650;
    box-shadow: 0 6px 18px rgba(109, 179, 245, 0.35);
  }
  button.primary:hover { filter: brightness(1.04); }
  .err-banner {
    background: var(--danger-bg); color: var(--danger-fg);
    border: 1px solid var(--danger-border); border-radius: 12px;
    padding: 11px 13px; margin: 4px 0 8px 0; word-break: break-word;
    backdrop-filter: blur(10px);
  }
</style>
</head>
<body>
  <div class="card" id="card"></div>
<script>
  var L = ${L};
  var cardEl = document.getElementById('card');
  var downloadStartTs = null;     // wall-clock when 'downloading' first seen
  var lastBytes = 0;

  function fmt(template, vars) {
    return String(template).replace(/\\{(\\w+)\\}/g, function (m, k) {
      return Object.prototype.hasOwnProperty.call(vars, k) ? String(vars[k]) : m;
    });
  }
  function escape(s) {
    return String(s).replace(/[&<>"']/g, function(c) {
      return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c];
    });
  }
  function fmtBytes(n) {
    if (!n || n < 1024) return (n || 0) + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
    return (n / 1073741824).toFixed(2) + ' GB';
  }
  function fmtDuration(sec) {
    if (sec == null || !isFinite(sec) || sec < 0) return L.calculating;
    sec = Math.round(sec);
    var m = Math.floor(sec / 60);
    var s = sec % 60;
    return (m < 10 ? '0' : '') + m + ':' + (s < 10 ? '0' : '') + s;
  }

  function renderChecking() {
    cardEl.innerHTML =
      '<div class="icon">↻</div>' +
      '<h1><span class="spinner"></span>' + escape(L.checkingHeading) + '</h1>' +
      '<p>' + escape(L.checkingBody) + '</p>';
  }

  function renderAvailable(st) {
    var body = fmt(L.availableBody, { latest: escape(st.latest), current: escape(st.current) });
    cardEl.innerHTML =
      '<div class="icon">⬆</div>' +
      '<h1>' + escape(L.availableHeading) + '</h1>' +
      '<p class="strong">' + body + '</p>' +
      '<div class="actions">' +
        '<button id="later">' + escape(L.later) + '</button>' +
        '<button id="yes" class="primary">' + escape(L.yes) + '</button>' +
      '</div>';
    document.getElementById('yes').addEventListener('click', function() {
      // Optimistic: flip to a preparing card so the click feels instant.
      cardEl.innerHTML =
        '<div class="icon">⬇</div>' +
        '<h1><span class="spinner"></span>' + escape(L.downloadingHeading) + '</h1>' +
        '<p>' + escape(L.preparing) + '</p>';
      window.electronAPI.updater.start();
    });
    document.getElementById('later').addEventListener('click', function() {
      window.electronAPI.updater.later();
    });
  }

  function renderDownloading(st) {
    if (downloadStartTs == null) downloadStartTs = Date.now();
    var total = (typeof st.totalBytes === 'number' && st.totalBytes > 0) ? st.totalBytes : null;
    var received = st.bytesReceived || 0;
    var pct = total ? Math.max(0, Math.min(100, Math.floor((received / total) * 100))) : null;
    var elapsedSec = (Date.now() - downloadStartTs) / 1000;
    var speed = elapsedSec > 0.4 ? received / elapsedSec : 0;   // bytes/s
    var etaSec = (total && speed > 0) ? (total - received) / speed : null;
    var barCls = total ? 'bar' : 'bar indeterminate';
    var pctLabel = total
      ? pct + '%  ·  ' + fmtBytes(received) + ' / ' + fmtBytes(total)
      : fmtBytes(received);
    cardEl.innerHTML =
      '<div class="icon">⬇</div>' +
      '<h1>' + escape(L.downloadingHeading) + '</h1>' +
      '<div class="progress-wrap">' +
        '<div class="' + barCls + '"><div class="fill" style="width:' + (total ? pct : 35) + '%"></div></div>' +
        '<div class="pct">' + escape(pctLabel) + '</div>' +
      '</div>' +
      '<div class="stats">' +
        '<div class="stat"><div class="k">' + escape(L.elapsed) + '</div><div class="v">' + escape(fmtDuration(elapsedSec)) + '</div></div>' +
        '<div class="stat"><div class="k">' + escape(L.remaining) + '</div><div class="v">' + escape(fmtDuration(etaSec)) + '</div></div>' +
        '<div class="stat"><div class="k">' + escape(L.speed) + '</div><div class="v">' + escape(speed > 0 ? fmtBytes(speed) + '/s' : '—') + '</div></div>' +
      '</div>';
  }

  function renderReady() {
    cardEl.innerHTML =
      '<div class="icon">✔</div>' +
      '<h1>' + escape(L.readyHeading) + '</h1>' +
      '<p class="strong">' + escape(L.readyBody) + '</p>' +
      '<div class="actions">' +
        '<button id="restart" class="primary">' + escape(L.restartNow) + '</button>' +
      '</div>';
    document.getElementById('restart').addEventListener('click', function() {
      cardEl.innerHTML =
        '<div class="icon">⚙</div>' +
        '<h1><span class="spinner"></span>' + escape(L.installing) + '</h1>';
      window.electronAPI.updater.apply();
    });
  }

  function renderError(st) {
    cardEl.innerHTML =
      '<div class="icon">⚠</div>' +
      '<h1>' + escape(L.errorHeading) + '</h1>' +
      (st.message ? '<div class="err-banner">' + escape(st.message) + '</div>' : '') +
      '<div class="actions">' +
        '<button id="later">' + escape(L.later) + '</button>' +
        '<button id="retry" class="primary">' + escape(L.retry) + '</button>' +
      '</div>';
    document.getElementById('retry').addEventListener('click', function() {
      downloadStartTs = null;
      window.electronAPI.updater.recheck();
      renderChecking();
    });
    document.getElementById('later').addEventListener('click', function() {
      window.electronAPI.updater.later();
    });
  }

  function renderUpToDate(st) {
    cardEl.innerHTML =
      '<div class="icon">✔</div>' +
      '<h1>' + escape(L.upToDateHeading) + '</h1>' +
      '<p>v' + escape(st.current) + '</p>' +
      '<div class="actions">' +
        '<button id="later" class="primary">' + escape(L.later) + '</button>' +
      '</div>';
    document.getElementById('later').addEventListener('click', function() {
      window.electronAPI.updater.later();
    });
  }

  function render(st) {
    if (!st) { renderChecking(); return; }
    if (st.phase !== 'downloading') downloadStartTs = null;
    switch (st.phase) {
      case 'checking': renderChecking(); break;
      case 'available': renderAvailable(st); break;
      case 'downloading': renderDownloading(st); break;
      case 'ready': renderReady(); break;
      case 'error': renderError(st); break;
      case 'up-to-date': renderUpToDate(st); break;
      default: renderChecking();
    }
  }

  renderChecking();
  if (window.electronAPI && window.electronAPI.updater) {
    window.electronAPI.updater.getState().then(function(res) {
      if (res && res.ok) render(res.result);
    });
    window.electronAPI.updater.onState(function(st) { render(st); });
  }
</script>
</body>
</html>`;
  return "data:text/html;charset=utf-8," + encodeURIComponent(html);
}
