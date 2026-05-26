/**
 * Liquid Glass driver-install modal — pre-elevation UI.
 *
 * Rendered as a small main-process-owned BrowserWindow (same pattern
 * as the iter-28 dedupe inspector + iter-37 Settings panel) loaded
 * from an inline `data:text/html` URL with a strict CSP. The renderer
 * has two affordances:
 *
 *   1. Explain what's about to happen (TAP-Windows V9 kernel driver
 *      install via the bundled tapctl.exe — one UAC prompt) so the
 *      OS prompt doesn't feel out of nowhere.
 *   2. Trigger the install via `electronAPI.vpn.installTapDriver()`,
 *      then close the window so the user can retry Connect.
 *
 * Design parity with the rest of rud1-desktop's mini-windows:
 *   - Light + dark themes driven by `prefers-color-scheme` (no toggle —
 *     the modal is too small to host one; the user's pinned-theme
 *     preference from Settings is mirrored via `data-theme` on <html>).
 *   - Pastel blue primary, glassmorphism surface tier, generous radius.
 *   - Tokens cloned from `settings-window-html.ts` so a brand refresh
 *     in one file propagates by ctrl-c / ctrl-v rather than divergence.
 *
 * Why a separate window rather than rendering this inside the rud1-es
 * panel: at the moment the user lands on the Connect tab there is no
 * VPN — which means the cloud panel may be momentarily unreachable
 * (cloud reverse-proxy expects the device to be online). A main-process
 * data-URL window doesn't depend on the panel being responsive.
 */

export interface DriverInstallWindowOpts {
  currentTheme: "system" | "light" | "dark";
  /** Pre-computed list of file paths the renderer will mention as
   *  "files installed" for transparency. Optional; main passes
   *  `[]` to suppress the section. */
  bundledFiles?: readonly string[];
}

export function buildDriverInstallWindowHtml(
  opts: DriverInstallWindowOpts,
): string {
  const themeAttr =
    opts.currentTheme === "light" || opts.currentTheme === "dark"
      ? ` data-theme="${opts.currentTheme}"`
      : "";
  const filesJson = JSON.stringify(opts.bundledFiles ?? []);
  const html = `<!doctype html>
<html lang="en"${themeAttr}>
<head>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none';" />
<title>rud1 — Install VPN driver</title>
<style>
  /*
   * Liquid Glass tokens — cloned from settings-window-html.ts. Keep them
   * in sync; a brand refresh in one file propagates by copy-paste rather
   * than drift.
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

    --primary: #a8c4ff;
    --primary-accent: #86a8ff;
    --primary-soft: #e0eaff;
    --primary-fg: #122a55;

    --warning-bg: #fde6c2;
    --warning-border: #f5b962;
    --warning-fg: #4a2d0a;

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
      --primary: #86a8ff;
      --primary-accent: #a8c4ff;
      --primary-soft: rgba(168, 196, 255, 0.18);
      --primary-fg: #f0f4ff;
      --warning-bg: rgba(245, 185, 98, 0.18);
      --warning-border: rgba(245, 185, 98, 0.45);
      --warning-fg: #fde6c2;
      --mesh-1: rgba(40, 80, 130, 0.36);
      --mesh-2: rgba(80, 60, 130, 0.32);
      --mesh-3: rgba(40, 110, 95, 0.28);
      --mesh-4: rgba(130, 80, 50, 0.28);
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
    --primary: #86a8ff;
    --primary-accent: #a8c4ff;
    --primary-soft: rgba(168, 196, 255, 0.18);
    --primary-fg: #f0f4ff;
    --warning-bg: rgba(245, 185, 98, 0.18);
    --warning-border: rgba(245, 185, 98, 0.45);
    --warning-fg: #fde6c2;
    --mesh-1: rgba(40, 80, 130, 0.36);
    --mesh-2: rgba(80, 60, 130, 0.32);
    --mesh-3: rgba(40, 110, 95, 0.28);
    --mesh-4: rgba(130, 80, 50, 0.28);
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
    min-height: 100vh;
  }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 18px;
    backdrop-filter: blur(24px) saturate(180%);
    -webkit-backdrop-filter: blur(24px) saturate(180%);
    box-shadow: 0 8px 28px var(--shadow);
    padding: 22px;
  }
  .card + .card { margin-top: 14px; }

  h1 {
    font-size: 18px;
    font-weight: 600;
    margin: 0 0 8px 0;
    letter-spacing: -0.01em;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .badge {
    background: var(--primary-soft);
    color: var(--primary-fg);
    border: 1px solid var(--primary);
    border-radius: 999px;
    padding: 2px 10px;
    font-size: 11px;
    font-weight: 500;
    letter-spacing: 0.02em;
  }
  p { margin: 0 0 10px 0; color: var(--fg); }
  p.muted { color: var(--muted-fg); font-size: 12px; }

  ul.steps {
    list-style: none;
    padding: 0;
    margin: 12px 0 0 0;
    display: grid;
    gap: 8px;
  }
  ul.steps li {
    background: var(--surface-strong);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 10px 14px;
    font-size: 12px;
    display: flex;
    align-items: flex-start;
    gap: 10px;
    backdrop-filter: blur(14px) saturate(160%);
    -webkit-backdrop-filter: blur(14px) saturate(160%);
  }
  ul.steps li::before {
    content: counter(step);
    counter-increment: step;
    flex: 0 0 22px;
    height: 22px;
    border-radius: 999px;
    background: var(--primary-soft);
    color: var(--primary-fg);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 11px;
    font-weight: 600;
  }
  ul.steps { counter-reset: step; }

  details.files {
    margin-top: 14px;
    font-size: 12px;
    color: var(--muted-fg);
  }
  details.files summary {
    cursor: pointer;
    padding: 6px 0;
  }
  details.files ul {
    list-style: none;
    padding: 8px 0 0 0;
    margin: 0;
    display: grid;
    gap: 4px;
    font-family: ui-monospace, "SF Mono", Consolas, monospace;
    font-size: 11px;
  }

  .actions {
    display: flex;
    gap: 10px;
    margin-top: 18px;
    justify-content: flex-end;
  }
  button {
    background: var(--surface);
    color: var(--fg);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 9px 18px;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    backdrop-filter: blur(14px) saturate(160%);
    -webkit-backdrop-filter: blur(14px) saturate(160%);
    transition: background 0.15s ease, transform 0.1s ease;
  }
  button:hover { background: var(--surface-strong); }
  button:active { transform: scale(0.98); }
  button:disabled { opacity: 0.55; cursor: not-allowed; }
  button.primary {
    background: var(--primary);
    color: var(--primary-fg);
    border-color: var(--primary-accent);
    font-weight: 600;
  }
  button.primary:hover { background: var(--primary-accent); }

  .status {
    margin-top: 12px;
    font-size: 12px;
    color: var(--muted-fg);
    min-height: 16px;
  }
  .status.error {
    color: var(--warning-fg);
    background: var(--warning-bg);
    border: 1px solid var(--warning-border);
    border-radius: 10px;
    padding: 8px 12px;
  }
  .spinner {
    display: inline-block;
    width: 14px;
    height: 14px;
    border: 2px solid var(--primary-soft);
    border-top-color: var(--primary);
    border-radius: 999px;
    animation: spin 0.8s linear infinite;
    vertical-align: middle;
    margin-right: 8px;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
  <div class="card">
    <h1>
      Install the VPN driver
      <span class="badge">One-time setup</span>
    </h1>
    <p>
      rud1 needs to install the <strong>TAP-Windows V9</strong> kernel driver
      so the OpenVPN client can expose a virtual network adapter to your
      engineering tools (TIA Portal, Codesys, OPC UA discovery, etc).
    </p>
    <p class="muted">
      Windows will ask you to approve the install. The driver is signed by
      OpenVPN Inc. and bundled with rud1 — no external download is required.
    </p>
    <ul class="steps">
      <li>Click <strong>Install driver</strong> below.</li>
      <li>Approve the OS elevation prompt (User Account Control).</li>
      <li>Click <strong>Connect</strong> on the device page in rud1.</li>
    </ul>
    <details class="files">
      <summary>Files installed (signed by OpenVPN Inc.)</summary>
      <ul id="files"></ul>
    </details>
    <div class="actions">
      <button id="cancel">Cancel</button>
      <button id="install" class="primary">Install driver</button>
    </div>
    <div id="status" class="status" role="status" aria-live="polite"></div>
  </div>
<script>
  // ESM-safe inline runtime — runs in the isolated renderer context but
  // shares the preload's electronAPI bridge.
  const files = ${filesJson};
  const filesEl = document.getElementById('files');
  if (files.length === 0) {
    document.querySelector('details.files').style.display = 'none';
  } else {
    filesEl.innerHTML = files
      .map(function (f) {
        // Defensive escaping: filenames are baked into the literal at
        // build time but pass through innerHTML, so escape control chars
        // anyway.
        return '<li>' + String(f).replace(/[&<>"']/g, function (c) {
          return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        }) + '</li>';
      })
      .join('');
  }

  const installBtn = document.getElementById('install');
  const cancelBtn = document.getElementById('cancel');
  const statusEl = document.getElementById('status');

  function setStatus(text, isError) {
    statusEl.textContent = text || '';
    statusEl.classList.toggle('error', !!isError);
  }
  function setLoading(loading) {
    if (loading) {
      installBtn.disabled = true;
      cancelBtn.disabled = true;
      setStatus('');
      statusEl.innerHTML = '<span class="spinner"></span>Waiting for the OS elevation prompt…';
    } else {
      installBtn.disabled = false;
      cancelBtn.disabled = false;
    }
  }

  cancelBtn.addEventListener('click', function () {
    window.close();
  });

  installBtn.addEventListener('click', function () {
    if (!window.electronAPI || !window.electronAPI.vpn || !window.electronAPI.vpn.installTapDriver) {
      setStatus('Bridge unavailable. Please relaunch rud1 and try again.', true);
      return;
    }
    setLoading(true);
    window.electronAPI.vpn.installTapDriver().then(function (res) {
      setLoading(false);
      if (res && res.ok) {
        setStatus('Driver installed. You can close this window and click Connect.', false);
        installBtn.textContent = 'Done';
        installBtn.classList.remove('primary');
        installBtn.addEventListener('click', function () { window.close(); }, { once: true });
        installBtn.disabled = false;
        cancelBtn.style.display = 'none';
      } else {
        setStatus((res && res.error) || 'The driver install was cancelled or failed.', true);
      }
    }, function (err) {
      setLoading(false);
      setStatus(err && err.message ? err.message : 'The driver install failed.', true);
    });
  });
</script>
</body>
</html>`;
  return "data:text/html;charset=utf-8," + encodeURIComponent(html);
}
