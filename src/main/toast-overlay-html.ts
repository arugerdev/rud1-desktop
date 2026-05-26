/**
 * Liquid Glass toast overlay — replaces the native OS notification stack
 * (Windows action center, macOS notification center) with an in-app
 * frameless transparent BrowserWindow that renders toasts in the same
 * pastel + glassmorphism language as the rest of rud1-desktop.
 *
 * Rendered inside a click-through always-on-top window pinned to the
 * top-right of the primary display. The window is owned by the main
 * process; this file only emits the HTML/CSS/JS shell.
 *
 * Communication contract:
 *   main → renderer (via webContents.send):
 *     - "toast:push"  payload: ToastDescriptor
 *     - "toast:dismiss"  payload: { id }
 *     - "toast:theme"  payload: { theme: "light" | "dark" }
 *   renderer → main (via ipcRenderer.send through preload bridge):
 *     - "toast:hover"  payload: { hovering: boolean }    (click-through gating)
 *     - "toast:user-dismiss"  payload: { id }            (X click)
 *     - "toast:action"  payload: { id, channel: string } (CTA click)
 */

export interface ToastOverlayHtmlOpts {
  /** Resolved theme. The shell only knows light/dark — "system" is
   *  resolved by the main process before rendering so the iframe never
   *  has to read prefers-color-scheme at runtime. */
  theme: "light" | "dark";
}

export function buildToastOverlayHtml(opts: ToastOverlayHtmlOpts): string {
  const themeAttr = ` data-theme="${opts.theme}"`;
  const html = `<!doctype html>
<html lang="en"${themeAttr}>
<head>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none';" />
<title>rud1 notifications</title>
<style>
  /* Tokens cloned from vpn-driver-install-html.ts. Keep in sync. */
  :root {
    color-scheme: light dark;

    --fg: #1a2030;
    --muted-fg: #6b7588;
    --surface: rgba(255, 255, 255, 0.78);
    --surface-strong: rgba(255, 255, 255, 0.92);
    --border: rgba(180, 195, 220, 0.55);
    --shadow: rgba(60, 80, 120, 0.22);

    --primary: #a8c4ff;
    --primary-accent: #86a8ff;
    --primary-soft: #e0eaff;
    --primary-fg: #122a55;

    --success: #b6e3c5;
    --success-soft: #dff5e6;
    --success-fg: #155a2a;
    --success-accent: #6dd17e;

    --warning: #f5b962;
    --warning-soft: #fde6c2;
    --warning-fg: #4a2d0a;

    --error: #f5a3a3;
    --error-soft: #fbdcdc;
    --error-fg: #5a1414;
    --error-accent: #d96a6a;
  }
  :root[data-theme="dark"] {
    --fg: #e6eaf2;
    --muted-fg: #93a0b8;
    --surface: rgba(28, 36, 50, 0.72);
    --surface-strong: rgba(28, 36, 50, 0.92);
    --border: rgba(120, 140, 175, 0.28);
    --shadow: rgba(0, 0, 0, 0.6);

    --primary: #86a8ff;
    --primary-accent: #a8c4ff;
    --primary-soft: rgba(168, 196, 255, 0.18);
    --primary-fg: #f0f4ff;

    --success: rgba(109, 209, 126, 0.5);
    --success-soft: rgba(109, 209, 126, 0.18);
    --success-fg: #c8f0d3;
    --success-accent: #6dd17e;

    --warning: rgba(245, 185, 98, 0.5);
    --warning-soft: rgba(245, 185, 98, 0.18);
    --warning-fg: #fde6c2;

    --error: rgba(245, 163, 163, 0.5);
    --error-soft: rgba(245, 163, 163, 0.18);
    --error-fg: #fbdcdc;
    --error-accent: #d96a6a;
  }

  * { box-sizing: border-box; }
  html, body {
    margin: 0;
    padding: 0;
    width: 100%;
    height: 100%;
    background: transparent;
    overflow: hidden;
    /* Whole document is click-through by default; toast cards re-enable
       pointer events. This works together with the main process's
       setIgnoreMouseEvents(true, { forward: true }) — the renderer
       still sees mouse-move events so it can ask main to flip
       click-through off when the cursor enters a toast. */
    pointer-events: none;
    font-family: -apple-system, "Segoe UI", "SF Pro Text", Inter, Roboto, sans-serif;
    -webkit-font-smoothing: antialiased;
    user-select: none;
    -webkit-user-select: none;
  }

  #stack {
    position: fixed;
    top: 18px;
    right: 18px;
    display: flex;
    flex-direction: column;
    gap: 10px;
    align-items: flex-end;
    max-width: 380px;
  }

  .toast {
    pointer-events: auto;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    backdrop-filter: blur(28px) saturate(180%);
    -webkit-backdrop-filter: blur(28px) saturate(180%);
    box-shadow: 0 10px 32px var(--shadow);
    color: var(--fg);
    padding: 14px 16px 12px 16px;
    width: 360px;
    min-height: 64px;
    opacity: 0;
    transform: translateX(110%);
    transition: transform 280ms cubic-bezier(0.16, 1, 0.3, 1),
                opacity 220ms ease,
                box-shadow 180ms ease;
    position: relative;
    overflow: hidden;
  }
  .toast.in {
    opacity: 1;
    transform: translateX(0);
  }
  .toast.out {
    opacity: 0;
    transform: translateX(110%);
  }
  .toast:hover {
    box-shadow: 0 14px 38px var(--shadow);
  }

  .toast .row {
    display: flex;
    align-items: flex-start;
    gap: 12px;
  }
  .toast .icon {
    flex: 0 0 28px;
    height: 28px;
    border-radius: 9px;
    background: var(--primary-soft);
    color: var(--primary-fg);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 14px;
    font-weight: 700;
    border: 1px solid var(--primary);
  }
  .toast.info  .icon { background: var(--primary-soft); color: var(--primary-fg); border-color: var(--primary); }
  .toast.success .icon { background: var(--success-soft); color: var(--success-fg); border-color: var(--success); }
  .toast.warning .icon { background: var(--warning-soft); color: var(--warning-fg); border-color: var(--warning); }
  .toast.error .icon { background: var(--error-soft); color: var(--error-fg); border-color: var(--error); }

  .toast .body { flex: 1; min-width: 0; }
  .toast .title {
    font-size: 13px;
    font-weight: 600;
    line-height: 1.3;
    margin: 0 0 2px 0;
    letter-spacing: -0.005em;
    overflow: hidden;
    text-overflow: ellipsis;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
  }
  .toast .desc {
    font-size: 12px;
    color: var(--muted-fg);
    line-height: 1.4;
    word-break: break-word;
    overflow: hidden;
    display: -webkit-box;
    -webkit-line-clamp: 4;
    -webkit-box-orient: vertical;
  }

  .toast .close {
    flex: 0 0 22px;
    height: 22px;
    border-radius: 7px;
    border: 1px solid transparent;
    background: transparent;
    color: var(--muted-fg);
    font-size: 16px;
    line-height: 1;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    transition: background 0.15s ease, color 0.15s ease;
  }
  .toast .close:hover {
    background: var(--surface-strong);
    color: var(--fg);
  }

  .toast .actions {
    margin-top: 10px;
    display: flex;
    gap: 8px;
    justify-content: flex-end;
  }
  .toast .actions button {
    background: var(--primary);
    color: var(--primary-fg);
    border: 1px solid var(--primary-accent);
    border-radius: 10px;
    padding: 6px 12px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s ease, transform 0.1s ease;
  }
  .toast .actions button:hover { background: var(--primary-accent); }
  .toast .actions button:active { transform: scale(0.97); }

  .toast .progress {
    position: absolute;
    left: 0;
    bottom: 0;
    height: 2px;
    background: var(--primary-accent);
    opacity: 0.7;
    width: 100%;
    transform-origin: left center;
    transform: scaleX(1);
    transition: transform linear;
  }
  .toast.success .progress { background: var(--success-accent); }
  .toast.warning .progress { background: var(--warning); }
  .toast.error   .progress { background: var(--error-accent); }
</style>
</head>
<body>
  <div id="stack" role="region" aria-label="rud1 notifications"></div>
<script>
  // ---- shared helpers ----
  function escapeText(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  // Tiny inline SVGs so we don't ship an icon library inside the data URL.
  function iconFor(kind) {
    switch (kind) {
      case "success":
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
      case "warning":
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>';
      case "error":
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
      default:
        return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    }
  }

  // ---- queue ----
  var stack = document.getElementById("stack");
  var toasts = new Map(); // id -> { el, timer, progressTimer }
  var MAX_VISIBLE = 5;

  function pushToast(t) {
    if (toasts.has(t.id)) return;
    // Evict oldest if over the visible limit.
    if (toasts.size >= MAX_VISIBLE) {
      var oldest = toasts.keys().next().value;
      if (oldest) removeToast(oldest);
    }
    var el = document.createElement("div");
    el.className = "toast " + (t.kind || "info");
    el.setAttribute("data-id", t.id);
    var actionHtml = "";
    if (t.action && t.action.label && t.action.channel) {
      actionHtml = '<div class="actions"><button data-channel="' + escapeText(t.action.channel) + '">' + escapeText(t.action.label) + '</button></div>';
    }
    el.innerHTML =
      '<div class="row">' +
        '<div class="icon">' + iconFor(t.kind || "info") + '</div>' +
        '<div class="body">' +
          '<p class="title">' + escapeText(t.title) + '</p>' +
          '<p class="desc">' + escapeText(t.body) + '</p>' +
          actionHtml +
        '</div>' +
        '<button class="close" aria-label="Dismiss">×</button>' +
      '</div>' +
      '<div class="progress" style="transform:scaleX(1)"></div>';

    stack.appendChild(el);

    // Trigger the entrance transition on the next frame so the initial
    // off-screen translate is committed first.
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        el.classList.add("in");
      });
    });

    var record = { el: el, timer: 0, progressTimer: 0 };
    toasts.set(t.id, record);

    var dwellMs = typeof t.autoDismissMs === "number" && t.autoDismissMs > 0
      ? t.autoDismissMs
      : 5500;
    if (dwellMs > 0 && dwellMs < 60000) {
      var progress = el.querySelector(".progress");
      if (progress) {
        progress.style.transition = "transform " + dwellMs + "ms linear";
        requestAnimationFrame(function () {
          progress.style.transform = "scaleX(0)";
        });
      }
      record.timer = window.setTimeout(function () { removeToast(t.id); }, dwellMs);
    }

    // Bind events.
    var closeBtn = el.querySelector(".close");
    if (closeBtn) {
      closeBtn.addEventListener("click", function () {
        if (window.rud1Bridge) window.rud1Bridge.userDismiss(t.id);
        removeToast(t.id);
      });
    }
    if (t.action && t.action.channel) {
      var actionBtn = el.querySelector(".actions button");
      if (actionBtn) {
        actionBtn.addEventListener("click", function () {
          if (window.rud1Bridge) window.rud1Bridge.fireAction(t.id, t.action.channel);
          removeToast(t.id);
        });
      }
    }
    el.addEventListener("mouseenter", function () { setHovering(true); });
    el.addEventListener("mouseleave", function () { setHovering(false); });
  }

  function removeToast(id) {
    var rec = toasts.get(id);
    if (!rec) return;
    toasts.delete(id);
    if (rec.timer) window.clearTimeout(rec.timer);
    rec.el.classList.remove("in");
    rec.el.classList.add("out");
    window.setTimeout(function () {
      if (rec.el.parentNode) rec.el.parentNode.removeChild(rec.el);
      if (toasts.size === 0 && window.rud1Bridge) {
        window.rud1Bridge.notifyEmpty();
      }
    }, 320);
  }

  // Hover state propagation so the main process can flip click-through.
  // We debounce a tick to coalesce rapid enter/leave when crossing
  // adjacent toasts.
  var hoverTimer = 0;
  var lastHovering = false;
  function setHovering(h) {
    if (hoverTimer) window.clearTimeout(hoverTimer);
    hoverTimer = window.setTimeout(function () {
      if (h !== lastHovering) {
        lastHovering = h;
        if (window.rud1Bridge) window.rud1Bridge.setHovering(h);
      }
    }, 30);
  }

  // ---- bridge ----
  // The preload script populates window.rud1Bridge with the IPC senders;
  // the receivers (push/dismiss/theme) come in via the main process.
  if (window.rud1Bridge && window.rud1Bridge.onPush) {
    window.rud1Bridge.onPush(function (t) { pushToast(t); });
  }
  if (window.rud1Bridge && window.rud1Bridge.onDismiss) {
    window.rud1Bridge.onDismiss(function (id) { removeToast(id); });
  }
  if (window.rud1Bridge && window.rud1Bridge.onTheme) {
    window.rud1Bridge.onTheme(function (theme) {
      document.documentElement.setAttribute("data-theme", theme === "dark" ? "dark" : "light");
    });
  }
</script>
</body>
</html>`;
  return "data:text/html;charset=utf-8," + encodeURIComponent(html);
}
