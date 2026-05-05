/**
 * rud1 Desktop — Settings/About panel HTML builder.
 *
 * The Settings panel is loaded as a `data:` URL in a sandboxed
 * BrowserWindow opened from the tray (see `showSettingsWindow` in
 * `index.ts`). The HTML is generated main-side because the renderer
 * has no network access (CSP `default-src 'none'`) and cannot fetch
 * its own template — we hand it everything as a single inline blob.
 *
 * ─── History ──────────────────────────────────────────────────────
 *   iter 37 — initial Settings/About panel (formatters + DOM mapping)
 *   iter 41 — bridgeSha256 surface + copy-hash button
 *   iter 42 — "Copy diagnostics" envelope on the blocked verdict
 *   iter 43 — extend "Copy diagnostics" to the three non-blocked
 *             verdicts (up-to-date / update-available / error)
 *   iter 44 — thread app.getVersion() into the inline JS as APP_VERSION
 *             so the error-verdict rebuild carries currentVersion
 *   iter 45 — extend the APP_VERSION read to blocked + update-available
 *             inline rebuilds; thread runtimeAppVersion through the
 *             two helpers in version-check-manager.ts
 *   iter 46 — extract `buildSettingsWindowHtml` into this dedicated
 *             file so it's importable from the test suite without
 *             pulling in `index.ts`'s Electron lifecycle side-effects;
 *             add a thin `buildSettingsWindowHtmlWithRuntimeVersion`
 *             wrapper so callers can't forget to pass app.getVersion()
 *   iter 54 — surface the iter-53 `signedDataMode` label as a small
 *             chip on the sig-fetch blocked verdict; same chip text
 *             as `formatBlockedStateMessage` produces for the inline
 *             banner so operators see the publisher-convention label
 *             without copying out the support-blob JSON
 */

/**
 * Build the Settings/About panel HTML.
 *
 * `currentVersion` is JSON-encoded into the inline script as a
 * top-level `APP_VERSION` constant. The renderer-side "Copy
 * diagnostics" rebuilds for all three verdicts (`error`, `blocked`,
 * `update-available`) read it preferentially over the corresponding
 * state field — same defensive `typeof + length>0` guard used by
 * the iter-45 `runtimeAppVersion` overrides on the helpers in
 * `version-check-manager.ts` (`buildBlockedDiagnosticsBlob` /
 * `buildUpdateAvailableDiagnosticsBlob`) and the iter-44 thread on
 * `buildErrorDiagnosticsBlob` (which sources `currentVersion` from
 * `state.current ?? null`).
 *
 * Returns a `data:text/html;charset=utf-8,…` URL ready for
 * `BrowserWindow.loadURL`.
 *
 * Iter 46 — most callers should prefer
 * `buildSettingsWindowHtmlWithRuntimeVersion` so the runtime
 * version override is wired in by name rather than by passing
 * `app.getVersion()` positionally.
 */
export function buildSettingsWindowHtml(currentVersion: string): string {
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
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none';" />
<title>rud1 — Settings & About</title>
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

    --primary: #6db3f5;
    --primary-soft: #d0e8ff;
    --primary-fg: #0d2540;

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
    --link: #3a86c4;
    --link-hover: #1f6eaa;

    /* Mesh tints — light */
    --mesh-1: rgba(189, 219, 255, 0.55);
    --mesh-2: rgba(228, 207, 255, 0.5);
    --mesh-3: rgba(196, 240, 224, 0.45);
    --mesh-4: rgba(255, 226, 197, 0.45);
  }

  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0a0e17;
      --fg: #e6eaf2;
      --muted-fg: #93a0b8;
      --surface: rgba(28, 36, 50, 0.55);
      --surface-strong: rgba(28, 36, 50, 0.78);
      --edge: rgba(180, 200, 230, 0.12);
      --border: rgba(120, 140, 175, 0.22);
      --shadow: rgba(0, 0, 0, 0.55);

      --primary: #92c8ff;
      --primary-soft: rgba(110, 172, 230, 0.32);
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
      --link: #92c8ff;
      --link-hover: #c8e2ff;

      /* Mesh tints — dark */
      --mesh-1: rgba(40, 80, 130, 0.4);
      --mesh-2: rgba(80, 60, 130, 0.36);
      --mesh-3: rgba(40, 110, 95, 0.32);
      --mesh-4: rgba(130, 80, 50, 0.32);
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
</style>
</head>
<body>
  <h1>Settings &amp; About</h1>
  <p class="muted">rud1 desktop — operator controls and update status.</p>

  <h2>Updates</h2>
  <div id="updates"><p class="muted">Loading…</p></div>

  <h2>First-boot notifications</h2>
  <p class="muted">Manage hosts the desktop app has already notified you about.</p>
  <div class="actions">
    <button id="open-dedupe">Open notified-hosts inspector…</button>
  </div>

  <div id="toast" class="toast" aria-live="polite"></div>

<script>
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
    var banner = 'Download v' + escape(state.requiredMinVersion) + ' manually first to continue receiving updates';
    var notes = state.releaseNotesUrl
      ? '<p><a id="rn-link">What\\'s new — view release notes</a></p>'
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
      ? '<div class="row"><span class="k">Expected SHA-256</span>' +
          '<span class="v"><code class="hash" id="bridge-hash">' + escape(hashHex) + '</code></span>' +
        '</div>'
      : '';
    var hashHelp = hashHex
      ? '<p class="muted hash-help" id="bridge-hash-help">' +
          'Verify hash before running installer — ' +
          '<code>Get-FileHash -Algorithm SHA256 &lt;file&gt;</code> on Windows or ' +
          '<code>shasum -a 256 &lt;file&gt;</code> on macOS / Linux.' +
        '</p>'
      : '';
    var hashBtn = hashHex
      ? '<button id="copy-hash" aria-describedby="bridge-hash-help">Copy expected sha256</button>'
      : '';
    updatesEl.innerHTML =
      '<div class="banner">' + banner + '</div>' +
      '<div class="summary">' +
        '<div class="row"><span class="k">Currently installed</span><span class="v">v' + escape(state.currentVersion) + '</span></div>' +
        '<div class="row"><span class="k">Target version</span><span class="v">v' + escape(state.targetVersion) + '</span></div>' +
        '<div class="row"><span class="k">Required intermediate</span><span class="v">v' + escape(state.requiredMinVersion) + '</span></div>' +
        hashRow +
      '</div>' +
      hashHelp +
      notes +
      '<div class="actions">' +
        '<button id="copy-url" class="primary"' + (hashHex ? ' aria-describedby="bridge-hash-help"' : '') + '>Copy download URL</button>' +
        hashBtn +
        // Iter 42 — copy a JSON diagnostics envelope (capturedAt + all
        // blocked-state fields + resolved download URL via pickDownloadUrl
        // precedence) for support tickets. Mirrors the rud1-app iter-42
        // pattern on the AuditForwardStatusCard. Always rendered: the
        // envelope is always meaningful (versions are guaranteed
        // populated by parseManifest) regardless of optional fields.
        '<button id="copy-diagnostics">Copy diagnostics</button>' +
        '<button id="recheck">Check for updates now</button>' +
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
        if (/[\x00-\x1f\x7f\s"<>\\^\`{|}]/.test(u)) return false;
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
        if (res && res.ok) toast('Copied download URL to clipboard');
        else toast('Copy failed: ' + (res && res.error ? res.error : 'unknown'));
      });
    });
    if (hashHex) {
      document.getElementById('copy-hash').addEventListener('click', function() {
        window.electronAPI.clipboard.writeText(hashHex).then(function(res) {
          if (res && res.ok) toast('Copied expected sha256 to clipboard');
          else toast('Copy failed: ' + (res && res.error ? res.error : 'unknown'));
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
        if (/[\x00-\x1f\x7f\s"<>\\^\`{|}]/.test(u)) return false;
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
        if (/[\x00-\x1f\x7f\s"<>\\^\`{|}]/.test(u)) return false;
        try {
          var p = new URL(u);
          var pr = (p.protocol || '').toLowerCase();
          if (pr === 'javascript:' || pr === 'data:') return false;
          if (pr !== 'http:' && pr !== 'https:') return false;
          if (p.username !== '' || p.password !== '') return false;
          return /\.(sig|minisig|asc)$/i.test(p.pathname);
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
        if (res && res.ok) toast('Copied diagnostics to clipboard');
        else toast('Copy failed: ' + (res && res.error ? res.error : 'unknown'));
      });
    });
    document.getElementById('recheck').addEventListener('click', function() {
      window.electronAPI.versionCheck.recheck();
      toast('Re-checking for updates…');
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
    var banner = 'Update blocked: signature could not be verified (' + escape(reason) + ')';
    var sigRow = state.signatureUrl
      ? '<div class="row"><span class="k">Signature URL</span>' +
          '<span class="v"><code>' + escape(state.signatureUrl) + '</code></span></div>'
      : '';
    var statusRow = (typeof state.httpStatus === 'number')
      ? '<div class="row"><span class="k">HTTP status</span><span class="v">' + escape(state.httpStatus) + '</span></div>'
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
      ? '<p><a id="rn-link">What\\'s new — view release notes</a></p>'
      : '';
    updatesEl.innerHTML =
      '<div class="banner">' + banner + '</div>' +
      '<div class="summary">' +
        '<div class="row"><span class="k">Currently installed</span><span class="v">v' + escape(state.currentVersion) + '</span></div>' +
        '<div class="row"><span class="k">Target version</span><span class="v">v' + escape(state.targetVersion) + '</span></div>' +
        '<div class="row"><span class="k">Reason</span><span class="v">' + escape(reason) + '</span></div>' +
        sigRow +
        statusRow +
        chipRow +
      '</div>' +
      notes +
      '<div class="actions">' +
        '<button id="copy-diagnostics">Copy diagnostics</button>' +
        '<button id="recheck">Check for updates now</button>' +
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
        if (/[\x00-\x1f\x7f\s"<>\\^\`{|}]/.test(u)) return false;
        try {
          var p = new URL(u);
          var pr = (p.protocol || '').toLowerCase();
          if (pr === 'javascript:' || pr === 'data:') return false;
          if (pr !== 'http:' && pr !== 'https:') return false;
          if (p.username !== '' || p.password !== '') return false;
          return /\.(sig|minisig|asc)$/i.test(p.pathname);
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
        if (res && res.ok) toast('Copied diagnostics to clipboard');
        else toast('Copy failed: ' + (res && res.error ? res.error : 'unknown'));
      });
    });
    document.getElementById('recheck').addEventListener('click', function() {
      window.electronAPI.versionCheck.recheck();
      toast('Re-checking for updates…');
    });
    if (state.releaseNotesUrl) {
      document.getElementById('rn-link').addEventListener('click', function() {
        window.electronAPI.shell.openExternal(state.releaseNotesUrl);
      });
    }
  }

  function renderState(state) {
    if (!state) {
      updatesEl.innerHTML = '<p class="muted">Update status unavailable.</p>';
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
    if (state.kind === 'idle') summary = 'Update check has not run yet.';
    else if (state.kind === 'checking') summary = 'Checking for updates…';
    else if (state.kind === 'up-to-date') {
      summary = 'Up to date (v' + escape(state.current) + ').';
      bannerCls = 'ok';
    }
    else if (state.kind === 'update-available') {
      summary = 'Update available — v' + escape(state.latest) + ' (currently v' + escape(state.current) + ').';
      bannerCls = 'warn';
    }
    else if (state.kind === 'error') summary = "Couldn't check for updates: " + escape(state.message);
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
      ? '<button id="copy-diagnostics">Copy diagnostics</button>'
      : '';
    updatesEl.innerHTML = banner +
      '<div class="actions">' +
        diagBtn +
        '<button id="recheck">Check for updates now</button>' +
      '</div>';
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
            if (/[\x00-\x1f\x7f\s"<>\\^\`{|}]/.test(u)) return false;
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
            if (/[\x00-\x1f\x7f\s"<>\\^\`{|}]/.test(u)) return false;
            try {
              var p = new URL(u);
              var pr = (p.protocol || '').toLowerCase();
              if (pr === 'javascript:' || pr === 'data:') return false;
              if (pr !== 'http:' && pr !== 'https:') return false;
              if (p.username !== '' || p.password !== '') return false;
              return /\.(sig|minisig|asc)$/i.test(p.pathname);
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
          if (res && res.ok) toast('Copied diagnostics to clipboard');
          else toast('Copy failed: ' + (res && res.error ? res.error : 'unknown'));
        });
      });
    }
    document.getElementById('recheck').addEventListener('click', function() {
      window.electronAPI.versionCheck.recheck();
      toast('Re-checking for updates…');
    });
  }

  // Initial fetch + subscribe to push updates from main.
  window.electronAPI.versionCheck.state().then(function(res) {
    if (res && res.ok) renderState(res.result);
    else renderState(null);
  });
  if (typeof window.electronAPI.versionCheck.onUpdate === 'function') {
    window.electronAPI.versionCheck.onUpdate(function(state) { renderState(state); });
  }

  // Dedupe inspector launcher — this just opens the existing iter-28
  // window. There is no IPC for "open dedupe inspector" today, so we
  // fall back to listing + offering a hint if the inspector isn't
  // accessible from here.
  document.getElementById('open-dedupe').addEventListener('click', function() {
    // No direct IPC: surface a hint that the inspector is on the tray
    // submenu. This is honest about the iter-28 boundary without
    // pretending we can launch it from a sibling panel.
    toast('Open from the tray menu → First-boot notifications');
  });
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
): string {
  return buildSettingsWindowHtml(runtimeAppVersion);
}
