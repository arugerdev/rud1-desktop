/**
 * Version-check manager (iter 29).
 *
 * Lightweight nudge: the desktop app currently has no self-update flow.
 * This manager fetches a JSON manifest from a configured HTTPS URL,
 * compares the advertised `version` against `app.getVersion()` using the
 * existing semver helpers in `auto-updater.ts`, and surfaces an "Update
 * available" affordance via a callback. Wiring lives in `index.ts` —
 * the manager is pure plumbing so it can be unit-tested without the
 * Electron runtime.
 *
 * Design choices, briefly:
 *   • The full electron-updater download/install flow is intentionally
 *     out of scope here. Until we ship signed builds with a release
 *     channel we just let the operator click through to the published
 *     download page; the autoUpdater plumbing in `auto-updater.ts`
 *     stays parked behind feature flags for future activation.
 *   • The manifest URL and current version are injected so tests don't
 *     have to monkey-patch `app.getVersion()` or stub `fetch`.
 *   • `checkOnce` is a single-shot fetch + compare. The schedule is
 *     applied by `start()` which runs an immediate check then sets a
 *     `setInterval`. We never retry on failure — a transient outage
 *     simply leaves `state.kind = "error"` until the next tick fires
 *     successfully.
 *   • All inputs from the network are validated: the URL must be
 *     HTTPS (matches `auto-updater.ts` policy), the response body must
 *     be a small JSON object, and the version string runs through
 *     `parseSemver` before comparison. A malformed manifest never
 *     promotes the state out of "error".
 */

import { __test as autoUpdaterInternals, type AutoUpdateState } from "./auto-updater";

const { isValidFeedUrl, parseSemver, isNewerVersion } = autoUpdaterInternals;

// Hard cap on the body we'll read from the manifest URL. A well-formed
// release feed is a few hundred bytes; anything bigger is almost
// certainly a misconfiguration (or an attempt to OOM the app).
const MAX_MANIFEST_BYTES = 16 * 1024;

// Default poll cadence. Hourly is plenty — release announcements aren't
// time-critical, and we want to be invisible on the network. Caller can
// override.
const DEFAULT_INTERVAL_MS = 60 * 60 * 1000;

// Per-fetch timeout. Short enough that a stuck CDN doesn't block app
// shutdown, long enough that a slow phone tether still completes.
const DEFAULT_FETCH_TIMEOUT_MS = 5_000;

export type VersionCheckState =
  | { kind: "idle" }
  | { kind: "checking" }
  | { kind: "up-to-date"; current: string; latest: string; checkedAt: number }
  | {
      kind: "update-available";
      current: string;
      latest: string;
      downloadUrl: string | null;
      checkedAt: number;
    }
  | { kind: "error"; message: string; checkedAt: number };

export interface VersionCheckOptions {
  /** HTTPS URL of the manifest. */
  manifestUrl: string;
  /** Current app version (semver). Usually `app.getVersion()`. */
  currentVersion: string;
  /** Poll interval in ms. Defaults to 1 hour. */
  intervalMs?: number;
  /** Per-fetch timeout in ms. Defaults to 5 s. */
  fetchTimeoutMs?: number;
  /**
   * Injected fetch — defaults to `globalThis.fetch`. Overridable so
   * tests can return a stubbed manifest without spinning up an HTTP
   * server.
   */
  fetch?: typeof globalThis.fetch;
  /**
   * Listener invoked on every state transition. The tray uses this to
   * rebuild the menu. Errors thrown by the listener are swallowed so a
   * misbehaving subscriber can't kill the polling loop.
   */
  onStateChange?: (state: VersionCheckState) => void;
}

export interface VersionManifest {
  /** Latest published version (semver). */
  version: string;
  /** Optional URL for the operator to follow. */
  downloadUrl?: string | null;
}

/**
 * Validates the parsed JSON body. Returns null when the shape is wrong;
 * we never throw because the caller treats a malformed manifest as a
 * recoverable error and keeps polling.
 */
export function parseManifest(raw: unknown): VersionManifest | null {
  if (raw == null || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  if (typeof obj.version !== "string" || obj.version.length === 0) return null;
  if (parseSemver(obj.version) == null) return null;
  let downloadUrl: string | null = null;
  if (typeof obj.downloadUrl === "string" && obj.downloadUrl.length > 0) {
    // Re-use the auto-updater allowlist so a malicious manifest can't
    // smuggle e.g. javascript: or file: URLs through to the tray menu.
    if (isValidFeedUrl(obj.downloadUrl)) downloadUrl = obj.downloadUrl;
    // else: silently drop — we'd rather show "update available" without
    // a clickable link than send the operator to an unsafe URL.
  }
  return { version: obj.version, downloadUrl };
}

/**
 * Pure helper: given a current + remote semver string, return the next
 * VersionCheckState as if the fetch just succeeded. Exposed so tests
 * can pin the comparison without mocking `fetch`.
 */
export function classifyManifest(
  current: string,
  manifest: VersionManifest,
  now: number,
): VersionCheckState {
  if (parseSemver(current) == null) {
    return {
      kind: "error",
      message: "current version is not valid semver",
      checkedAt: now,
    };
  }
  if (isNewerVersion(manifest.version, current)) {
    return {
      kind: "update-available",
      current,
      latest: manifest.version,
      downloadUrl: manifest.downloadUrl ?? null,
      checkedAt: now,
    };
  }
  return {
    kind: "up-to-date",
    current,
    latest: manifest.version,
    checkedAt: now,
  };
}

/**
 * VersionCheckManager — encapsulates the timer + last-known state and
 * exposes a small API the main process can call from the tray + IPC.
 */
export class VersionCheckManager {
  private state: VersionCheckState = { kind: "idle" };
  private timer: NodeJS.Timeout | null = null;
  private readonly opts: Required<
    Pick<VersionCheckOptions, "manifestUrl" | "currentVersion" | "intervalMs" | "fetchTimeoutMs">
  > & {
    fetch: typeof globalThis.fetch;
    onStateChange: (s: VersionCheckState) => void;
  };

  constructor(options: VersionCheckOptions) {
    if (!isValidFeedUrl(options.manifestUrl)) {
      // Surface this as a permanent error rather than a throw so the
      // tray still shows the "couldn't check" entry — easier for the
      // operator to debug than a silent no-op.
      this.state = {
        kind: "error",
        message: "invalid manifest URL",
        checkedAt: Date.now(),
      };
    }
    if (parseSemver(options.currentVersion) == null) {
      this.state = {
        kind: "error",
        message: "current version is not valid semver",
        checkedAt: Date.now(),
      };
    }
    this.opts = {
      manifestUrl: options.manifestUrl,
      currentVersion: options.currentVersion,
      intervalMs: options.intervalMs ?? DEFAULT_INTERVAL_MS,
      fetchTimeoutMs: options.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS,
      fetch: options.fetch ?? (globalThis.fetch?.bind(globalThis) as typeof globalThis.fetch),
      onStateChange: options.onStateChange ?? (() => {}),
    };
  }

  /**
   * Returns a snapshot of the current state. Cheap; never blocks.
   */
  getState(): VersionCheckState {
    return this.state;
  }

  /**
   * Performs one check + notifies subscribers. Returns the new state.
   * Safe to call concurrently; overlapping fetches just race to the
   * same final state, and the late winner overwrites the early one.
   */
  async checkOnce(): Promise<VersionCheckState> {
    if (this.state.kind === "error" && this.state.message === "invalid manifest URL") {
      this.notify();
      return this.state;
    }
    this.transition({ kind: "checking" });
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.opts.fetchTimeoutMs);
    try {
      const res = await this.opts.fetch(this.opts.manifestUrl, {
        method: "GET",
        signal: ctrl.signal,
        headers: { Accept: "application/json" },
      });
      if (!res.ok) {
        return this.transition({
          kind: "error",
          message: `manifest HTTP ${res.status}`,
          checkedAt: Date.now(),
        });
      }
      // Read with a hard byte cap so a misconfigured CDN can't OOM us.
      const text = await readBodyCapped(res, MAX_MANIFEST_BYTES);
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        return this.transition({
          kind: "error",
          message: "manifest is not valid JSON",
          checkedAt: Date.now(),
        });
      }
      const manifest = parseManifest(parsed);
      if (!manifest) {
        return this.transition({
          kind: "error",
          message: "manifest shape rejected",
          checkedAt: Date.now(),
        });
      }
      return this.transition(
        classifyManifest(this.opts.currentVersion, manifest, Date.now()),
      );
    } catch (e) {
      const err = e as Error;
      const msg = err?.name === "AbortError" ? "fetch timed out" : err?.message || "fetch failed";
      return this.transition({
        kind: "error",
        message: msg,
        checkedAt: Date.now(),
      });
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Kicks off an immediate check and schedules the recurring one. Safe
   * to call multiple times — additional calls reset the schedule.
   */
  start(): void {
    this.stop();
    void this.checkOnce();
    this.timer = setInterval(() => {
      void this.checkOnce();
    }, this.opts.intervalMs);
    if (typeof this.timer.unref === "function") this.timer.unref();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private transition(next: VersionCheckState): VersionCheckState {
    this.state = next;
    this.notify();
    return next;
  }

  private notify(): void {
    try {
      this.opts.onStateChange(this.state);
    } catch {
      // Subscribers must not break the polling loop.
    }
  }
}

/**
 * Read at most `cap` bytes from the response body. The fetch API's
 * `Response.body` is a ReadableStream; we accumulate chunks and bail
 * out as soon as we exceed the cap. `Response.text()` would buffer the
 * whole body unconditionally — fine for trusted sources, not for an
 * arbitrary URL we follow at app launch.
 */
async function readBodyCapped(res: Response, cap: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) {
    // Some implementations (e.g. older undici stubs) don't expose a
    // streamed body. Fall back to text() but enforce the cap on the
    // resulting string — defensive only, both stub paths under our
    // control return small bodies.
    const text = await res.text();
    if (text.length > cap) {
      throw new Error("manifest exceeds size cap");
    }
    return text;
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.length;
    if (total > cap) {
      try {
        await reader.cancel();
      } catch {
        // best-effort
      }
      throw new Error("manifest exceeds size cap");
    }
    chunks.push(value);
  }
  // TextDecoder defaults to UTF-8 which matches any sane manifest.
  return new TextDecoder().decode(concat(chunks));
}

function concat(parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ─── Tray menu builder (iter 29 + iter 30) ──────────────────────────────────
//
// `buildVersionCheckMenuItems` returns the rows the system-tray menu
// renders for the update slot. Iter 29 covered the basic states
// (idle/checking/up-to-date/update-available/error); iter 30 layers in
// the optional auto-update flow on top:
//
//   • `auto.kind === "downloading"`     — a disabled "Downloading update… NN%"
//                                         row with progress in the sublabel
//   • `auto.kind === "ready-to-apply"`  — "Download ready — Restart to install"
//                                         click → handlers.applyAndRestart
//   • `auto.kind === "error"`           — "Update download failed: …" with
//                                         retry that re-runs the version check
//
// When `auto` is null/undefined or `kind === "idle"` we render the iter-29
// rows verbatim so the existing test suite keeps passing.
//
// `handlers` are click callbacks injected by the caller — the function
// stays pure (no electron imports beyond the type) so the unit suite
// can pin the labels and click semantics without spawning a tray.

export interface VersionCheckMenuHandlers {
  /** Open the published download URL in the system browser. */
  openExternal?: (url: string) => void;
  /** Trigger an immediate version-check refetch. */
  recheck?: () => void;
  /** Start an in-app background download (iter 30 auto-update). */
  startDownload?: (url: string, sha256: string | null) => void;
  /** Apply the staged download + restart (iter 30 auto-update). */
  applyAndRestart?: () => void;
  /** Reset auto-update state after an error (iter 30 auto-update). */
  resetAutoUpdate?: () => void;
}

export interface MenuItemShape {
  label: string;
  enabled?: boolean;
  click?: () => void;
  sublabel?: string;
}

/**
 * Build the version-check menu rows. Pure: no electron imports.
 *
 * `auto` is the iter-30 auto-update state. Pass `undefined` (or omit) to
 * render the iter-29 rows unchanged — the original 5-state behaviour.
 *
 * `manifestSha256` is captured from the manifest (when present) and
 * threaded to `startDownload` so `applyAndRestart` can verify the
 * artifact before launching the installer.
 */
export function buildVersionCheckMenuItems(
  state: VersionCheckState,
  handlers: VersionCheckMenuHandlers = {},
  auto?: AutoUpdateState,
  manifestSha256?: string | null,
): MenuItemShape[] {
  // Iter 30 — when an auto-update flow is in progress, the rows for
  // it take priority over the iter-29 verdict (the operator wants
  // status on the running download, not "v1.4 is available" again).
  if (auto && auto.kind === "downloading") {
    const pct = auto.totalBytes && auto.totalBytes > 0
      ? Math.min(100, Math.floor((auto.bytesReceived / auto.totalBytes) * 100))
      : null;
    const label = pct != null
      ? `Downloading update… ${pct}%`
      : `Downloading update… ${formatBytes(auto.bytesReceived)}`;
    return [{ label, enabled: false, sublabel: progressBar(pct) }];
  }
  if (auto && auto.kind === "ready-to-apply") {
    return [
      {
        label: "Download ready — Restart to install",
        click: () => { handlers.applyAndRestart?.(); },
      },
    ];
  }
  if (auto && auto.kind === "error") {
    return [
      {
        label: `Update download failed: ${auto.message}`,
        enabled: false,
      },
      {
        label: "Reset and retry update check",
        click: () => {
          handlers.resetAutoUpdate?.();
          handlers.recheck?.();
        },
      },
    ];
  }
  // Iter 29 baseline — `auto` is idle or absent.
  if (state.kind === "idle" || state.kind === "checking") return [];
  if (state.kind === "update-available") {
    const url = state.downloadUrl;
    const isAuto = auto != null;
    return [
      {
        label: `▲ Update available — v${state.latest}`,
        click: () => {
          if (!url) return;
          if (isAuto && handlers.startDownload) {
            handlers.startDownload(url, manifestSha256 ?? null);
          } else {
            handlers.openExternal?.(url);
          }
        },
        enabled: url != null,
      },
      {
        label: `Currently installed: v${state.current}`,
        enabled: false,
      },
      {
        label: "Check for updates now",
        click: () => { handlers.recheck?.(); },
      },
    ];
  }
  if (state.kind === "up-to-date") {
    return [
      {
        label: `Up to date (v${state.current})`,
        enabled: false,
      },
      {
        label: "Check for updates now",
        click: () => { handlers.recheck?.(); },
      },
    ];
  }
  // error
  return [
    {
      label: `Couldn't check for updates: ${state.message}`,
      enabled: false,
    },
    {
      label: "Retry update check",
      click: () => { handlers.recheck?.(); },
    },
  ];
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function progressBar(pct: number | null): string {
  if (pct == null) return "";
  const filled = Math.max(0, Math.min(20, Math.floor(pct / 5)));
  return "[" + "#".repeat(filled) + "-".repeat(20 - filled) + `] ${pct}%`;
}

// Test-only hatch — mirrors the convention in auto-updater.ts.
export const __test = {
  parseManifest,
  classifyManifest,
  readBodyCapped,
  MAX_MANIFEST_BYTES,
  formatBytes,
  progressBar,
};
