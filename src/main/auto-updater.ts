/**
 * Auto-updater manager (iter 21).
 *
 * Thin wrapper over `electron-updater`'s `autoUpdater` singleton. The
 * feed URL, release channel, and any version strings that reach us from
 * the feed are treated as untrusted: a compromised update server could
 * otherwise induce the app to auto-install arbitrary payloads, and a
 * malicious IPC caller could flip the channel to a staging feed. All
 * inputs that cross a trust boundary run through the validators in
 * `__test` before anything touches `electron-updater`.
 *
 * Scope:
 *   • isValidFeedUrl        — allowlist-style URL validator; only https://
 *     with a bare host, no userinfo, no control characters, no shell
 *     metacharacters in the path.
 *   • isValidChannel        — allowlist of release channel names
 *     ("latest", "beta", "alpha"). Anything else is rejected.
 *   • parseSemver / compareSemver — best-effort semver parsing used to
 *     decide whether a remote "latest" is actually newer than the
 *     currently-installed app. electron-updater does its own comparison
 *     internally; ours is a defensive cross-check used by `isNewerVersion`
 *     so we never surface a "downgrade available" dialog.
 *   • isNewerVersion        — pure predicate used by the renderer-facing
 *     status handler.
 *
 * Runtime wiring (registerAutoUpdater / checkForUpdates) is intentionally
 * minimal: we delegate the actual download + staged install to
 * electron-updater. The test suite covers the validators + version logic
 * directly and uses `it.todo` for the event-emitter chain, matching the
 * pattern established in iter 17–20.
 */

// The `autoUpdater` import is lazy: importing `electron-updater` at module
// load time pulls in `electron.app` which is not available in a plain
// Node vitest run. We only touch it from `registerAutoUpdater`, which is
// called from the main process after `app.whenReady()`.
type ElectronUpdaterLike = {
  autoDownload: boolean;
  allowPrerelease: boolean;
  channel: string | null;
  setFeedURL: (opts: { provider: "generic"; url: string; channel?: string }) => void;
  checkForUpdates: () => Promise<unknown>;
  on: (event: string, listener: (...args: unknown[]) => void) => void;
};

const ALLOWED_CHANNELS = ["latest", "beta", "alpha"] as const;
type Channel = (typeof ALLOWED_CHANNELS)[number];

// A conservative host charset: ASCII letters/digits, dots, hyphens. No
// userinfo (`user:pass@host`), no IP-literal brackets, no port-component
// validation — electron-updater parses the URL itself and will refuse
// non-HTTPS in signed builds. Our guard is a belt-and-braces pre-filter.
const HOST_REGEX = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i;

// Path + query charset: URL-safe characters only. Reject control chars,
// whitespace, backslash, and the classic shell metacharacters. A feed URL
// is embedded verbatim in HTTP requests — never in a shell — but we
// defence-in-depth anyway in case a future refactor logs it through
// execFile (see vpn-manager iter 19).
const UNSAFE_PATH_CHARS = /[\s\\`$;&|<>"'(){}[\]]/;

/**
 * Allowlist validator for an update feed URL.
 *
 * Rules:
 *   • must parse as a URL
 *   • protocol must be exactly `https:` — plain http would let a MITM
 *     attacker swap the update manifest; `file://` / `javascript:` etc.
 *     are obviously forbidden.
 *   • no `userinfo` component (e.g. `https://user:pass@evil/`) — those
 *     can be used to smuggle credentials or to bypass hostname checks
 *     in some URL parsers.
 *   • hostname must match HOST_REGEX (ASCII letters/digits, dots, hyphens)
 *   • path + search must not contain control characters, whitespace,
 *     backslash, or shell metacharacters.
 *   • hash fragment is not allowed (feed URLs don't use them; an
 *     unexpected `#` is probably an injection attempt).
 */
function isValidFeedUrl(input: unknown): input is string {
  if (typeof input !== "string" || input.length === 0) return false;
  if (input.length > 2048) return false; // hard cap — feed URLs are short
  // Check the RAW input for unsafe characters BEFORE the URL parser
  // canonicalises them away. The WHATWG URL parser silently
  // percent-encodes backticks / quotes / spaces and even rewrites
  // backslashes to forward slashes — that canonicalisation would
  // otherwise hide shell metacharacters from the post-parse guard.
  if (UNSAFE_PATH_CHARS.test(input)) return false;
  let u: URL;
  try {
    u = new URL(input);
  } catch {
    return false;
  }
  if (u.protocol !== "https:") return false;
  if (u.username !== "" || u.password !== "") return false;
  if (u.hash !== "") return false;
  if (!u.hostname || !HOST_REGEX.test(u.hostname)) return false;
  // Disallow trailing dot ("example.com.") and empty labels ("a..b").
  if (u.hostname.endsWith(".") || u.hostname.includes("..")) return false;
  const pathAndQuery = u.pathname + u.search;
  if (UNSAFE_PATH_CHARS.test(pathAndQuery)) return false;
  // Must not contain percent-encoded CR/LF — header-injection shape.
  if (/%0[aAdD]/.test(pathAndQuery)) return false;
  return true;
}

function assertFeedUrl(input: unknown): asserts input is string {
  if (!isValidFeedUrl(input)) throw new Error("invalid feed URL");
}

function isValidChannel(input: unknown): input is Channel {
  return (
    typeof input === "string" &&
    (ALLOWED_CHANNELS as readonly string[]).includes(input)
  );
}

export interface Semver {
  major: number;
  minor: number;
  patch: number;
  // Empty string means "stable release" (no prerelease tag).
  prerelease: string;
}

/**
 * Minimal semver parser. Accepts `MAJOR.MINOR.PATCH` with an optional
 * `-PRERELEASE` suffix; ignores build metadata after `+`. Returns null
 * on anything that doesn't match — we'd rather refuse to compare than
 * guess.
 */
function parseSemver(input: unknown): Semver | null {
  if (typeof input !== "string") return null;
  // Strip a leading `v` (some release tags use `v1.2.3`).
  const stripped = input.startsWith("v") ? input.slice(1) : input;
  // Drop build metadata (`+sha`) — irrelevant for ordering.
  const noBuild = stripped.split("+", 1)[0]!;
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(noBuild);
  if (!m) return null;
  const [, maj, min, pat, pre] = m;
  const major = Number(maj);
  const minor = Number(min);
  const patch = Number(pat);
  if (!Number.isFinite(major) || !Number.isFinite(minor) || !Number.isFinite(patch)) return null;
  return { major, minor, patch, prerelease: pre ?? "" };
}

/**
 * Returns negative if `a < b`, zero if equal, positive if `a > b`.
 * Follows semver 2.0 precedence: prerelease versions rank below the
 * matching release, and prerelease identifiers compare numerically when
 * both are numeric, lexically otherwise.
 */
function compareSemver(a: Semver, b: Semver): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;
  // Same MAJOR.MINOR.PATCH: a release outranks a prerelease.
  if (a.prerelease === "" && b.prerelease === "") return 0;
  if (a.prerelease === "") return 1; // release > prerelease
  if (b.prerelease === "") return -1;
  const aParts = a.prerelease.split(".");
  const bParts = b.prerelease.split(".");
  const len = Math.max(aParts.length, bParts.length);
  for (let i = 0; i < len; i++) {
    const ap = aParts[i];
    const bp = bParts[i];
    // A shorter identifier list with equal prefix ranks lower.
    if (ap === undefined) return -1;
    if (bp === undefined) return 1;
    const aNum = /^\d+$/.test(ap) ? Number(ap) : null;
    const bNum = /^\d+$/.test(bp) ? Number(bp) : null;
    if (aNum !== null && bNum !== null) {
      if (aNum !== bNum) return aNum - bNum;
    } else if (aNum !== null) {
      return -1; // numeric < non-numeric per semver
    } else if (bNum !== null) {
      return 1;
    } else {
      if (ap < bp) return -1;
      if (ap > bp) return 1;
    }
  }
  return 0;
}

/**
 * True iff `remote` parses and is strictly greater than `current`. Used
 * to gate the "update available" UI so a feed that accidentally serves
 * an older release can't trigger a downgrade prompt.
 */
function isNewerVersion(remote: unknown, current: unknown): boolean {
  const r = parseSemver(remote);
  const c = parseSemver(current);
  if (!r || !c) return false;
  return compareSemver(r, c) > 0;
}

// ─── Public API ─────────────────────────────────────────────────────────────

export interface ConfigureAutoUpdaterOptions {
  feedUrl: string;
  channel?: string;
  allowPrerelease?: boolean;
  autoDownload?: boolean;
}

/**
 * Validates and applies feed URL + channel to the given updater handle.
 * Accepts a handle parameter so the main process can pass
 * `electron-updater.autoUpdater` and the test suite can pass a stub.
 */
export function configureAutoUpdater(
  updater: ElectronUpdaterLike,
  opts: ConfigureAutoUpdaterOptions,
): void {
  assertFeedUrl(opts.feedUrl);
  const channel = opts.channel ?? "latest";
  if (!isValidChannel(channel)) throw new Error("invalid channel");
  updater.autoDownload = opts.autoDownload ?? false;
  updater.allowPrerelease = opts.allowPrerelease ?? false;
  updater.channel = channel;
  updater.setFeedURL({ provider: "generic", url: opts.feedUrl, channel });
}

// ─── In-app download flow (iter 30) ─────────────────────────────────────────
//
// The iter-29 version-check manager surfaces "Update available" via the tray
// and routes the operator to a download URL through `shell.openExternal`.
// Iter 30 wires an opt-in alternative: when `RUD1_DESKTOP_AUTO_UPDATE=1` (or
// the equivalent JSON config in userData) AND `app.isPackaged === true`, the
// tray entry runs through `startBackgroundDownload` → `applyAndRestart`
// instead of the external-browser handoff.
//
// Conservative scope on purpose:
//   • we use `electron.net` + `app.getPath("userData")` rather than
//     pulling `electron-updater` into the runtime path. electron-updater
//     wants signed builds + a configured feed; this iter doesn't touch
//     either, and we'd rather ship a working "open the installer" flow
//     than half-finished silent-install plumbing.
//   • `applyAndRestart` calls `shell.openPath(downloadedFile)` and then
//     `app.quit()` — the user clicks through their OS installer prompt.
//     Full silent install is out of scope; tracked for a future iter.
//   • SHA-256 verification is opt-in via the manifest. If the manifest
//     omits `sha256` we still allow apply, but log it; the user already
//     opted into auto-update via the env flag and the URL itself ran
//     through the iter-21 `isValidFeedUrl` allowlist.

import * as fs from "fs";
import { promises as fsp } from "fs";
import * as path from "path";
import { createHash } from "crypto";
import {
  app as electronApp,
  net as electronNet,
  shell as electronShell,
} from "electron";

const AUTO_UPDATE_ENV = "RUD1_DESKTOP_AUTO_UPDATE";
const AUTO_UPDATE_CONFIG_FILE = "auto-update-config.json";
const DOWNLOAD_FILE_DEFAULT = "rud1-update.bin";
// Hard cap on the downloaded artifact. A real DMG / NSIS / AppImage is
// a few hundred MB; 512 MB is a generous ceiling that still refuses
// runaway responses.
const MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024;

export type AutoUpdateState =
  | { kind: "idle" }
  | { kind: "downloading"; url: string; bytesReceived: number; totalBytes: number | null }
  | { kind: "ready-to-apply"; url: string; filepath: string; sha256: string | null }
  | { kind: "error"; message: string };

interface AutoUpdaterDependencies {
  app?: { isPackaged: boolean; getPath: (n: string) => string };
  net?: { request: (opts: unknown) => unknown };
  shell?: { openPath: (p: string) => Promise<string>; openExternal: (u: string) => Promise<void> };
  quit?: () => void;
  fileSystem?: typeof fs;
}

let state: AutoUpdateState = { kind: "idle" };
let listeners: Array<(s: AutoUpdateState) => void> = [];
let deps: AutoUpdaterDependencies = {};

/**
 * Inject Electron-side handles. Called from `index.ts` after
 * `app.whenReady()` so the module can be imported safely from a Node
 * vitest run (which has no `electronApp.isPackaged` etc.). Tests pass
 * stubs.
 */
export function configureAutoUpdaterRuntime(d: AutoUpdaterDependencies): void {
  deps = { ...d };
}

export function getAutoUpdateState(): AutoUpdateState {
  return state;
}

export function subscribeAutoUpdate(fn: (s: AutoUpdateState) => void): () => void {
  listeners.push(fn);
  return () => {
    listeners = listeners.filter((l) => l !== fn);
  };
}

function setState(next: AutoUpdateState): void {
  state = next;
  for (const l of listeners) {
    try { l(next); } catch { /* ignore */ }
  }
}

/**
 * Reset the auto-update state machine back to "idle". Used by the tray
 * "Retry" handler after a download error so a subsequent click on
 * "Update available" can start a fresh download instead of re-rendering
 * the stuck error row.
 */
export function resetAutoUpdateState(): void {
  setState({ kind: "idle" });
}

/**
 * Read the in-userData config file (if present) for the auto-update
 * opt-in flag. Missing / malformed → `{}`. Synchronous on purpose: this
 * is called once per tray menu rebuild and the file is tens of bytes.
 */
function readPersistedConfig(getUserData: () => string, fileSystem: typeof fs): { autoUpdate?: boolean } {
  try {
    const p = path.join(getUserData(), AUTO_UPDATE_CONFIG_FILE);
    const raw = fileSystem.readFileSync(p, "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && typeof parsed.autoUpdate === "boolean") {
      return { autoUpdate: parsed.autoUpdate };
    }
    return {};
  } catch {
    return {};
  }
}

/**
 * True when the operator has opted into the in-app update flow AND the
 * runtime is a packaged build. Both gates are required: the env flag
 * alone isn't enough because a developer with `RUD1_DESKTOP_AUTO_UPDATE=1`
 * in their shell shouldn't accidentally trigger downloader plumbing
 * during `npm run dev`.
 *
 * Callers may pass overrides for tests; runtime callers omit them and
 * the function falls back to the configured deps.
 */
export function isAutoUpdateEnabled(opts: {
  env?: NodeJS.ProcessEnv;
  appOverride?: { isPackaged: boolean; getPath: (n: string) => string };
  fileSystem?: typeof fs;
} = {}): boolean {
  const env = opts.env ?? process.env;
  const a = opts.appOverride ?? deps.app ?? electronApp;
  const fileSystem = opts.fileSystem ?? deps.fileSystem ?? fs;
  if (!a || a.isPackaged !== true) return false;
  if (env[AUTO_UPDATE_ENV] === "1") return true;
  const cfg = readPersistedConfig(() => a.getPath("userData"), fileSystem);
  return cfg.autoUpdate === true;
}

/**
 * Start a background download of the artifact at `url` to
 * `<userData>/rud1-update.bin`. Atomic write via `<file>.partial` →
 * `rename` so a process kill mid-download doesn't strand a half-file
 * marked ready. Returns immediately; subscribers see the state machine
 * transition via the registered listeners.
 *
 * The optional `sha256` argument is captured into the ready state so
 * `applyAndRestart` can verify before launching the installer.
 */
export function startBackgroundDownload(
  url: string,
  options: { sha256?: string | null; userDataDir?: string; net?: AutoUpdaterDependencies["net"]; fileSystem?: typeof fs } = {},
): Promise<AutoUpdateState> {
  if (!isValidFeedUrl(url)) {
    setState({ kind: "error", message: "invalid download URL" });
    return Promise.resolve(state);
  }
  const sha256 = options.sha256 ?? null;
  const userDataDir = options.userDataDir ?? deps.app?.getPath("userData") ?? electronApp.getPath("userData");
  const net = options.net ?? deps.net ?? electronNet;
  const fileSystem = options.fileSystem ?? deps.fileSystem ?? fs;
  const filepath = path.join(userDataDir, DOWNLOAD_FILE_DEFAULT);
  const tmp = `${filepath}.partial`;

  setState({ kind: "downloading", url, bytesReceived: 0, totalBytes: null });

  return new Promise<AutoUpdateState>((resolve) => {
    let received = 0;
    let total: number | null = null;
    let writer: fs.WriteStream;
    try {
      fileSystem.mkdirSync(userDataDir, { recursive: true });
      writer = fileSystem.createWriteStream(tmp);
    } catch (e) {
      setState({ kind: "error", message: `cannot open download file: ${(e as Error)?.message ?? e}` });
      resolve(state);
      return;
    }

    const req = (net as { request: (o: unknown) => any }).request({ method: "GET", url });
    req.on("response", (res: any) => {
      const status = res.statusCode ?? 0;
      if (status < 200 || status >= 300) {
        try { writer.destroy(); } catch { /* ignore */ }
        try { fileSystem.unlinkSync(tmp); } catch { /* ignore */ }
        setState({ kind: "error", message: `download HTTP ${status}` });
        resolve(state);
        return;
      }
      const lenHeader = res.headers?.["content-length"];
      const lenStr = Array.isArray(lenHeader) ? lenHeader[0] : lenHeader;
      if (lenStr) {
        const n = Number(lenStr);
        if (Number.isFinite(n) && n > 0) total = n;
      }
      res.on("data", (chunk: Buffer) => {
        received += chunk.length;
        if (received > MAX_DOWNLOAD_BYTES) {
          try { res.destroy?.(); } catch { /* ignore */ }
          try { writer.destroy(); } catch { /* ignore */ }
          try { fileSystem.unlinkSync(tmp); } catch { /* ignore */ }
          setState({ kind: "error", message: "download exceeded size cap" });
          resolve(state);
          return;
        }
        writer.write(chunk);
        setState({ kind: "downloading", url, bytesReceived: received, totalBytes: total });
      });
      res.on("end", () => {
        writer.end(() => {
          try {
            fileSystem.renameSync(tmp, filepath);
          } catch (e) {
            setState({ kind: "error", message: `rename failed: ${(e as Error)?.message ?? e}` });
            resolve(state);
            return;
          }
          setState({ kind: "ready-to-apply", url, filepath, sha256 });
          resolve(state);
        });
      });
      res.on("error", (err: Error) => {
        try { writer.destroy(); } catch { /* ignore */ }
        try { fileSystem.unlinkSync(tmp); } catch { /* ignore */ }
        setState({ kind: "error", message: `download stream error: ${err?.message ?? err}` });
        resolve(state);
      });
    });
    req.on("error", (err: Error) => {
      try { writer.destroy(); } catch { /* ignore */ }
      try { fileSystem.unlinkSync(tmp); } catch { /* ignore */ }
      setState({ kind: "error", message: `download request error: ${err?.message ?? err}` });
      resolve(state);
    });
    try {
      req.end();
    } catch (e) {
      setState({ kind: "error", message: `download request failed: ${(e as Error)?.message ?? e}` });
      resolve(state);
    }
  });
}

/**
 * Verify (when sha256 was advertised) and hand off to the OS installer.
 * macOS / Windows / Linux all use `shell.openPath` — the user clicks
 * through their installer dialog and we quit so the new version takes
 * over on next launch. Full silent install would need `electron-updater`
 * + a signed feed; explicitly out of scope this iter.
 */
export async function applyAndRestart(
  options: { shell?: AutoUpdaterDependencies["shell"]; quit?: () => void; fileSystem?: typeof fs } = {},
): Promise<AutoUpdateState> {
  if (state.kind !== "ready-to-apply") {
    setState({ kind: "error", message: "no downloaded artifact ready" });
    return state;
  }
  const sh = options.shell ?? deps.shell ?? electronShell;
  const quit = options.quit ?? deps.quit ?? (() => electronApp.quit());
  const fileSystem = options.fileSystem ?? deps.fileSystem ?? fs;
  const ready = state;
  if (ready.sha256) {
    try {
      const buf = await fsp.readFile(ready.filepath);
      const got = createHash("sha256").update(buf).digest("hex").toLowerCase();
      const want = ready.sha256.toLowerCase();
      if (got !== want) {
        setState({ kind: "error", message: `sha256 mismatch: got ${got}, expected ${want}` });
        try { fileSystem.unlinkSync(ready.filepath); } catch { /* ignore */ }
        return state;
      }
    } catch (e) {
      setState({ kind: "error", message: `sha256 read failed: ${(e as Error)?.message ?? e}` });
      return state;
    }
  }
  try {
    const errMsg = await sh!.openPath(ready.filepath);
    if (typeof errMsg === "string" && errMsg.length > 0) {
      setState({ kind: "error", message: `openPath failed: ${errMsg}` });
      return state;
    }
  } catch (e) {
    setState({ kind: "error", message: `openPath threw: ${(e as Error)?.message ?? e}` });
    return state;
  }
  quit();
  return state;
}

// Test-only hatch — mirrors iter 17–20.
export const __test = {
  isValidFeedUrl,
  assertFeedUrl,
  isValidChannel,
  parseSemver,
  compareSemver,
  isNewerVersion,
  ALLOWED_CHANNELS,
  HOST_REGEX,
  UNSAFE_PATH_CHARS,
  AUTO_UPDATE_ENV,
  AUTO_UPDATE_CONFIG_FILE,
  DOWNLOAD_FILE_DEFAULT,
  MAX_DOWNLOAD_BYTES,
  readPersistedConfig,
  setStateForTesting: (s: AutoUpdateState) => { state = s; },
  resetStateForTesting: () => { state = { kind: "idle" }; listeners = []; deps = {}; },
};
