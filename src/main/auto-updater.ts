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
};
