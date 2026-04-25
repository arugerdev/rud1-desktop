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

import { createHash } from "crypto";

import { __test as autoUpdaterInternals, type AutoUpdateState } from "./auto-updater";

const { isValidFeedUrl, parseSemver, isNewerVersion, compareSemver } = autoUpdaterInternals;

// Hard cap on the body we'll read from the manifest URL. A well-formed
// release feed is a few hundred bytes; anything bigger is almost
// certainly a misconfiguration (or an attempt to OOM the app).
const MAX_MANIFEST_BYTES = 16 * 1024;

// Iter 32 — manifest schema version cap. We accept legacy unversioned
// manifests (treated as v1) and explicit v1; v2 layers in the requirement
// that `sha256` be present and shaped like 64 lowercase-hex chars. Any
// `manifestVersion` strictly greater than this constant is REFUSED as
// "unsupported future schema" — failing closed beats silently treating an
// unknown shape as if it were the latest known one. Bumping the cap is a
// deliberate gate for future schema work.
const MAX_SUPPORTED_MANIFEST_VERSION = 2;

// Iter 32 — sha256 hex shape: exactly 64 chars of [0-9a-f] (case-insensitive
// input is accepted; we lowercase before storing). Anything else is
// rejected so a manifest with `sha256: "deadbeef"` (too short) or
// `sha256: "...zzz..."` (non-hex) can't slip past the v2 gate.
const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/i;

// Iter 36 — minBootstrapVersion shape gate. Anchored at start; the
// sha256-style strictness ("malformed → reject the whole manifest") is the
// same as for `version` itself. We deliberately keep the regex permissive
// enough to accept prerelease / build-metadata suffixes (`1.2.3-rc.1+sha`)
// but require the leading `MAJOR.MINOR.PATCH` triplet — anything else is a
// server-side typo we'd rather surface than mask. The dedicated `parseSemver`
// run a few lines later then performs the full RFC parse.
const MIN_BOOTSTRAP_VERSION_SHAPE = /^\d+\.\d+\.\d+/;

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
      // Iter 33 — optional changelog URL parsed from the manifest. The
      // tray menu surfaces a "What's new — view release notes" row above
      // the recheck entry when this is non-null. Validated through the
      // same allowlist as `downloadUrl` at parse time so unsafe URLs
      // never reach the state.
      releaseNotesUrl: string | null;
      checkedAt: number;
    }
  | {
      // Iter 36 — staged-migration gate. The manifest advertised a
      // `minBootstrapVersion` and the currently-installed app is older
      // than it: the operator must do a manual install of the
      // intermediate `requiredMinVersion` first before the auto-update
      // path will agree to apply `targetVersion`. The "What's new" link
      // (changelog) is still surfaced when the manifest carried one so
      // the operator can read context before downloading the bridge
      // build by hand. The download row is replaced with a clear
      // blocked-state label — auto-update + external-browser flows are
      // both refused for this fetch tick.
      kind: "update-blocked-by-min-bootstrap";
      requiredMinVersion: string;
      currentVersion: string;
      targetVersion: string;
      releaseNotesUrl: string | null;
      // Iter 38 — manifest-supplied bridge build URL (allowlist-validated
      // at parse time). Surfaced to the Settings/About panel's "Copy
      // download URL" button as the preferred copy target.
      bridgeDownloadUrl: string | null;
      // Iter 39 — per-`minBootstrapVersion` bridge download map. Each
      // key is a semver-shaped version string (`MAJOR.MINOR.PATCH...`)
      // identifying the bootstrap version the value installer covers,
      // each value is an https-allowlist-validated URL pointing at that
      // bootstrap installer. The Settings/About "Copy download URL"
      // button looks up `bridgeDownloadUrls[requiredMinVersion]` first
      // and only falls through to the iter-38 scalar / iter-37 release
      // notes / synthesized fallback when no keyed match exists. The
      // map is `undefined` (not `null`) when the manifest didn't carry
      // one or when every entry was filtered out by validation; this
      // keeps the iter-38 scalar-only path strictly backward-compatible.
      bridgeDownloadUrls?: Record<string, string>;
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
  /**
   * Iter 34 — stable per-installation identifier used to compute the
   * staged-rollout bucket. When omitted, rollout suppression is
   * disabled and every device is classified as if the manifest had no
   * `rolloutBucket` field. Wiring in `index.ts` derives this from
   * `app.getName() + machine identifier` once at startup.
   */
  installId?: string;
  /**
   * Iter 35 — predicate evaluated on every `checkOnce` to decide
   * whether the iter-34 `rolloutBucket` gate should be bypassed. When
   * truthy at the time of the fetch, the manager passes
   * `forceRollout=true` into `classifyManifest` so a device outside
   * its bucket is still classified as `update-available`.
   *
   * Function-typed (rather than a static boolean) so a runtime change
   * to the env var or persisted config takes effect on the next tick
   * without restarting the manager. Defaults to "always false" — the
   * iter-34 bucket gate stays in force.
   */
  forceRollout?: () => boolean;
}

export interface VersionManifest {
  /** Latest published version (semver). */
  version: string;
  /** Optional URL for the operator to follow. */
  downloadUrl?: string | null;
  /**
   * Schema version of the manifest. Always populated by `parseManifest`:
   * legacy manifests (no field) and explicit v1 both resolve to `1`.
   * Iter 32 introduced `2`, which adds the sha256 requirement enforced
   * at parse time.
   */
  manifestVersion: number;
  /**
   * Lowercase 64-char hex SHA-256 of the artifact at `downloadUrl`.
   *
   * Iter 30 made this optional; iter 31 added an opt-in apply-time
   * strict mode that rejected null. Iter 32 makes the schema enforce
   * it: when `manifestVersion >= 2`, `parseManifest` REFUSES the
   * whole manifest if `sha256` is missing or shape-invalid. v1
   * manifests still allow null for backward compatibility.
   */
  sha256: string | null;
  /**
   * Optional URL to the human-readable release notes / changelog for
   * `version`. Iter 33 — surfaced in the tray menu as a "What's new"
   * entry so an operator can see the changelog before clicking
   * Download. Validated through the same `isValidFeedUrl` allowlist as
   * `downloadUrl` (no `javascript:` / `file:` slipping through), and
   * silently dropped on validation failure rather than rejecting the
   * whole manifest — the changelog is a convenience, not an integrity
   * claim. Optional in BOTH v1 and v2 manifests; future v3 may promote
   * it to required.
   */
  releaseNotesUrl: string | null;
  /**
   * Iter 34 — staged-rollout bucket. When present, an integer in
   * `[1, 100]` representing the percentage of the install base that
   * should be classified as `update-available`. The device computes a
   * stable per-installation bucket (also `[1, 100]`) and compares: if
   * `deviceBucket <= rolloutBucket` the device is eligible; otherwise
   * the manifest is suppressed and classified as `up-to-date` instead.
   * Optional in v1 and v2 — `null` means "ship to everyone", which is
   * the historical behaviour.
   *
   * Wrong-type / out-of-range values reject the WHOLE manifest at
   * parse time (a server-side bug we'd rather surface than mask).
   */
  rolloutBucket: number | null;
  /**
   * Iter 36 — staged-migration anchor. When present, a non-empty
   * semver-shaped string (`MAJOR.MINOR.PATCH[...]`) identifying the
   * lowest currently-installed desktop version that may auto-update to
   * `version` directly. If the running app is BELOW
   * `minBootstrapVersion`, `classifyManifest` refuses the update and
   * surfaces `update-blocked-by-min-bootstrap` instead — the operator
   * must do a manual install of the intermediate version first
   * (`download v{requiredMinVersion}`).
   *
   * Optional in BOTH v1 and v2 manifests; the spec reserves the right
   * to promote it to required in v3. Malformed values (empty string,
   * non-string, `"1.2"`, `"1.2.3.4-"`, etc.) reject the whole
   * manifest, mirroring the strictness applied to `sha256` and the
   * other typed fields — the integrity of the migration anchor is too
   * load-bearing to silently drop. Missing / null / undefined → stored
   * as `null`, behaviour unchanged (no gate).
   */
  minBootstrapVersion: string | null;
  /**
   * Iter 38 — companion to `minBootstrapVersion`. When present, an
   * absolute https URL pointing at the bridge build the operator must
   * install manually before the auto-update path will accept the
   * `version` upgrade. The Settings/About panel "Copy download URL"
   * button copies this value when set, falling back to
   * `releaseNotesUrl` and finally a synthesized
   * `https://rud1.es/desktop/download?version={requiredMinVersion}`.
   *
   * Optional in v1 and v2 manifests. Validated through the same
   * `isValidFeedUrl` allowlist as `downloadUrl` / `releaseNotesUrl`
   * (https only, no userinfo, no CRLF / control chars). On allowlist
   * rejection the field is silently dropped (mirrors the
   * `releaseNotesUrl` lenient stance — a bad URL is a missing
   * convenience, not an integrity failure). Wrong-type values (numbers,
   * objects, arrays) reject the whole manifest like every other typed
   * field.
   */
  bridgeDownloadUrl: string | null;
  /**
   * Iter 39 — per-`minBootstrapVersion` bridge download map. Promotes
   * the iter-38 scalar `bridgeDownloadUrl` to a keyed lookup so a
   * multi-version fleet can serve a different bootstrap installer per
   * minimum version requirement.
   *
   * Each key is a semver-shaped string (`MAJOR.MINOR.PATCH...` —
   * matches the `minBootstrapVersion` shape gate used elsewhere in
   * this file). Each value is validated through the iter-38
   * `isBridgeDownloadUrlAllowed` allowlist. Individual entries that
   * fail either check are SILENTLY DROPPED (consistent with the
   * iter-33 `releaseNotesUrl` stance — bad-but-not-essential
   * convenience data degrades gracefully). The whole manifest is only
   * rejected when `bridgeDownloadUrls` is the wrong TYPE (anything
   * other than a plain object — strings, arrays, numbers, etc.); a
   * server-side type swap is a louder signal than a typo'd entry.
   *
   * After filtering, an empty map is coerced to `undefined` so
   * downstream code only has to special-case the missing-map shape
   * once. Optional in v1 and v2 manifests; the iter-38 scalar
   * remains the documented fallback for unkeyed manifests.
   */
  bridgeDownloadUrls?: Record<string, string>;
}

/**
 * Validates the parsed JSON body. Returns null when the shape is wrong;
 * we never throw because the caller treats a malformed manifest as a
 * recoverable error and keeps polling.
 *
 * Iter 32 — `manifestVersion` schema gate.
 *   • Field is OPTIONAL for backward compatibility: a legacy manifest with
 *     no `manifestVersion` field is treated as v1 (the iter 29/30 shape).
 *   • Type-strict on purpose: only finite numbers are accepted. Strings
 *     like `"2"` are REJECTED rather than coerced — JSON manifests should
 *     produce numbers from `JSON.parse`, and a string-typed schema
 *     version is almost always a server-side bug we'd rather surface
 *     than paper over. (Documented in the iter-32 commit message.)
 *   • Future versions (`manifestVersion > MAX_SUPPORTED_MANIFEST_VERSION`)
 *     are REJECTED. Failing closed on an unknown schema is safer than
 *     latest-shape-treatment, especially since v3+ may add NEW required
 *     fields whose absence from this code path would otherwise be
 *     silently ignored.
 *   • When the resolved version is `>= 2`, `sha256` MUST be a string
 *     matching SHA256_HEX_REGEX. Missing, null, wrong-type, wrong-length
 *     or non-hex inputs all reject the manifest. This is the whole
 *     point of the v2 bump — making the integrity claim part of the
 *     schema rather than an opt-in operator flag.
 *
 * Strict mode (iter 31) and v2 (iter 32) are orthogonal: v2 enforces the
 * presence of sha256 in the parser; strict enforces non-null at apply
 * time. Both compose — a legacy v1 manifest with no sha256 still passes
 * the parser but trips the strict gate, exactly as in iter 31.
 */
export function parseManifest(raw: unknown): VersionManifest | null {
  if (raw == null || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  if (typeof obj.version !== "string" || obj.version.length === 0) return null;
  if (parseSemver(obj.version) == null) return null;

  // Resolve the schema version. Legacy manifests that omit the field —
  // i.e. every iter-29/30/31 manifest in the wild — resolve to v1.
  // Anything with the field present must be a finite integer; we
  // refuse strings and floats so a typo on the server side is loud.
  let manifestVersion = 1;
  if (Object.prototype.hasOwnProperty.call(obj, "manifestVersion")) {
    const mv = obj.manifestVersion;
    if (typeof mv !== "number" || !Number.isFinite(mv) || !Number.isInteger(mv) || mv < 1) {
      return null;
    }
    if (mv > MAX_SUPPORTED_MANIFEST_VERSION) {
      // Future schema we don't understand. Fail closed.
      return null;
    }
    manifestVersion = mv;
  }

  // Sha256 extraction + shape validation. The field is optional for v1
  // but mandatory for v2+ — we run the same shape check in both branches
  // (so a v1 manifest with a malformed sha256 also rejects, rather than
  // silently dropping it and pretending nothing was advertised).
  let sha256: string | null = null;
  if (Object.prototype.hasOwnProperty.call(obj, "sha256") && obj.sha256 != null) {
    if (typeof obj.sha256 !== "string") return null;
    if (!SHA256_HEX_REGEX.test(obj.sha256)) return null;
    sha256 = obj.sha256.toLowerCase();
  }
  if (manifestVersion >= 2 && sha256 == null) {
    // The v2 schema's contract: sha256 is REQUIRED. Reject the whole
    // manifest rather than promoting to update-available without an
    // integrity claim — the operator who served us a v2 manifest
    // promised one, and we'd rather surface the rejection than drift.
    return null;
  }

  let downloadUrl: string | null = null;
  if (typeof obj.downloadUrl === "string" && obj.downloadUrl.length > 0) {
    // Re-use the auto-updater allowlist so a malicious manifest can't
    // smuggle e.g. javascript: or file: URLs through to the tray menu.
    if (isValidFeedUrl(obj.downloadUrl)) downloadUrl = obj.downloadUrl;
    // else: silently drop — we'd rather show "update available" without
    // a clickable link than send the operator to an unsafe URL.
  }

  // Iter 33 — optional releaseNotesUrl. Same allowlist as downloadUrl;
  // silent drop on validation failure (the changelog is a convenience,
  // not an integrity claim). Wrong-type / non-string values reject the
  // whole manifest, mirroring the strictness on every other typed field
  // — a server-side bug here is louder than a missing convenience link.
  let releaseNotesUrl: string | null = null;
  if (
    Object.prototype.hasOwnProperty.call(obj, "releaseNotesUrl") &&
    obj.releaseNotesUrl != null
  ) {
    if (typeof obj.releaseNotesUrl !== "string") return null;
    if (obj.releaseNotesUrl.length > 0 && isValidFeedUrl(obj.releaseNotesUrl)) {
      releaseNotesUrl = obj.releaseNotesUrl;
    }
    // else: empty string OR allowlist rejection ⇒ silently drop.
  }

  // Iter 34 — optional rolloutBucket. Integer in [1, 100]. Wrong-type or
  // out-of-range values reject the whole manifest, mirroring the
  // strictness on every other typed field — a server-side bug here
  // (e.g. accidentally shipping `rolloutBucket: 0` and silencing the
  // entire fleet) is louder than a missing convenience.
  let rolloutBucket: number | null = null;
  if (
    Object.prototype.hasOwnProperty.call(obj, "rolloutBucket") &&
    obj.rolloutBucket != null
  ) {
    const rb = obj.rolloutBucket;
    if (typeof rb !== "number" || !Number.isFinite(rb) || !Number.isInteger(rb)) {
      return null;
    }
    if (rb < 1 || rb > 100) return null;
    rolloutBucket = rb;
  }

  // Iter 36 — optional minBootstrapVersion. Non-empty semver-shaped
  // string; malformed values reject the whole manifest (same loud-fail
  // policy as sha256). The shape regex is a cheap pre-filter — the
  // canonical parse runs through `parseSemver` so a value that passes
  // the shape but fails full RFC parsing (e.g. `"1.2.3.4-"` — extra
  // numeric segment) still rejects.
  let minBootstrapVersion: string | null = null;
  if (
    Object.prototype.hasOwnProperty.call(obj, "minBootstrapVersion") &&
    obj.minBootstrapVersion != null
  ) {
    if (typeof obj.minBootstrapVersion !== "string") return null;
    if (obj.minBootstrapVersion.length === 0) return null;
    if (!MIN_BOOTSTRAP_VERSION_SHAPE.test(obj.minBootstrapVersion)) return null;
    if (parseSemver(obj.minBootstrapVersion) == null) return null;
    minBootstrapVersion = obj.minBootstrapVersion;
  }

  // Iter 38 — optional bridgeDownloadUrl. Same allowlist as downloadUrl;
  // silent drop on validation failure (the bridge link is a convenience —
  // the operator can still synthesize the fallback download URL from
  // `minBootstrapVersion`). Wrong-type / non-string values reject the
  // whole manifest, mirroring the strictness on every other typed field.
  let bridgeDownloadUrl: string | null = null;
  if (
    Object.prototype.hasOwnProperty.call(obj, "bridgeDownloadUrl") &&
    obj.bridgeDownloadUrl != null
  ) {
    if (typeof obj.bridgeDownloadUrl !== "string") return null;
    if (obj.bridgeDownloadUrl.length > 0 && isValidFeedUrl(obj.bridgeDownloadUrl)) {
      bridgeDownloadUrl = obj.bridgeDownloadUrl;
    }
    // else: empty string OR allowlist rejection ⇒ silently drop.
  }

  // Iter 39 — optional bridgeDownloadUrls map. Promotes iter-38's scalar
  // to a per-`minBootstrapVersion` lookup. The whole-manifest reject only
  // fires when the field is the wrong TYPE (not a plain object); within
  // a well-typed map, individual entries that fail key/value validation
  // are silently dropped (iter-33 stance for non-essential convenience
  // data). An empty map after filtering coerces to undefined so the
  // downstream `pickDownloadUrl` chain can rely on `undefined === no map`.
  let bridgeDownloadUrls: Record<string, string> | undefined;
  if (
    Object.prototype.hasOwnProperty.call(obj, "bridgeDownloadUrls") &&
    obj.bridgeDownloadUrls != null
  ) {
    const raw = obj.bridgeDownloadUrls;
    // Reject wrong types loud-and-early. Arrays are typeof 'object' but
    // semantically the wrong shape — a manifest publisher who wrote
    // `bridgeDownloadUrls: ["1.2.0", "url"]` made a server-side mistake
    // we'd rather surface than mask.
    if (typeof raw !== "object" || Array.isArray(raw)) return null;
    const filtered: Record<string, string> = {};
    for (const key of Object.keys(raw as Record<string, unknown>)) {
      const value = (raw as Record<string, unknown>)[key];
      if (typeof key !== "string" || key.length === 0) continue;
      if (!MIN_BOOTSTRAP_VERSION_SHAPE.test(key)) continue;
      if (parseSemver(key) == null) continue;
      if (typeof value !== "string") continue;
      if (!isBridgeDownloadUrlAllowed(value)) continue;
      filtered[key] = value;
    }
    if (Object.keys(filtered).length > 0) {
      bridgeDownloadUrls = filtered;
    }
  }

  return {
    version: obj.version,
    downloadUrl,
    manifestVersion,
    sha256,
    releaseNotesUrl,
    rolloutBucket,
    minBootstrapVersion,
    bridgeDownloadUrl,
    bridgeDownloadUrls,
  };
}

/**
 * Iter 34 — derive a stable per-installation bucket in `[1, 100]` from
 * an arbitrary installation identifier. Same input always yields the
 * same bucket so a device with `deviceBucket=42` consistently sees
 * (or doesn't see) every staged rollout the server publishes.
 *
 * Uses sha256 of the input, reads the first 4 bytes as a big-endian
 * uint32, takes mod 100, +1 to map onto `[1, 100]`. The mod/distribution
 * is uniform enough across realistic installation-ID populations
 * (UUIDs, hostnames, machine fingerprints) for staged-rollout purposes
 * — we are not running a CSPRNG, just bucketing.
 */
export function computeDeviceBucket(installId: string): number {
  const digest = createHash("sha256").update(installId).digest();
  const u32 =
    ((digest[0] << 24) >>> 0) |
    (digest[1] << 16) |
    (digest[2] << 8) |
    digest[3];
  return (u32 >>> 0) % 100 + 1;
}

/**
 * Pure helper: given a current + remote semver string, return the next
 * VersionCheckState as if the fetch just succeeded. Exposed so tests
 * can pin the comparison without mocking `fetch`.
 *
 * Iter 34 — `deviceBucket` is the per-installation bucket in `[1, 100]`
 * (see `computeDeviceBucket`). When the manifest carries a non-null
 * `rolloutBucket`, devices with `deviceBucket > rolloutBucket` are
 * silently classified as `up-to-date` even though a newer version is
 * advertised — they're outside the rollout cohort. `null` means
 * "ship to everyone" (historical behaviour). When `deviceBucket` is
 * not provided, rollout suppression is disabled (used by tests that
 * don't care about bucketing).
 *
 * Iter 35 — `forceRollout=true` bypasses the bucket comparison entirely
 * so a tester (env var `RUD1_DESKTOP_ROLLOUT_FORCE=1` or persisted
 * config `rolloutForce: true`) can fetch the artifact regardless of
 * bucket. Default false preserves the iter-34 behaviour.
 */
export function classifyManifest(
  current: string,
  manifest: VersionManifest,
  now: number,
  deviceBucket?: number,
  forceRollout: boolean = false,
): VersionCheckState {
  if (parseSemver(current) == null) {
    return {
      kind: "error",
      message: "current version is not valid semver",
      checkedAt: now,
    };
  }
  if (isNewerVersion(manifest.version, current)) {
    if (
      !forceRollout &&
      manifest.rolloutBucket != null &&
      deviceBucket != null &&
      deviceBucket > manifest.rolloutBucket
    ) {
      return {
        kind: "up-to-date",
        current,
        latest: manifest.version,
        checkedAt: now,
      };
    }
    // Iter 36 — staged-migration gate. Runs AFTER the rollout bucket
    // gate (so an out-of-bucket device stays in the silent up-to-date
    // path) and BEFORE the update-available promotion. The min anchor
    // was already shape-validated at parse time, so `parseSemver`
    // returning null here is impossible in practice; the defensive
    // check exists only so a future schema rev that accepts looser
    // shapes can't silently bypass the gate.
    if (manifest.minBootstrapVersion != null) {
      const cur = parseSemver(current);
      const min = parseSemver(manifest.minBootstrapVersion);
      if (cur != null && min != null && compareSemver(cur, min) < 0) {
        return {
          kind: "update-blocked-by-min-bootstrap",
          requiredMinVersion: manifest.minBootstrapVersion,
          currentVersion: current,
          targetVersion: manifest.version,
          releaseNotesUrl: manifest.releaseNotesUrl,
          bridgeDownloadUrl: manifest.bridgeDownloadUrl,
          bridgeDownloadUrls: manifest.bridgeDownloadUrls,
          checkedAt: now,
        };
      }
    }
    return {
      kind: "update-available",
      current,
      latest: manifest.version,
      downloadUrl: manifest.downloadUrl ?? null,
      releaseNotesUrl: manifest.releaseNotesUrl,
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
    installId: string | null;
    forceRollout: () => boolean;
  };
  private readonly deviceBucket: number | null;

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
      installId: options.installId ?? null,
      forceRollout: options.forceRollout ?? (() => false),
    };
    this.deviceBucket =
      this.opts.installId != null ? computeDeviceBucket(this.opts.installId) : null;
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
      // Iter 34/35 — log the rollout decision once per fetch when the
      // manifest carries a bucket. Eligibility now also reflects the
      // iter-35 force-override (via `RUD1_DESKTOP_ROLLOUT_FORCE` or
      // persisted config), so a tester reading the console sees the
      // override as the cause when their bucket would otherwise have
      // suppressed the update.
      let forceRollout = false;
      try {
        forceRollout = this.opts.forceRollout();
      } catch {
        // A throwing predicate (e.g. fileSystem suddenly returning
        // EPERM mid-poll) must not break the version-check loop.
        // Default to "not forced" so we fall back to the iter-34 gate.
        forceRollout = false;
      }
      if (manifest.rolloutBucket != null && this.deviceBucket != null) {
        const inBucket = this.deviceBucket <= manifest.rolloutBucket;
        const eligible = inBucket || forceRollout;
        console.info(
          `[version-check] rollout: device bucket=${this.deviceBucket}, manifest bucket=${manifest.rolloutBucket}, inBucket=${inBucket}, forced=${forceRollout}, eligible=${eligible}`,
        );
      } else if (forceRollout) {
        console.info(`[version-check] rollout: force override active (no bucket in manifest)`);
      }
      return this.transition(
        classifyManifest(
          this.opts.currentVersion,
          manifest,
          Date.now(),
          this.deviceBucket ?? undefined,
          forceRollout,
        ),
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
    const items: MenuItemShape[] = [
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
    ];
    // Iter 33 — surface the release notes URL above the recheck row when
    // the manifest advertised one. Click always opens in the system
    // browser (changelogs are read-only content; never an installer
    // payload — keep them out of the auto-update download path).
    if (state.releaseNotesUrl) {
      items.push({
        label: "What's new — view release notes",
        click: () => {
          handlers.openExternal?.(state.releaseNotesUrl as string);
        },
      });
    }
    items.push({
      label: "Check for updates now",
      click: () => { handlers.recheck?.(); },
    });
    return items;
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
  // Iter 36 — staged-migration block. The download row is replaced by a
  // disabled label that calls the operator to install the bridge build
  // by hand; the "What's new" link still works (changelogs are read-only
  // content). Auto-update + external-browser flows are both refused for
  // this fetch tick — `applyAndRestart` would fail downstream anyway,
  // but surfacing the block in the menu is what makes the migration
  // policy visible.
  if (state.kind === "update-blocked-by-min-bootstrap") {
    const items: MenuItemShape[] = [
      {
        label: `Update requires manual install: download v${state.requiredMinVersion} first`,
        enabled: false,
      },
      {
        label: `Currently installed: v${state.currentVersion}`,
        enabled: false,
      },
      {
        label: `Target version: v${state.targetVersion}`,
        enabled: false,
      },
    ];
    if (state.releaseNotesUrl) {
      items.push({
        label: "What's new — view release notes",
        click: () => {
          handlers.openExternal?.(state.releaseNotesUrl as string);
        },
      });
    }
    items.push({
      label: "Check for updates now",
      click: () => { handlers.recheck?.(); },
    });
    return items;
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

// ─── Iter 37 — Settings/About panel formatters ──────────────────────────────
//
// Pure helpers consumed by the Settings/About data-URL window's "Updates"
// section. Extracted out of the HTML template so the copy is unit-testable
// without spinning up a renderer. Each helper takes a fully-typed
// `VersionCheckState` (or one of its variants) and returns a plain
// presentation object — the renderer is a dumb mapper from these shapes to
// DOM nodes.
//
// The blocked-state copy is the headline: a clear "Download v{X} manually
// first" call to action plus the installed/target version pair so the
// operator can confirm they're following the right migration ladder.

export interface BlockedStateMessage {
  /** Headline banner copy. */
  banner: string;
  /** "Currently installed: v…" caption row. */
  currentLine: string;
  /** "Target: v…" caption row. */
  targetLine: string;
  /** The download URL the "Copy download URL" button copies, or null. */
  downloadHint: string;
  /** When non-null, a "What's new" changelog URL the renderer surfaces. */
  releaseNotesUrl: string | null;
}

/**
 * Format the iter-36 `update-blocked-by-min-bootstrap` state into the copy
 * the iter-37 Settings/About panel renders. Pure: no DOM, no Electron.
 *
 * Rationale for keeping this a separate helper:
 *   • the HTML template builder in index.ts can stay a string-concat path
 *     (no logic interleaved with markup, easier to scan for XSS holes);
 *   • unit tests can pin the exact operator-facing copy without parsing
 *     HTML — a regression in the headline ("Update blocked" vs "Download
 *     v… first") is loudly caught;
 *   • a future iter that retitles or i18n's the panel only needs to swap
 *     this function out, not re-grep the template.
 *
 * The download-URL hint is intentionally NOT a clickable URL in the copy
 * — the operator copies it via the "Copy download URL" button (clipboard
 * IPC) and pastes into a browser or installer. This avoids the
 * data:-origin permission grant that `navigator.clipboard.writeText` would
 * otherwise require.
 */
export function formatBlockedStateMessage(
  state: VersionCheckState & { kind: "update-blocked-by-min-bootstrap" },
): BlockedStateMessage {
  return {
    banner: `Download v${state.requiredMinVersion} manually first to continue receiving updates`,
    currentLine: `Currently installed: v${state.currentVersion}`,
    targetLine: `Target: v${state.targetVersion}`,
    downloadHint: `Manual download required for v${state.requiredMinVersion}`,
    releaseNotesUrl: state.releaseNotesUrl,
  };
}

/**
 * Build the headline copy for the non-blocked verdicts. Returned as a
 * single string the panel can render in a paragraph; the blocked state has
 * its own structured message via `formatBlockedStateMessage`.
 *
 * Iter 37 — kept brief; the blocked path is the main feature of this
 * iter, the others are nice-to-have for context. The strings are
 * semantically equivalent to the tray-menu rows from `buildVersionCheckMenuItems`
 * but reworded to fit a panel paragraph (no leading triangle, etc.).
 */
export function formatVersionCheckSummary(state: VersionCheckState): string {
  switch (state.kind) {
    case "idle":
      return "Update check has not run yet.";
    case "checking":
      return "Checking for updates…";
    case "up-to-date":
      return `Up to date (v${state.current}).`;
    case "update-available":
      return `Update available — v${state.latest} (currently v${state.current}).`;
    case "update-blocked-by-min-bootstrap":
      // Headline summary; the full blocked-state UI is rendered from
      // `formatBlockedStateMessage` and a dedicated banner.
      return `Update blocked: install v${state.requiredMinVersion} manually first.`;
    case "error":
      return `Couldn't check for updates: ${state.message}`;
  }
}

// ─── Iter 38 / 39 — Settings/About panel: download URL precedence ───────────
//
// Pure helper picking the URL the "Copy download URL" button copies when
// the verdict is `update-blocked-by-min-bootstrap`. Iter-39 precedence:
//   1. bridgeDownloadUrls[requiredMinVersion] (iter 39) — exact-match
//      keyed lookup against the manifest's per-bootstrap-version map. A
//      multi-version fleet's manifest can ship one map and route every
//      device to the right installer in one round trip.
//   2. bridgeDownloadUrl (iter 38) — scalar fallback for unkeyed
//      manifests (or manifests where the keyed map didn't include this
//      device's `requiredMinVersion`).
//   3. releaseNotesUrl (iter 33 fallback used by iter-37) — better than
//      the synthesized URL because it's a real link the publisher wrote.
//   4. Synthesized `https://rud1.es/desktop/download?version={X}` — last
//      resort when no manifest fields are usable.
//
// Both the keyed and the scalar URL are re-validated through the same
// allowlist used at parse time so a caller that hands us an unverified
// state object (a synthetic test fixture, an IPC round-trip from a
// misbehaving renderer, an old build of the renderer that pre-dates the
// parse-time validation) cannot smuggle an unsafe URL through the
// precedence chain. The keyed lookup also re-runs the semver shape gate
// on the key — a key that wasn't validated at parse time (e.g. because
// the state was constructed in-memory by the caller) still cannot match.

const BRIDGE_DOWNLOAD_URL_UNSAFE_CHARS = /[\x00-\x1f\x7f\s"<>\\^`{|}]/;
const BRIDGE_DOWNLOAD_URL_MAX_LENGTH = 2048;

export function isBridgeDownloadUrlAllowed(rawUrl: unknown): boolean {
  if (typeof rawUrl !== "string") return false;
  if (rawUrl.length === 0 || rawUrl.length > BRIDGE_DOWNLOAD_URL_MAX_LENGTH) return false;
  if (BRIDGE_DOWNLOAD_URL_UNSAFE_CHARS.test(rawUrl)) return false;
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") return false;
  if (parsed.username !== "" || parsed.password !== "") return false;
  return true;
}

export function pickDownloadUrl(state: {
  bridgeDownloadUrl?: string | null;
  bridgeDownloadUrls?: Record<string, string>;
  releaseNotesUrl?: string | null;
  requiredMinVersion?: string;
}): string {
  // Iter 39 — keyed lookup wins when an exact match exists for this
  // device's `requiredMinVersion`. The defensive re-validation here
  // mirrors the iter-38 scalar branch: a future caller that
  // hand-constructs the state cannot bypass parse-time validation.
  if (
    state.bridgeDownloadUrls != null &&
    typeof state.requiredMinVersion === "string" &&
    state.requiredMinVersion.length > 0 &&
    Object.prototype.hasOwnProperty.call(state.bridgeDownloadUrls, state.requiredMinVersion)
  ) {
    const keyed = state.bridgeDownloadUrls[state.requiredMinVersion];
    if (isBridgeDownloadUrlAllowed(keyed)) {
      return keyed;
    }
  }
  if (state.bridgeDownloadUrl && isBridgeDownloadUrlAllowed(state.bridgeDownloadUrl)) {
    return state.bridgeDownloadUrl;
  }
  if (state.releaseNotesUrl) {
    return state.releaseNotesUrl;
  }
  return (
    "https://rud1.es/desktop/download?version=" +
    encodeURIComponent(state.requiredMinVersion ?? "")
  );
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
  computeDeviceBucket,
  readBodyCapped,
  MAX_MANIFEST_BYTES,
  MAX_SUPPORTED_MANIFEST_VERSION,
  SHA256_HEX_REGEX,
  // Iter 36 — re-export the auto-updater's compareSemver via this
  // module's __test hatch so the test suite for staged-migration logic
  // can exercise the helper without reaching across files.
  MIN_BOOTSTRAP_VERSION_SHAPE,
  compareSemver,
  formatBytes,
  progressBar,
  // Iter 37 — Settings/About formatters.
  formatBlockedStateMessage,
  formatVersionCheckSummary,
  // Iter 38 — bridge download URL precedence helpers.
  pickDownloadUrl,
  isBridgeDownloadUrlAllowed,
};
