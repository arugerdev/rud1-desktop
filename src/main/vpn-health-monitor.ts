/**
 * Auto-reconnect monitor for the WireGuard tunnel.
 *
 * After every successful `vpnConnect`, the monitor starts a 30 s
 * polling loop that asks the platform for the latest handshake age
 * via `wg show <iface> latest-handshakes`. When the most recent
 * handshake is older than `STALE_THRESHOLD_MS` (3 min by default,
 * matching the panel's stale classifier) the monitor triggers a
 * reconnect using the most recently stored config.
 *
 * Cooldown + grace handling
 *   - A successful reconnect is followed by `RECONNECT_GRACE_MS` of
 *     "no-decision" time so the loop doesn't immediately re-fire on
 *     the freshly-installed tunnel that hasn't handshaken yet.
 *   - At most one reconnect per `RECONNECT_COOLDOWN_MS` window —
 *     prevents a flapping ISP from billing us a reconnect every tick.
 *
 * The decision logic is split out as a pure function (`shouldReconnect`)
 * so the integration tests can exercise the FSM without spinning up
 * a real tunnel.
 */

// PLC-7 hardening: pre-PLC defaults were poll=30s / stale=3min / cool=60s
// / grace=60s, giving a worst-case "first attempt" of 5.5 min between a
// real loss and a recovery attempt. The new defaults bring that down
// to ~95 s peak (poll=15s + stale=75s + cool=20s on first retry,
// then exponential up to 5 min on persistent failures).
//
// Why these values:
//   - POLL_INTERVAL_MS=15s: the kernel's wg handshake interval is 25s
//     (PersistentKeepalive); polling at 15s means the snapshot is at
//     most one keepalive cycle behind the kernel. Going under 10s
//     just burns CPU on the laptop without seeing fresher data.
//   - STALE_THRESHOLD_MS=75s: 3× keepalive. A real disconnect makes
//     the device skip 2 keepalives in a row, this declares stale on
//     the 3rd missed one.
//   - RECONNECT_COOLDOWN_MS_INITIAL=20s: first retry is fast — most
//     "stale" episodes are a transient ISP blip the next handshake
//     fixes immediately. Starting with 20s lets the user recover
//     before the human even notices.
//   - RECONNECT_BACKOFF_MAX_MS=300_000: when something is genuinely
//     broken (e.g. Pi is offline for 10 min), we stop hammering it
//     and reconnect every 5 min until it comes back.
//   - RECONNECT_GRACE_MS=45s: the freshly-installed tunnel needs
//     at MOST one keepalive (25s) + two RTTs to handshake. 45s gives
//     the kernel comfortable room without pinning a "warming up"
//     status forever.
export const POLL_INTERVAL_MS = 15_000;
export const STALE_THRESHOLD_MS = 75_000;
export const RECONNECT_COOLDOWN_MS_INITIAL = 20_000;
export const RECONNECT_BACKOFF_MAX_MS = 5 * 60_000;
export const RECONNECT_GRACE_MS = 45_000;

// Legacy alias kept for any external callers that imported the
// pre-PLC-7 constant by name. Prefer RECONNECT_COOLDOWN_MS_INITIAL.
export const RECONNECT_COOLDOWN_MS = RECONNECT_COOLDOWN_MS_INITIAL;

// nextCooldownMs returns the cooldown window for the Nth consecutive
// failed reconnect attempt (1-indexed). Doubling sequence with a hard
// cap so a long outage doesn't keep retrying every 20 s for an hour.
//
//   attempt=1 → 20 s
//   attempt=2 → 40 s
//   attempt=3 → 80 s
//   attempt=4 → 160 s
//   attempt≥5 → 300 s (cap)
export function nextCooldownMs(consecutiveFailures: number): number {
  if (consecutiveFailures <= 0) return RECONNECT_COOLDOWN_MS_INITIAL;
  const doubled = RECONNECT_COOLDOWN_MS_INITIAL * Math.pow(2, consecutiveFailures - 1);
  return Math.min(doubled, RECONNECT_BACKOFF_MAX_MS);
}

export type HandshakeSnapshot =
  | { kind: "no-tunnel" }
  | { kind: "no-handshake-yet" }
  | { kind: "fresh"; handshakeAgeMs: number }
  | { kind: "stale"; handshakeAgeMs: number };

export interface ShouldReconnectInput {
  snapshot: HandshakeSnapshot;
  lastReconnectAt: number; // 0 when never reconnected
  reconnectInFlight: boolean;
  now: number;
  // PLC-7: number of consecutive reconnect attempts that did NOT
  // restore a fresh handshake. Drives the exponential backoff via
  // nextCooldownMs(consecutiveFailures). 0 on the first attempt or
  // after a successful recovery.
  consecutiveFailures?: number;
  staleThresholdMs?: number;
  cooldownMs?: number; // explicit override; ignores backoff schedule when set
  graceMs?: number;
}

/**
 * Pure FSM: given the latest health snapshot and the loop's bookkeeping,
 * decide whether the next tick should trigger a reconnect. The boolean
 * return collapses every "no" branch (idle, fresh, in-flight, cooldown)
 * — callers don't need to differentiate.
 */
export function shouldReconnect(input: ShouldReconnectInput): boolean {
  const stale = input.staleThresholdMs ?? STALE_THRESHOLD_MS;
  const grace = input.graceMs ?? RECONNECT_GRACE_MS;
  // Cooldown ladder: explicit override > exponential schedule keyed on
  // consecutiveFailures. The schedule starts at the first-retry value
  // (20 s) so a successful flow reads identically to the iter-8 fast-
  // recovery path that tests assert against.
  const cooldown =
    input.cooldownMs ?? nextCooldownMs(input.consecutiveFailures ?? 0);

  if (input.reconnectInFlight) return false;

  // No tunnel = nothing to recover. The renderer is responsible for
  // re-issuing connect when the user explicitly asks.
  if (input.snapshot.kind === "no-tunnel") return false;

  // Fresh (or never-handshaked) within the grace window after a
  // recent reconnect: the tunnel is still warming up — not stale yet.
  if (input.lastReconnectAt > 0) {
    const sinceReconnect = input.now - input.lastReconnectAt;
    if (sinceReconnect < grace) return false;
  }

  // Cooldown gate: don't fire more than once per cooldown window.
  if (input.lastReconnectAt > 0) {
    const sinceReconnect = input.now - input.lastReconnectAt;
    if (sinceReconnect < cooldown) return false;
  }

  // The actual stale signal. We treat "no handshake at all" past the
  // grace window as stale too — a tunnel that's been up for 5 min and
  // never seen a peer is just as broken as one with an old handshake.
  if (input.snapshot.kind === "stale") {
    return input.snapshot.handshakeAgeMs >= stale;
  }
  if (input.snapshot.kind === "no-handshake-yet") {
    if (input.lastReconnectAt === 0) {
      // First-ever connection: give the user `grace` from boot to
      // handshake before we declare it stale. We approximate "boot
      // time" as the moment the monitor started — but the loop
      // doesn't know that. Conservative: never reconnect on a
      // never-handshaked tunnel without a previous reconnect to
      // anchor "how long has this been not-handshaking".
      return false;
    }
    return true;
  }
  return false;
}

/**
 * Parse `wg show <iface> latest-handshakes` into a `HandshakeSnapshot`.
 * Output format is `<publickey>\t<unix-ts>` per peer; an empty stdout
 * means the tunnel doesn't exist. ts == 0 means "never handshaked".
 *
 * We keep the freshest timestamp across all peers — for rud1 there's
 * only ever one peer per tunnel, but the parser is tolerant of a
 * future multi-peer setup.
 */
export function parseHandshakeSnapshot(
  stdout: string,
  now: number,
): HandshakeSnapshot {
  if (!stdout || stdout.trim().length === 0) {
    return { kind: "no-tunnel" };
  }
  let freshest = 0;
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    // Match the trailing integer; tolerates either tab- or
    // whitespace-separated columns.
    const m = trimmed.match(/(\d+)\s*$/);
    if (!m) continue;
    const ts = Number.parseInt(m[1], 10);
    if (!Number.isFinite(ts)) continue;
    if (ts > freshest) freshest = ts;
  }
  if (freshest === 0) return { kind: "no-handshake-yet" };
  const ageMs = now - freshest * 1000;
  if (ageMs < 0) {
    // Clock skew between our wall-clock and the kernel's monotonic —
    // treat as fresh rather than negative.
    return { kind: "fresh", handshakeAgeMs: 0 };
  }
  if (ageMs >= STALE_THRESHOLD_MS) {
    return { kind: "stale", handshakeAgeMs: ageMs };
  }
  return { kind: "fresh", handshakeAgeMs: ageMs };
}

export interface MonitorDeps {
  /** Reads the latest handshake state. The platform-specific shell-
   *  out lives in vpn-manager; injection keeps this module testable. */
  fetchSnapshot: () => Promise<HandshakeSnapshot>;
  /** Performs the reconnect. The wg config lookup happens upstream in
   *  vpn-manager; we just call this and trust it. */
  reconnect: () => Promise<void>;
  /** Returns true while the user has the auto-reconnect preference
   *  toggled on. Read every tick so a Settings flip takes effect
   *  without restarting the loop. */
  enabled: () => boolean;
  /** Hook for tests — defaults to Date.now. */
  now?: () => number;
  /** Override the cadence — primarily useful in tests. */
  pollIntervalMs?: number;
}

export class VpnHealthMonitor {
  private timer: NodeJS.Timeout | null = null;
  private reconnectInFlight = false;
  private lastReconnectAt = 0;
  // PLC-7: number of consecutive reconnects that did NOT restore a
  // fresh handshake. Reset to 0 the next tick the snapshot reports
  // `fresh`. Drives the exponential backoff via nextCooldownMs.
  private consecutiveFailures = 0;
  // PLC-7: human-readable summary of the last reconnect outcome.
  // Surfaced via `lastDiagnostic()` so the renderer (panel banner)
  // can show "intentando reconectar — endpoint no responde (intento 3)"
  // instead of a silent "Stale" with no signal.
  private lastDiagnostic: string = "";
  private readonly deps: MonitorDeps;

  constructor(deps: MonitorDeps) {
    this.deps = deps;
  }

  start(): void {
    if (this.timer) return;
    const interval = this.deps.pollIntervalMs ?? POLL_INTERVAL_MS;
    this.timer = setInterval(() => {
      void this.tick();
    }, interval);
    if (typeof this.timer.unref === "function") this.timer.unref();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.reconnectInFlight = false;
  }

  /** Read-only accessor for the latest reconnect outcome description. */
  getLastDiagnostic(): string {
    return this.lastDiagnostic;
  }

  /** Read-only accessor for the consecutive-failure counter. */
  getConsecutiveFailures(): number {
    return this.consecutiveFailures;
  }

  /** Force one tick — exposed for tests; not called from production. */
  async tick(): Promise<void> {
    if (!this.deps.enabled()) return;
    let snapshot: HandshakeSnapshot;
    try {
      snapshot = await this.deps.fetchSnapshot();
    } catch {
      // A failed `wg show` (binary missing, permission flap) shouldn't
      // panic the loop — the next tick retries.
      this.lastDiagnostic = "wg show falló (¿permisos?)";
      return;
    }

    // Fresh handshake observed: clear the failure streak so the next
    // genuine outage starts the cooldown ladder from 20 s again
    // instead of inheriting a stale 5-min back-off.
    if (snapshot.kind === "fresh") {
      if (this.consecutiveFailures > 0) {
        this.lastDiagnostic = `Conexión estable tras ${this.consecutiveFailures} reintentos`;
      } else {
        this.lastDiagnostic = "Conectado (handshake fresco)";
      }
      this.consecutiveFailures = 0;
    }

    const now = (this.deps.now ?? Date.now)();
    const fire = shouldReconnect({
      snapshot,
      lastReconnectAt: this.lastReconnectAt,
      reconnectInFlight: this.reconnectInFlight,
      consecutiveFailures: this.consecutiveFailures,
      now,
    });
    if (!fire) return;

    this.reconnectInFlight = true;
    this.lastReconnectAt = now;
    const attempt = this.consecutiveFailures + 1;
    this.lastDiagnostic = `Reconectando (intento ${attempt})…`;
    try {
      await this.deps.reconnect();
      // Reconnect call succeeded at the API level. We DON'T zero
      // consecutiveFailures here — only an actual fresh handshake on
      // the next tick proves recovery. A `wg-quick up` that returns 0
      // but never hands-shakes (e.g. wrong endpoint, blocked by
      // firewall) still needs to count as a failure so the ladder
      // stretches.
      this.consecutiveFailures = attempt;
      this.lastDiagnostic = `Tunel re-instalado (intento ${attempt}); esperando handshake`;
    } catch (err) {
      this.consecutiveFailures = attempt;
      const reason = err instanceof Error ? err.message : "error desconocido";
      this.lastDiagnostic = `Reconexión falló (intento ${attempt}): ${reason}`;
    } finally {
      this.reconnectInFlight = false;
    }
  }
}
