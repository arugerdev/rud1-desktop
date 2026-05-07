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

export const POLL_INTERVAL_MS = 30_000;
export const STALE_THRESHOLD_MS = 3 * 60_000; // 3 min
export const RECONNECT_COOLDOWN_MS = 60_000;
export const RECONNECT_GRACE_MS = 60_000;

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
  staleThresholdMs?: number;
  cooldownMs?: number;
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
  const cooldown = input.cooldownMs ?? RECONNECT_COOLDOWN_MS;
  const grace = input.graceMs ?? RECONNECT_GRACE_MS;

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

  /** Force one tick — exposed for tests; not called from production. */
  async tick(): Promise<void> {
    if (!this.deps.enabled()) return;
    let snapshot: HandshakeSnapshot;
    try {
      snapshot = await this.deps.fetchSnapshot();
    } catch {
      // A failed `wg show` (binary missing, permission flap) shouldn't
      // panic the loop — the next tick retries.
      return;
    }
    const now = (this.deps.now ?? Date.now)();
    const fire = shouldReconnect({
      snapshot,
      lastReconnectAt: this.lastReconnectAt,
      reconnectInFlight: this.reconnectInFlight,
      now,
    });
    if (!fire) return;

    this.reconnectInFlight = true;
    this.lastReconnectAt = now;
    try {
      await this.deps.reconnect();
    } catch {
      // Reconnect itself failed. The cooldown ticks from
      // `lastReconnectAt` regardless so we don't hammer a broken
      // upstream — the next attempt is at least cooldownMs away.
    } finally {
      this.reconnectInFlight = false;
    }
  }
}
