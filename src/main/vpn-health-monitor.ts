// Poll=15s (1 keepalive cycle), stale=75s (3x keepalive), cool=20s exp backoff a 5min, grace=45s.
export const POLL_INTERVAL_MS = 15_000;
export const STALE_THRESHOLD_MS = 75_000;
export const RECONNECT_COOLDOWN_MS_INITIAL = 20_000;
export const RECONNECT_BACKOFF_MAX_MS = 5 * 60_000;
export const RECONNECT_GRACE_MS = 45_000;

export const RECONNECT_COOLDOWN_MS = RECONNECT_COOLDOWN_MS_INITIAL;

// Cooldown duplica por intento; cap a 5min.
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
  cooldownMs?: number;
  graceMs?: number;
}

export function shouldReconnect(input: ShouldReconnectInput): boolean {
  const stale = input.staleThresholdMs ?? STALE_THRESHOLD_MS;
  const grace = input.graceMs ?? RECONNECT_GRACE_MS;
  const cooldown =
    input.cooldownMs ?? nextCooldownMs(input.consecutiveFailures ?? 0);

  if (input.reconnectInFlight) return false;

  if (input.snapshot.kind === "no-tunnel") return false;

  if (input.lastReconnectAt > 0) {
    const sinceReconnect = input.now - input.lastReconnectAt;
    if (sinceReconnect < grace) return false;
  }

  if (input.lastReconnectAt > 0) {
    const sinceReconnect = input.now - input.lastReconnectAt;
    if (sinceReconnect < cooldown) return false;
  }

  if (input.snapshot.kind === "stale") {
    return input.snapshot.handshakeAgeMs >= stale;
  }
  if (input.snapshot.kind === "no-handshake-yet") {
    // Conservative: nunca reconectar sin un previous reconnect que ancle el cómputo.
    if (input.lastReconnectAt === 0) return false;
    return true;
  }
  return false;
}

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
    const m = trimmed.match(/(\d+)\s*$/);
    if (!m) continue;
    const ts = Number.parseInt(m[1], 10);
    if (!Number.isFinite(ts)) continue;
    if (ts > freshest) freshest = ts;
  }
  if (freshest === 0) return { kind: "no-handshake-yet" };
  const ageMs = now - freshest * 1000;
  // Clock skew vs kernel monotonic: trata como fresh.
  if (ageMs < 0) return { kind: "fresh", handshakeAgeMs: 0 };
  if (ageMs >= STALE_THRESHOLD_MS) {
    return { kind: "stale", handshakeAgeMs: ageMs };
  }
  return { kind: "fresh", handshakeAgeMs: ageMs };
}

// onHealthChange dispara sólo en transitions, no en steady-state ticks.
/**
 *   "down"        → handshake just went stale OR the tunnel disappeared
 *                   while the monitor thought it was healthy.
 *   "recovering"  → reconnect attempted but no fresh handshake yet.
 *   "up"          → fresh handshake observed after a previous down/recovering.
 */
export type VpnHealthTransition = "down" | "recovering" | "up";

export interface VpnHealthChangeEvent {
  transition: VpnHealthTransition;
  /** Latest snapshot the FSM saw. Useful for the renderer to render
   *  precise text ("Handshake 4m ago" on a "down" event). */
  snapshot: HandshakeSnapshot;
  /** Same `lastDiagnostic` string the monitor surfaces internally — kept
   *  in sync with the transition so the caller doesn't have to compose
   *  the message themselves. */
  diagnostic: string;
  /** Consecutive failed reconnects at the time of the event (0 on `up`). */
  consecutiveFailures: number;
  /** Wall-clock ms when the event was emitted (`deps.now()` value). */
  at: number;
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
  /**
   * Iter 71: invoked on every observable health transition (NOT on every
   * tick — steady state stays quiet). The handler runs synchronously
   * inside `tick()`; throw / reject is swallowed so a broken consumer
   * never wedges the monitor. Optional — pre-iter71 callers (tests,
   * legacy entry points) keep the same behaviour when this is omitted.
   */
  onHealthChange?: (event: VpnHealthChangeEvent) => void;
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
  // Iter 71: high-level health classification carried across ticks so
  // we can detect *transitions* and emit `onHealthChange` only when the
  // user-visible signal changes (steady ticks stay quiet). "unknown"
  // is the initial state — the very first tick after `start()` always
  // emits something concrete (up/down/recovering) so consumers can
  // paint their initial banner without waiting for a real transition.
  private lastHealth: "unknown" | VpnHealthTransition = "unknown";
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
    // Iter 71: emit a health transition BEFORE deciding whether to
    // reconnect. We want the "tunnel dropped" notification to land as
    // soon as we observe the stale signal, not after a 20-30 s
    // reconnect attempt completes.
    this.maybeEmitTransition(snapshot, now);

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
    // Iter 71: surface the "recovering" transition before the actual
    // wg-quick call so the renderer can paint a spinner while the
    // reconnect is in flight (typically 1-3 s on Windows, less on Unix).
    this.emitTransition("recovering", snapshot, now);
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

  // Iter 71: maps a snapshot to a transition label and emits via the
  // optional `onHealthChange` callback. Only emits when the resolved
  // transition differs from `lastHealth` so the consumer sees one
  // event per *change* rather than one per tick. Initial transition
  // from "unknown" always fires so consumers get an anchor state.
  private maybeEmitTransition(
    snapshot: HandshakeSnapshot,
    now: number,
  ): void {
    let next: VpnHealthTransition;
    if (snapshot.kind === "fresh") {
      next = "up";
    } else if (
      snapshot.kind === "stale" ||
      snapshot.kind === "no-tunnel" ||
      // "no-handshake-yet" after the grace window is "down" too. We
      // approximate the boundary by checking whether a previous
      // reconnect anchored the timeline; identical to shouldReconnect's
      // grace logic so the events line up with the reconnect attempts.
      (snapshot.kind === "no-handshake-yet" && this.lastReconnectAt > 0)
    ) {
      next = "down";
    } else {
      // Initial "no-handshake-yet" with no prior reconnect: we don't
      // know if the tunnel is warming up or genuinely broken. Treat as
      // recovering so the renderer shows a neutral spinner rather than
      // a scary "disconnected" banner during the first 30 s of a
      // legitimate connect.
      next = "recovering";
    }
    if (this.lastHealth === next) return;
    this.emitTransition(next, snapshot, now);
  }

  // Always-fire emit (callers gate on transition logic upstream). Pulls
  // the diagnostic string + failure count so the consumer doesn't have
  // to call two more getters to render the notification body.
  private emitTransition(
    transition: VpnHealthTransition,
    snapshot: HandshakeSnapshot,
    now: number,
  ): void {
    this.lastHealth = transition;
    const cb = this.deps.onHealthChange;
    if (!cb) return;
    try {
      cb({
        transition,
        snapshot,
        diagnostic: this.lastDiagnostic,
        consecutiveFailures: this.consecutiveFailures,
        at: now,
      });
    } catch {
      // A broken renderer-side listener must never wedge the polling
      // loop. We deliberately swallow without logging — the consumer
      // owns its own error reporting.
    }
  }

  /** Iter 71: read-only view of the most recent transition the monitor
   *  emitted. Returns "unknown" before the first tick has run. Used by
   *  consumers (tray tooltip) that come online after the monitor has
   *  been ticking and want to render the current state without waiting
   *  for the next transition. */
  getLastHealth(): "unknown" | VpnHealthTransition {
    return this.lastHealth;
  }
}
