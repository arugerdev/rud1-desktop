import { describe, expect, it, vi } from "vitest";

import {
  STALE_THRESHOLD_MS,
  VpnHealthMonitor,
  parseHandshakeSnapshot,
  shouldReconnect,
  type HandshakeSnapshot,
  type VpnHealthChangeEvent,
} from "./vpn-health-monitor";

describe("parseHandshakeSnapshot", () => {
  const NOW = 10_000_000_000; // arbitrary fixed wall-clock for the suite

  it("classifies an empty stdout as 'no tunnel'", () => {
    expect(parseHandshakeSnapshot("", NOW)).toEqual({ kind: "no-tunnel" });
    expect(parseHandshakeSnapshot("   \n  ", NOW)).toEqual({ kind: "no-tunnel" });
  });

  it("classifies ts=0 as 'no handshake yet'", () => {
    expect(
      parseHandshakeSnapshot("BJxxx=\t0", NOW),
    ).toEqual({ kind: "no-handshake-yet" });
  });

  it("classifies a recent ts as 'fresh'", () => {
    const ts = Math.floor(NOW / 1000) - 30; // 30 s ago
    const out = parseHandshakeSnapshot(`BJxxx=\t${ts}`, NOW);
    expect(out.kind).toBe("fresh");
    if (out.kind === "fresh") {
      expect(out.handshakeAgeMs).toBeGreaterThanOrEqual(29_000);
      expect(out.handshakeAgeMs).toBeLessThanOrEqual(31_000);
    }
  });

  it("classifies an old ts as 'stale'", () => {
    const ts = Math.floor(NOW / 1000) - 600; // 10 min ago
    const out = parseHandshakeSnapshot(`BJxxx=\t${ts}`, NOW);
    expect(out.kind).toBe("stale");
    if (out.kind === "stale") {
      expect(out.handshakeAgeMs).toBeGreaterThan(STALE_THRESHOLD_MS);
    }
  });

  it("keeps the FRESHEST handshake when multiple peers are reported", () => {
    const recent = Math.floor(NOW / 1000) - 10;
    const old = Math.floor(NOW / 1000) - 1000;
    const stdout = `BJaaa=\t${old}\nBJbbb=\t${recent}`;
    const out = parseHandshakeSnapshot(stdout, NOW);
    expect(out.kind).toBe("fresh");
  });

  it("treats clock skew (negative age) as fresh, not negative", () => {
    const future = Math.floor(NOW / 1000) + 60;
    const out = parseHandshakeSnapshot(`BJxxx=\t${future}`, NOW);
    expect(out).toEqual({ kind: "fresh", handshakeAgeMs: 0 });
  });

  it("ignores malformed lines without crashing", () => {
    const ts = Math.floor(NOW / 1000) - 5;
    const stdout = `garbage line without ts\nBJxxx=\t${ts}\n   \n: comment`;
    const out = parseHandshakeSnapshot(stdout, NOW);
    expect(out.kind).toBe("fresh");
  });
});

describe("shouldReconnect FSM", () => {
  const baseInput = {
    lastReconnectAt: 0,
    reconnectInFlight: false,
    now: 1_000_000,
  };

  it("never reconnects when a reconnect is already in flight", () => {
    expect(
      shouldReconnect({
        ...baseInput,
        reconnectInFlight: true,
        snapshot: { kind: "stale", handshakeAgeMs: 999_999 },
      }),
    ).toBe(false);
  });

  it("reconnects immediately when no tunnel is up and there is no prior anchor", () => {
    // The monitor is only armed by a successful connect and stopped by an
    // explicit disconnect, so a "no-tunnel" tick means openvpn died after
    // connecting — auto-recover.
    expect(
      shouldReconnect({
        ...baseInput,
        snapshot: { kind: "no-tunnel" },
      }),
    ).toBe(true);
  });

  it("does NOT reconnect on no-tunnel while still inside the cooldown window", () => {
    expect(
      shouldReconnect({
        ...baseInput,
        lastReconnectAt: baseInput.now - 10_000, // 10 s ago, inside 20s cooldown
        snapshot: { kind: "no-tunnel" },
      }),
    ).toBe(false);
  });

  it("reconnects again on no-tunnel once the cooldown has elapsed", () => {
    expect(
      shouldReconnect({
        ...baseInput,
        lastReconnectAt: baseInput.now - 120_000, // 2 min ago
        snapshot: { kind: "no-tunnel" },
      }),
    ).toBe(true);
  });

  it("never reconnects when the handshake is fresh", () => {
    expect(
      shouldReconnect({
        ...baseInput,
        snapshot: { kind: "fresh", handshakeAgeMs: 5_000 },
      }),
    ).toBe(false);
  });

  it("reconnects on first stale detection (no prior reconnect)", () => {
    expect(
      shouldReconnect({
        ...baseInput,
        snapshot: { kind: "stale", handshakeAgeMs: 4 * 60_000 },
      }),
    ).toBe(true);
  });

  it("does NOT reconnect within the cooldown window after a recent attempt", () => {
    // PLC-7 hardening: default cooldown for the FIRST retry is 20 s
    // (consecutiveFailures=0 → first ladder rung). 10 s ago is still
    // inside that window.
    expect(
      shouldReconnect({
        ...baseInput,
        lastReconnectAt: baseInput.now - 10_000, // 10 s ago
        snapshot: { kind: "stale", handshakeAgeMs: 5 * 60_000 },
      }),
    ).toBe(false);
  });

  it("reconnects again once the cooldown has elapsed", () => {
    expect(
      shouldReconnect({
        ...baseInput,
        lastReconnectAt: baseInput.now - 120_000, // 2 min ago
        snapshot: { kind: "stale", handshakeAgeMs: 5 * 60_000 },
      }),
    ).toBe(true);
  });

  it("backoff stretches with consecutiveFailures: 5 attempts later, 60 s is still inside the window", () => {
    // PLC-7: after 5 consecutive failed reconnects the cooldown is
    // capped at 5 min. 60 s ago is therefore still inside the window
    // even though it would clear the iter-8 default of 20 s.
    expect(
      shouldReconnect({
        ...baseInput,
        lastReconnectAt: baseInput.now - 60_000, // 1 min ago
        consecutiveFailures: 5,
        snapshot: { kind: "stale", handshakeAgeMs: 10 * 60_000 },
      }),
    ).toBe(false);
  });

  it("backoff respects the 5-min cap: 6 min after the last attempt fires regardless of failures", () => {
    expect(
      shouldReconnect({
        ...baseInput,
        lastReconnectAt: baseInput.now - 6 * 60_000, // 6 min ago
        consecutiveFailures: 99, // saturated
        snapshot: { kind: "stale", handshakeAgeMs: 10 * 60_000 },
      }),
    ).toBe(true);
  });

  it("does NOT reconnect on no-handshake-yet without a prior reconnect anchor", () => {
    expect(
      shouldReconnect({
        ...baseInput,
        snapshot: { kind: "no-handshake-yet" },
      }),
    ).toBe(false);
  });

  it("DOES reconnect on no-handshake-yet past the cooldown after a previous reconnect", () => {
    expect(
      shouldReconnect({
        ...baseInput,
        lastReconnectAt: baseInput.now - 120_000,
        snapshot: { kind: "no-handshake-yet" },
      }),
    ).toBe(true);
  });

  it("respects an injected stale threshold", () => {
    // 90 s threshold + 100 s age = stale
    expect(
      shouldReconnect({
        ...baseInput,
        snapshot: { kind: "stale", handshakeAgeMs: 100_000 },
        staleThresholdMs: 90_000,
      }),
    ).toBe(true);
    // 200 s threshold + 100 s age = NOT stale
    expect(
      shouldReconnect({
        ...baseInput,
        snapshot: { kind: "stale", handshakeAgeMs: 100_000 },
        staleThresholdMs: 200_000,
      }),
    ).toBe(false);
  });
});

// Iter 71: the monitor's `onHealthChange` callback is the surface main
// uses to drive notifications + tray tooltip + renderer broadcasts.
// These tests pin: (a) one event per transition (no per-tick spam),
// (b) the initial transition fires, (c) the synthetic "recovering"
// event lands between the stale-detection tick and the actual reconnect.
describe("VpnHealthMonitor.onHealthChange transitions", () => {
  // Build a monitor with deterministic snapshot + reconnect deps. The
  // snapshot value is mutated between ticks so the FSM sees the
  // operator-visible scenario play out.
  function makeMonitor(opts: {
    initialSnapshot: HandshakeSnapshot;
    reconnect?: () => Promise<void>;
    onHealthChange?: (event: VpnHealthChangeEvent) => void;
    enabled?: () => boolean;
  }) {
    let snap = opts.initialSnapshot;
    const monitor = new VpnHealthMonitor({
      fetchSnapshot: async () => snap,
      reconnect: opts.reconnect ?? (async () => undefined),
      enabled: opts.enabled ?? (() => true),
      onHealthChange: opts.onHealthChange,
      now: () => 5_000_000, // anchored; tests that exercise time can stub
    });
    const setSnapshot = (next: HandshakeSnapshot) => {
      snap = next;
    };
    return { monitor, setSnapshot };
  }

  it("fires a single 'up' event on the first fresh tick and stays quiet afterwards", async () => {
    const events: VpnHealthChangeEvent[] = [];
    const { monitor } = makeMonitor({
      initialSnapshot: { kind: "fresh", handshakeAgeMs: 5_000 },
      onHealthChange: (e) => events.push(e),
    });
    await monitor.tick();
    await monitor.tick();
    await monitor.tick();
    expect(events.length).toBe(1);
    expect(events[0]?.transition).toBe("up");
  });

  it("fires 'down' when a fresh handshake goes stale", async () => {
    const events: VpnHealthChangeEvent[] = [];
    const { monitor, setSnapshot } = makeMonitor({
      initialSnapshot: { kind: "fresh", handshakeAgeMs: 5_000 },
      onHealthChange: (e) => events.push(e),
    });
    await monitor.tick(); // first "up"
    setSnapshot({ kind: "stale", handshakeAgeMs: 4 * 60_000 });
    await monitor.tick(); // observes stale → "down" then "recovering" (reconnect fires)
    const transitions = events.map((e) => e.transition);
    expect(transitions[0]).toBe("up");
    expect(transitions).toContain("down");
    // "recovering" lands BEFORE the reconnect resolves because the FSM
    // gates on shouldReconnect() which sees an anchor-less stale → fires.
    expect(transitions).toContain("recovering");
  });

  it("fires 'up' when a previously-stale tunnel recovers", async () => {
    const events: VpnHealthChangeEvent[] = [];
    const { monitor, setSnapshot } = makeMonitor({
      // Pretend the desktop opened mid-outage — first observable state
      // is stale. consecutiveFailures stays 0 because the monitor only
      // bumps it inside tick() after a reconnect attempt.
      initialSnapshot: { kind: "stale", handshakeAgeMs: 4 * 60_000 },
      onHealthChange: (e) => events.push(e),
    });
    await monitor.tick();
    setSnapshot({ kind: "fresh", handshakeAgeMs: 2_000 });
    await monitor.tick();
    const transitions = events.map((e) => e.transition);
    expect(transitions[transitions.length - 1]).toBe("up");
  });

  it("does NOT re-emit the same transition on consecutive ticks", async () => {
    const events: VpnHealthChangeEvent[] = [];
    const { monitor } = makeMonitor({
      initialSnapshot: { kind: "fresh", handshakeAgeMs: 5_000 },
      onHealthChange: (e) => events.push(e),
    });
    for (let i = 0; i < 10; i++) {
      await monitor.tick();
    }
    expect(events).toHaveLength(1);
  });

  it("a throwing handler does not wedge the polling loop", async () => {
    let calls = 0;
    const { monitor } = makeMonitor({
      initialSnapshot: { kind: "fresh", handshakeAgeMs: 1_000 },
      onHealthChange: () => {
        calls++;
        throw new Error("boom");
      },
    });
    // Each tick should complete cleanly. The handler is called once
    // (transition fires only on the initial "up") and the second tick
    // is steady-state so it doesn't call the handler at all.
    await expect(monitor.tick()).resolves.toBeUndefined();
    await expect(monitor.tick()).resolves.toBeUndefined();
    expect(calls).toBe(1);
  });

  it("getLastHealth() reports the most recently emitted transition", async () => {
    const { monitor, setSnapshot } = makeMonitor({
      initialSnapshot: { kind: "fresh", handshakeAgeMs: 1_000 },
    });
    expect(monitor.getLastHealth()).toBe("unknown");
    await monitor.tick();
    expect(monitor.getLastHealth()).toBe("up");
    setSnapshot({ kind: "stale", handshakeAgeMs: 5 * 60_000 });
    await monitor.tick();
    // The stale tick emits "down" first then "recovering" (because the
    // FSM fires a reconnect attempt). getLastHealth therefore reports
    // the most recent of the two — "recovering".
    expect(monitor.getLastHealth()).toBe("recovering");
  });

  it("does NOT call the handler when enabled() returns false", async () => {
    const handler = vi.fn();
    const { monitor } = makeMonitor({
      initialSnapshot: { kind: "stale", handshakeAgeMs: 9 * 60_000 },
      onHealthChange: handler,
      enabled: () => false,
    });
    await monitor.tick();
    expect(handler).not.toHaveBeenCalled();
  });
});
