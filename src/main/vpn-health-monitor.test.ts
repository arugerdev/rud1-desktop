import { describe, expect, it } from "vitest";

import {
  STALE_THRESHOLD_MS,
  parseHandshakeSnapshot,
  shouldReconnect,
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

  it("never reconnects when no tunnel is up", () => {
    expect(
      shouldReconnect({
        ...baseInput,
        snapshot: { kind: "no-tunnel" },
      }),
    ).toBe(false);
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
