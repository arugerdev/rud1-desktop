import { describe, expect, it } from "vitest";

import {
  SESSION_CAP,
  SESSION_TTL_MS,
  addSession,
  enforceCap,
  pruneExpiredSessions,
  removeSessionByBusId,
  removeSessionByPort,
  type AttachedUsbSession,
} from "./usb-session-state";

const MOCK_NOW = new Date("2026-05-08T12:00:00.000Z");

function mkSession(
  busId: string,
  host = "rud1.local",
  attachedAtIso = MOCK_NOW.toISOString(),
  port?: number,
  label?: string,
): AttachedUsbSession {
  return { host, busId, attachedAt: attachedAtIso, port, label };
}

describe("addSession", () => {
  it("appends a new entry", () => {
    const out = addSession([], mkSession("1-1.4"));
    expect(out).toHaveLength(1);
    expect(out[0].busId).toBe("1-1.4");
  });

  it("replaces an existing entry by (host, busId)", () => {
    const old = mkSession("1-1.4", "rud1.local", "2026-04-01T00:00:00.000Z");
    const fresh = mkSession("1-1.4", "rud1.local", MOCK_NOW.toISOString(), 7);
    const out = addSession([old], fresh);
    expect(out).toHaveLength(1);
    expect(out[0].port).toBe(7);
    expect(out[0].attachedAt).toBe(MOCK_NOW.toISOString());
  });

  it("keeps a same-busId entry under a different host as separate", () => {
    const a = mkSession("1-1.4", "rud1.local");
    const b = mkSession("1-1.4", "rud1-spare.local");
    const out = addSession([a], b);
    expect(out).toHaveLength(2);
  });
});

describe("removeSessionByBusId", () => {
  it("drops every entry with the given busId across hosts", () => {
    const sessions = [
      mkSession("1-1.4", "rud1.local"),
      mkSession("1-1.4", "rud1-spare.local"),
      mkSession("1-1.5", "rud1.local"),
    ];
    const out = removeSessionByBusId(sessions, "1-1.4");
    expect(out).toHaveLength(1);
    expect(out[0].busId).toBe("1-1.5");
  });
});

describe("removeSessionByPort", () => {
  it("drops only the entry with the matching port", () => {
    const sessions = [
      mkSession("1-1.4", "rud1.local", MOCK_NOW.toISOString(), 5),
      mkSession("1-1.5", "rud1.local", MOCK_NOW.toISOString(), 6),
    ];
    const out = removeSessionByPort(sessions, 5);
    expect(out).toHaveLength(1);
    expect(out[0].busId).toBe("1-1.5");
  });
});

describe("pruneExpiredSessions", () => {
  it("drops sessions older than the TTL", () => {
    const fresh = mkSession("1-1.4", "rud1.local", MOCK_NOW.toISOString());
    const stale = mkSession(
      "1-1.5",
      "rud1.local",
      new Date(MOCK_NOW.getTime() - SESSION_TTL_MS - 1).toISOString(),
    );
    const out = pruneExpiredSessions([fresh, stale], MOCK_NOW);
    expect(out).toEqual([fresh]);
  });

  it("drops sessions with malformed timestamps", () => {
    const bad = { ...mkSession("1-1.4"), attachedAt: "not-a-date" };
    const out = pruneExpiredSessions([bad as AttachedUsbSession], MOCK_NOW);
    expect(out).toEqual([]);
  });
});

describe("enforceCap", () => {
  it("keeps the newest entries when over the cap", () => {
    const sessions: AttachedUsbSession[] = Array.from({ length: SESSION_CAP + 5 }, (_, i) =>
      mkSession(
        `1-${i + 1}`,
        "rud1.local",
        new Date(MOCK_NOW.getTime() + i * 1000).toISOString(),
      ),
    );
    const out = enforceCap(sessions);
    expect(out).toHaveLength(SESSION_CAP);
    // Earliest by attachedAt should be evicted; busId 1-1..1-5 fall off.
    expect(out[0].busId).toBe(`1-6`);
  });

  it("returns the input as-is when under the cap", () => {
    const sessions = [mkSession("1-1.4")];
    const out = enforceCap(sessions);
    expect(out).toEqual(sessions);
    expect(out).not.toBe(sessions);
  });
});
