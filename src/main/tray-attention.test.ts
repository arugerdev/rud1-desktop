/**
 * Unit tests for the tray-attention pure state machine (iter 28).
 *
 * Scope: just the `computeTrayState` / `formatTrayTitle` /
 * `formatTrayTooltip` helpers — the side-effecting `applyTrayState` in
 * index.ts is intentionally NOT tested here because it requires a live
 * Tray instance. The pure helpers are the load-bearing logic — the apply
 * step is a thin `tray.setTitle` + `tray.setToolTip` wrapper.
 *
 * The state machine has four interesting transitions, mirroring the
 * iter 28 spec:
 *
 *   • 0 → 0   (idle tick)             — `changed=false`, tooltip stays default
 *   • 0 → N   (rising edge)           — `changed=true`,  attention title set
 *   • N → 0   (falling edge)          — `changed=true`,  title cleared
 *   • N → M   (count update)          — `changed=true`,  title reflects M
 *
 * Plus edge cases that the probe loop won't produce but the IPC surface
 * might (NaN, negative, fractional). They're collapsed to 0.
 */

import { describe, expect, it } from "vitest";

import {
  computeTrayState,
  formatTrayTitle,
  formatTrayTooltip,
} from "./tray-attention";

describe("formatTrayTitle", () => {
  it("returns empty for zero", () => {
    expect(formatTrayTitle(0)).toBe("");
  });

  it("formats a single-digit count with leading space", () => {
    expect(formatTrayTitle(1)).toBe(" 1");
    expect(formatTrayTitle(7)).toBe(" 7");
    expect(formatTrayTitle(9)).toBe(" 9");
  });

  it("caps overflow at '9+'", () => {
    expect(formatTrayTitle(10)).toBe(" 9+");
    expect(formatTrayTitle(42)).toBe(" 9+");
  });

  it("clamps non-positive / non-finite counts to empty", () => {
    expect(formatTrayTitle(-3)).toBe("");
    expect(formatTrayTitle(Number.NaN)).toBe("");
    expect(formatTrayTitle(Number.POSITIVE_INFINITY)).toBe("");
  });

  it("floors fractional counts before formatting", () => {
    expect(formatTrayTitle(2.7)).toBe(" 2");
    // 0.5 floors to 0 — must produce empty, not " 0".
    expect(formatTrayTitle(0.5)).toBe("");
  });
});

describe("formatTrayTooltip", () => {
  it("returns the default tooltip when count is zero", () => {
    expect(formatTrayTooltip(0)).toBe("rud1 Desktop");
  });

  it("uses singular phrasing for exactly 1 device", () => {
    expect(formatTrayTooltip(1)).toBe("rud1 Desktop — 1 device ready to configure");
  });

  it("uses plural phrasing for >= 2 devices", () => {
    expect(formatTrayTooltip(2)).toBe("rud1 Desktop — 2 devices ready to configure");
    expect(formatTrayTooltip(15)).toBe("rud1 Desktop — 15 devices ready to configure");
  });

  it("clamps invalid counts to the default tooltip", () => {
    expect(formatTrayTooltip(-1)).toBe("rud1 Desktop");
    expect(formatTrayTooltip(Number.NaN)).toBe("rud1 Desktop");
  });
});

describe("computeTrayState — transitions", () => {
  it("0 → 0 is a no-op (changed=false, default tooltip)", () => {
    const t = computeTrayState(0, 0);
    expect(t.changed).toBe(false);
    expect(t.next.title).toBe("");
    expect(t.next.tooltip).toBe("rud1 Desktop");
  });

  it("0 → N raises attention (changed=true, title set, plural tooltip)", () => {
    const t = computeTrayState(0, 3);
    expect(t.changed).toBe(true);
    expect(t.prev.count).toBe(0);
    expect(t.next.count).toBe(3);
    expect(t.next.title).toBe(" 3");
    expect(t.next.tooltip).toBe("rud1 Desktop — 3 devices ready to configure");
  });

  it("N → 0 clears attention (changed=true, empty title, default tooltip)", () => {
    const t = computeTrayState(2, 0);
    expect(t.changed).toBe(true);
    expect(t.prev.count).toBe(2);
    expect(t.next.count).toBe(0);
    expect(t.next.title).toBe("");
    expect(t.next.tooltip).toBe("rud1 Desktop");
  });

  it("N → M (different non-zero) updates the badge (changed=true)", () => {
    const t = computeTrayState(1, 2);
    expect(t.changed).toBe(true);
    expect(t.next.title).toBe(" 2");
    expect(t.next.tooltip).toBe("rud1 Desktop — 2 devices ready to configure");
  });

  it("N → N (same non-zero) is a no-op (changed=false)", () => {
    const t = computeTrayState(2, 2);
    expect(t.changed).toBe(false);
    expect(t.next.title).toBe(" 2");
    expect(t.next.tooltip).toBe("rud1 Desktop — 2 devices ready to configure");
  });

  it("clamps NaN/negative inputs to 0 — preserves changed=false on no-op", () => {
    const t = computeTrayState(Number.NaN, -5);
    expect(t.changed).toBe(false);
    expect(t.next.count).toBe(0);
    expect(t.next.title).toBe("");
  });

  it("9+ overflow boundary still flips to changed when count crosses 9 → 10", () => {
    const t = computeTrayState(9, 10);
    // The displayed title is the same shape (" 9+" vs " 9"), but the
    // count truly differs so we DO want to push a tooltip update — the
    // tooltip text changes from "9 devices" to "10 devices".
    expect(t.changed).toBe(true);
    expect(t.next.title).toBe(" 9+");
    expect(t.next.tooltip).toBe("rud1 Desktop — 10 devices ready to configure");
  });
});
