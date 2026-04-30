// Pure state machine for the tray-icon "attention" badge: given the
// previous and new first-boot host counts, returns the tray fields the
// caller in index.ts pushes to Electron. Kept side-effect-free so the
// policy is exhaustively unit-testable without a real Tray.
//
// macOS uses `tray.setTitle()` for an always-visible count next to the
// menu-bar icon; on Win/Linux setTitle no-ops, so the tooltip + the
// idle/attention icon swap (in tray.ts) carry the signal.

export interface TrayAttentionState {
  count: number;
  title: string;
  tooltip: string;
}

export type TrayIconKind = "idle" | "attention";

export interface TrayStateTransition {
  prev: TrayAttentionState;
  next: TrayAttentionState;
  changed: boolean;
  prevIcon: TrayIconKind;
  nextIcon: TrayIconKind;
  iconChanged: boolean;
}

export function iconStateForCount(count: number): TrayIconKind {
  if (!Number.isFinite(count) || count <= 0) return "idle";
  return Math.floor(count) > 0 ? "attention" : "idle";
}

// Leading space keeps the digit from rendering flush against the icon
// (subscript-looking at menu-bar font sizes); cap at "9+" so the title
// can't blow out menu-bar real estate on a fleet network.
export function formatTrayTitle(count: number): string {
  if (!Number.isFinite(count) || count <= 0) return "";
  const n = Math.floor(count);
  if (n <= 0) return "";
  if (n > 9) return " 9+";
  return ` ${n}`;
}

export function formatTrayTooltip(count: number): string {
  const n = Number.isFinite(count) && count > 0 ? Math.floor(count) : 0;
  if (n <= 0) return "rud1 Desktop";
  if (n === 1) return "rud1 Desktop — 1 device ready to configure";
  return `rud1 Desktop — ${n} devices ready to configure`;
}

export function computeTrayState(
  prevCount: number,
  newCount: number,
): TrayStateTransition {
  // Coerce non-finite/negative to 0 — `NaN !== NaN` would otherwise pin
  // `changed` to true on every tick. Probe loop never emits these, but
  // the IPC surface might once a renderer-driven override lands.
  const prev = clampCount(prevCount);
  const next = clampCount(newCount);
  const prevIcon = iconStateForCount(prev);
  const nextIcon = iconStateForCount(next);
  return {
    prev: {
      count: prev,
      title: formatTrayTitle(prev),
      tooltip: formatTrayTooltip(prev),
    },
    next: {
      count: next,
      title: formatTrayTitle(next),
      tooltip: formatTrayTooltip(next),
    },
    changed: prev !== next,
    prevIcon,
    nextIcon,
    iconChanged: prevIcon !== nextIcon,
  };
}

function clampCount(n: number): number {
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}
