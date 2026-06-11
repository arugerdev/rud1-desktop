// Pure: macOS usa setTitle, Win/Linux usa tooltip + icon swap.
import { t } from "./i18n";

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

// Leading space + "9+" cap evita romper la menu-bar.
export function formatTrayTitle(count: number): string {
  if (!Number.isFinite(count) || count <= 0) return "";
  const n = Math.floor(count);
  if (n <= 0) return "";
  if (n > 9) return " 9+";
  return ` ${n}`;
}

export function formatTrayTooltip(count: number): string {
  const n = Number.isFinite(count) && count > 0 ? Math.floor(count) : 0;
  if (n <= 0) return t("tray.tooltipBase");
  if (n === 1) return t("tray.tooltipOneDevice");
  return t("tray.tooltipManyDevices", { count: n });
}

export type TrayVpnHealth = "unknown" | "up" | "down" | "recovering";

export function formatTrayTooltipWithVpn(
  count: number,
  vpn: TrayVpnHealth,
): string {
  const base = formatTrayTooltip(count);
  if (vpn === "down") return `${base} — ${t("tray.vpnDown")}`;
  if (vpn === "recovering") return `${base} — ${t("tray.vpnRecovering")}`;
  return base;
}

export function computeTrayState(
  prevCount: number,
  newCount: number,
): TrayStateTransition {
  // Coerce no-finite/neg a 0 (NaN!==NaN pinearía changed=true cada tick).
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
