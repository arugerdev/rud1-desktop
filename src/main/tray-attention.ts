/**
 * tray-attention — pure state machine for the tray-icon "attention" badge
 * (iter 28).
 *
 * Iter 25–27 surfaced first-boot LAN devices via:
 *   • the tray context-menu CTA (visible only when the operator opens the
 *     menu — easy to miss),
 *   • a one-shot OS notification on the rising edge (also easy to miss
 *     if the operator wasn't looking at the corner of their screen at the
 *     right moment), and
 *   • a tooltip update (basically invisible — requires hovering).
 *
 * Iter 28 closes the gap with a persistent visual signal on the tray icon
 * itself. Two practical paths exist in Electron:
 *
 *   1. Swap the tray image (`tray.setImage(badgedIcon)`) — works on every
 *      platform, but requires shipping a second icon asset and tinting/
 *      compositing one when the count rises. The repo currently ships NO
 *      icon at all (the tray falls back to `nativeImage.createEmpty()` —
 *      see `createTray()` in index.ts), so a swap would need at least two
 *      new files baked in.
 *
 *   2. macOS: `tray.setTitle("N")` renders short text next to the icon in
 *      the menu bar — visible at all times, no extra asset needed.
 *      Windows/Linux: Electron has no equivalent (`setTitle` is a macOS-only
 *      API; it silently no-ops elsewhere). The cross-platform fallback is
 *      a tooltip change ("rud1 — N device(s) ready to configure") which
 *      matches the existing `setToolTip` plumbing in rebuildTrayMenu().
 *
 * We pick (2): no new assets, no new heavyweight deps, and the macOS title
 * is the strongest visual signal we can produce without shipping pixels.
 * The Win/Linux degradation is documented in the commit and is, in
 * practice, a wash with iter 27 — the OS notification + tray context-menu
 * CTA already worked, and the tooltip is a marginal upgrade.
 *
 * `computeTrayState` is the pure state machine: given the previous count
 * and the new count, it returns the fields the side-effecting `applyTrayState`
 * (in index.ts) needs to call into Electron. Keeping the policy here means
 * the behaviour can be exhaustively unit-tested without a real Tray.
 */

/**
 * The display-shape of the tray attention state. Cross-platform; the
 * platform-specific surfaces (`tray.setTitle` on macOS, tooltip everywhere)
 * are applied by the caller in index.ts.
 */
export interface TrayAttentionState {
  /** Number of distinct first-boot hosts currently on the LAN. */
  count: number;
  /**
   * String to render via `tray.setTitle()` on macOS. Empty string means
   * "no badge — clear the title". Capped at "9+" so the menu-bar real
   * estate doesn't blow up on a fleet network.
   */
  title: string;
  /**
   * Tooltip text — used as the cross-platform fallback signal. When count
   * is zero this is the steady-state "rud1 Desktop"; otherwise it embeds
   * the count so an operator hovering over the icon sees the queue.
   */
  tooltip: string;
}

/**
 * The diff `applyTrayState` consumes to decide whether it has any work to
 * do. `changed=false` means the count is unchanged from the previous call
 * — the caller can no-op to avoid spamming `tray.setTitle` and
 * `tray.setToolTip` on every probe tick.
 */
export interface TrayStateTransition {
  prev: TrayAttentionState;
  next: TrayAttentionState;
  changed: boolean;
}

/**
 * Format the title shown next to the icon on macOS. Two ergonomic choices:
 *
 *   • A leading space — `setTitle("N")` renders the digit flush against
 *     the icon, which looks like a subscript at typical menu-bar font
 *     sizes. Padding it gives the eye room to read.
 *   • "9+" cap — counts above 9 fold to "9+" so the title stays
 *     readable. The exact breakpoint is arbitrary; 9 is a good
 *     compromise between "shows the real number for typical fleets" and
 *     "doesn't take 4 chars of menu bar".
 */
export function formatTrayTitle(count: number): string {
  if (!Number.isFinite(count) || count <= 0) return "";
  // Treat fractional counts as their floor — the count is conceptually
  // an integer (number of hosts), but defensive against accidental float
  // arithmetic in the caller.
  const n = Math.floor(count);
  if (n <= 0) return "";
  if (n > 9) return " 9+";
  return ` ${n}`;
}

/**
 * Format the tooltip embedded in the tray. The "rud1 Desktop" baseline
 * matches the iter 25 default; the attention shape mirrors the wording of
 * the iter 26 notification body for consistency across surfaces.
 */
export function formatTrayTooltip(count: number): string {
  const n = Number.isFinite(count) && count > 0 ? Math.floor(count) : 0;
  if (n <= 0) return "rud1 Desktop";
  if (n === 1) return "rud1 Desktop — 1 device ready to configure";
  return `rud1 Desktop — ${n} devices ready to configure`;
}

/**
 * Compute the post-transition tray state from the previous count and the
 * new count.
 *
 * Pure: never touches Electron, never reads time. The caller decides
 * whether to actually push the new state to the tray based on
 * `transition.changed` — saves a `setTitle`/`setToolTip` round-trip on
 * idle ticks.
 */
export function computeTrayState(
  prevCount: number,
  newCount: number,
): TrayStateTransition {
  // Coerce non-finite or negative counts to 0 — these would otherwise
  // confuse the diff (`NaN !== NaN` in particular makes the "changed"
  // bit always true). The probe loop never produces them, but the IPC
  // surface might once we add a renderer-driven count override.
  const prev = clampCount(prevCount);
  const next = clampCount(newCount);
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
  };
}

function clampCount(n: number): number {
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}
