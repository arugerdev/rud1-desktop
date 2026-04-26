/**
 * Native OS notification helpers for VPN / USB lifecycle events.
 *
 * Why this exists at all: the operator needs to know — without
 * pulling up the panel — when (a) the VPN tunnel comes up or drops,
 * and (b) a USB device finishes attaching / detaching. The panel
 * already mirrors the state, but a notification makes those events
 * non-blocking surface area: the user can be on a Slack window or in
 * a terminal and still see "Pi-shop-01: SanDisk USB attached" the
 * moment the bridge confirms it.
 *
 * Implementation notes
 * --------------------
 *   • Electron's main-process `Notification` API maps to the native
 *     toast on each platform: Action Center (Win), Notification
 *     Centre (mac), libnotify/notify-osd (Linux).
 *   • We call `Notification.isSupported()` once at module load. On a
 *     headless or notification-deprived environment the helpers
 *     no-op rather than throwing — IPC handlers should never crash
 *     because the toast couldn't render.
 *   • Title/body are bounded so a malicious or absurdly long device
 *     label can't push past the platform's display limits and break
 *     wrapping. Linux libnotify in particular has a per-line cap.
 */

import { Notification } from "electron";

const SUPPORTED = Notification.isSupported();

const MAX_TITLE = 80;
const MAX_BODY = 240;

function clamp(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + "…"; // …
}

function show(title: string, body: string, opts?: { silent?: boolean }) {
  if (!SUPPORTED) return;
  try {
    const n = new Notification({
      title: clamp(title, MAX_TITLE),
      body: clamp(body, MAX_BODY),
      silent: opts?.silent ?? false,
    });
    n.show();
  } catch {
    // Best effort. A platform that throws for any reason (no DBus
    // session on a fresh Linux box, etc.) shouldn't break the IPC
    // call that triggered this helper.
  }
}

// ─── VPN ────────────────────────────────────────────────────────────────────

/**
 * Fired after the bridge confirms `wireguard.exe /installtunnelservice`
 * (or `wg-quick up` on unix) succeeded. The body should be brief; the
 * panel carries the full handshake / IP detail. */
export function notifyVpnConnected(deviceName?: string) {
  show(
    "VPN Connected",
    deviceName ? `Tunnel up to ${deviceName}.` : "Tunnel is up.",
  );
}

/**
 * Variant of {@link notifyVpnConnected} fired when the agent's reported
 * endpoint sits inside RFC 6598 (100.64.0.0/10). The tunnel installs but
 * the WireGuard handshake is statistically certain to fail because the
 * Pi's ISP is performing carrier-grade NAT — telling the user up-front
 * saves a 30 s "tunnel installed but no handshake" debugging session.
 *
 * Title-cased "Tunnel installed (CGNAT detected)" so it's visually
 * distinct from the success path even when the body wraps off-screen.
 */
export function notifyVpnCgnatWarning(deviceName?: string) {
  show(
    "Tunnel installed (CGNAT detected)",
    deviceName
      ? `${deviceName} sits behind carrier-grade NAT — handshake is unlikely to complete.`
      : "Device sits behind carrier-grade NAT — handshake is unlikely to complete.",
  );
}

/**
 * Fired after a successful disconnect. The user typically sees the
 * panel switch to "VPN Disconnected" already; this is for when they
 * triggered disconnect from a device's Connect tab and immediately
 * navigated away.
 *
 * Iter 59: optional `uptimeLabel` — pre-formatted via vpn-manager's
 * `formatUptimeMs` (e.g. "2h 14m"). When supplied we append "after X"
 * so the user gets a satisfying confirmation that the tunnel was
 * actually live, distinguishable from a "tear down a leftover service"
 * fall-through path.
 */
export function notifyVpnDisconnected(
  deviceName?: string,
  uptimeLabel?: string | null,
) {
  const target = deviceName ? `Tunnel to ${deviceName} dropped` : "Tunnel is down";
  const suffix = uptimeLabel && uptimeLabel.trim() ? ` after ${uptimeLabel.trim()}` : "";
  show(
    "VPN Disconnected",
    `${target}${suffix}.`,
    { silent: true },
  );
}

/** Used when the bridge surfaces a structured failure rather than a
 *  successful state transition. Kept distinct so the UX can pick a
 *  louder presentation later (icon, action button to open logs). */
export function notifyVpnError(message: string) {
  show("VPN Error", message);
}

// ─── USB ────────────────────────────────────────────────────────────────────

/**
 * Fired after `usbip attach` returns success.
 *
 * `label` is the human-readable form the renderer assembles from
 * `vendorName + productName` (or whatever it has — sometimes only the
 * raw VID:PID is available). `busId` is the dotted/dashed Linux bus
 * ID used as a fallback when `label` is missing or empty.
 */
export function notifyUsbAttached(label: string | null, busId: string) {
  const subject = label && label.trim() ? label.trim() : `USB ${busId}`;
  show("USB Attached", `${subject} is now mounted on this machine.`);
}

/**
 * Fired after `usbip detach` returns success. Silent: detach is
 * almost always user-initiated, so the toast is informational and
 * doesn't need to interrupt.
 */
export function notifyUsbDetached(label: string | null, busId: string) {
  const subject = label && label.trim() ? label.trim() : `USB ${busId}`;
  show("USB Detached", `${subject} was unmounted.`, { silent: true });
}

/** True when the platform supports notifications and the constructor
 *  worked. Exposed for diagnostics so the renderer can decide whether
 *  to fall back to in-app toasts. */
export function notificationsSupported(): boolean {
  return SUPPORTED;
}
