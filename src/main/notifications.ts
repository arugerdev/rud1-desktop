/**
 * Liquid Glass notification helpers for VPN / USB / device lifecycle events.
 *
 * Public surface is intentionally unchanged from the platform-native
 * `Notification` era — callers keep doing `notifyVpnConnected("foo")`,
 * `notifyUsbAttached(label, busId)`, etc. — but under the hood we now
 * route every toast through the frameless overlay window managed by
 * `toast-overlay.ts`. Tradeoffs vs. the OS-native path documented in
 * `toast-overlay.ts`.
 *
 * Per-category mute (Settings → Notifications) is still honoured via
 * `isNotificationEnabled(category)` — the toast simply never reaches the
 * overlay queue when the user has silenced it.
 */

import {
  isNotificationEnabled,
  type NotificationToggles,
} from "./preferences-manager";
import { pushToast, type ToastKind } from "./toast-overlay";

const MAX_TITLE = 80;
const MAX_BODY = 240;

function clamp(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + "…";
}

interface ShowOpts {
  kind?: ToastKind;
  category?: keyof NotificationToggles;
  /** Auto-dismiss override. Defaults to 5.5s. 0 = sticky. */
  autoDismissMs?: number;
  /** Optional CTA. The channel is fired through the toast overlay's IPC
   *  bridge — register a handler with `onToastAction(channel, cb)`. */
  action?: { label: string; channel: string };
}

function show(title: string, body: string, opts?: ShowOpts) {
  if (opts?.category && !isNotificationEnabled(opts.category)) return;
  try {
    pushToast({
      kind: opts?.kind ?? "info",
      title: clamp(title, MAX_TITLE),
      body: clamp(body, MAX_BODY),
      autoDismissMs: opts?.autoDismissMs,
      action: opts?.action,
    });
  } catch (err) {
    // Best effort — a failed toast shouldn't break the IPC call that
    // triggered it. Log so headless dev runs still surface the message.
    console.warn(
      "[notifications] toast push failed:",
      err instanceof Error ? err.message : err,
      title,
      "—",
      body,
    );
  }
}

// ─── VPN ────────────────────────────────────────────────────────────────────

export function notifyVpnConnected(deviceName?: string) {
  show(
    "VPN Connected",
    deviceName ? `Tunnel up to ${deviceName}.` : "Tunnel is up.",
    { kind: "success", category: "vpn" },
  );
}

/**
 * Preserved for IPC contract stability. Pre-OpenVPN we fired this when
 * the agent's WireGuard endpoint sat inside RFC 6598 (100.64.0.0/10) —
 * which made the symmetric WG handshake statistically certain to fail.
 * OpenVPN's client-OUTBOUND model is unaffected by CGNAT on either side,
 * so this notification is now a vestige; we keep the export so existing
 * callers don't need a coordinated rename.
 */
export function notifyVpnCgnatWarning(deviceName?: string) {
  show(
    "VPN connecting (CGNAT detected)",
    deviceName
      ? `${deviceName} appears to be behind carrier-grade NAT. The OpenVPN client opens an outbound TLS connection, so this typically still works.`
      : "Carrier-grade NAT was detected on the device side. The OpenVPN client opens an outbound TLS connection, so this typically still works.",
    { kind: "warning", category: "vpn" },
  );
}

/**
 * Fired when the desktop detects the TAP-Windows V9 kernel driver is
 * missing — the renderer's Liquid Glass modal will appear above the
 * panel asking the user to grant elevation.
 */
export function notifyVpnTapDriverMissing() {
  show(
    "TAP driver required",
    "rud1 needs to install the TAP-Windows V9 driver. Click Connect and accept the elevation prompt.",
    { kind: "warning", category: "vpn" },
  );
}

export function notifyVpnDisconnected(
  deviceName?: string,
  uptimeLabel?: string | null,
) {
  const target = deviceName ? `Tunnel to ${deviceName} dropped` : "Tunnel is down";
  const suffix = uptimeLabel && uptimeLabel.trim() ? ` after ${uptimeLabel.trim()}` : "";
  show(
    "VPN Disconnected",
    `${target}${suffix}.`,
    { kind: "info", category: "vpn" },
  );
}

/** Used when the bridge surfaces a structured failure rather than a
 *  successful state transition. */
export function notifyVpnError(message: string) {
  show("VPN Error", message, { kind: "error", category: "vpn", autoDismissMs: 9_000 });
}

// ─── USB ────────────────────────────────────────────────────────────────────

export function notifyUsbAttached(label: string | null, busId: string) {
  const subject = label && label.trim() ? label.trim() : `USB ${busId}`;
  show("USB Attached", `${subject} is now mounted on this machine.`, {
    kind: "success",
    category: "usb",
  });
}

export function notifyUsbDetached(label: string | null, busId: string) {
  const subject = label && label.trim() ? label.trim() : `USB ${busId}`;
  show("USB Detached", `${subject} was unmounted.`, {
    kind: "info",
    category: "usb",
  });
}

// ─── Device lifecycle ───────────────────────────────────────────────────────

export function notifyDeviceReady(deviceName: string | null | undefined) {
  const subject = deviceName && deviceName.trim() ? deviceName.trim() : "Device";
  show(`${subject} connected`, `${subject} is online and ready to use.`, {
    kind: "success",
    category: "deviceReady",
  });
}

/**
 * True when the toast surface can render. Always true under the in-app
 * overlay (no platform-dependent feature detection needed). Kept for
 * IPC contract stability — the renderer used to read this to fall back
 * on in-panel toasts; with the overlay the fallback is moot.
 */
export function notificationsSupported(): boolean {
  return true;
}
