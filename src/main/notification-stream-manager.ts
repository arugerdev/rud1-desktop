/**
 * Cloud→Desktop SSE manager.
 *
 * Opens a long-lived `text/event-stream` GET against
 * `${baseUrl}/api/v1/notifications/stream` and fires a native OS
 * notification for every `notification` event the server pushes. The
 * dashboard cookie session shipped by `electron.net.fetch` carries
 * the auth — same way the BrowserWindow itself loads the dashboard,
 * so the manager doesn't need to know anything about login state.
 *
 * Reconnect strategy: 1 s → 2 s → 4 s → … capped at 60 s on errors,
 * and the same delay (starting fresh) when the server closes cleanly.
 * 401 backs off harder (60 s) because it almost always means "the
 * user hasn't logged into the dashboard yet" and hammering the
 * endpoint won't help.
 */

import { Notification, net } from "electron";

import { isNotificationEnabled } from "./preferences-manager";
import { SseParser, type SseEvent } from "./sse-parser";

const STREAM_PATH = "/api/v1/notifications/stream";
const INITIAL_RECONNECT_MS = 1_000;
const MAX_RECONNECT_MS = 60_000;
const UNAUTH_RECONNECT_MS = 60_000;

interface CloudNotification {
  id: string;
  category: "alert" | "security" | "organization" | "system";
  title: string;
  body: string | null;
  link: string | null;
  metadata: unknown;
  createdAt: string;
}

function isCloudNotification(value: unknown): value is CloudNotification {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.id === "string" &&
    typeof v.title === "string" &&
    typeof v.category === "string"
  );
}

export interface NotificationStreamManagerDeps {
  /**
   * Origin to dial — typically `https://www.rud1.es` (or the
   * `RUD1_APP_URL` host the BrowserWindow points at). Must NOT
   * include a trailing slash.
   */
  baseUrl: string;
  /**
   * Called when a notification fires and the user clicks the OS
   * toast. Receives the absolute URL the dashboard should navigate
   * to. The implementation lives in index.ts so it can show/focus
   * the main window before navigation.
   */
  onNotificationClick: (url: string) => void;
}

export class NotificationStreamManager {
  private readonly deps: NotificationStreamManagerDeps;
  private abortController: AbortController | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private nextDelayMs = INITIAL_RECONNECT_MS;
  private running = false;
  private dedupeIds = new Set<string>();

  constructor(deps: NotificationStreamManagerDeps) {
    this.deps = deps;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.nextDelayMs = INITIAL_RECONNECT_MS;
    void this.connect();
  }

  stop(): void {
    this.running = false;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
  }

  private scheduleReconnect(ms: number): void {
    if (!this.running) return;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      void this.connect();
    }, ms);
    if (typeof this.reconnectTimer.unref === "function") {
      this.reconnectTimer.unref();
    }
  }

  private bumpReconnectDelay(): number {
    const current = this.nextDelayMs;
    this.nextDelayMs = Math.min(current * 2, MAX_RECONNECT_MS);
    return current;
  }

  private async connect(): Promise<void> {
    if (!this.running) return;
    this.abortController = new AbortController();
    const url = `${this.deps.baseUrl}${STREAM_PATH}`;

    let response: Response;
    try {
      response = await net.fetch(url, {
        signal: this.abortController.signal,
        // `useSessionCookies` is implicit for net.fetch — same posture
        // as the BrowserWindow's HTTP layer. We don't need to forward
        // anything manually. The `cache` field isn't on net.fetch's
        // typed RequestInit, but the response has cache-control: no-store
        // server-side so intermediaries won't cache anyway.
        headers: { accept: "text/event-stream" },
      });
    } catch (err) {
      if (this.running) {
        this.scheduleReconnect(this.bumpReconnectDelay());
      }
      void err;
      return;
    }

    if (response.status === 401) {
      // User hasn't signed in yet (or session expired). Back off.
      this.scheduleReconnect(UNAUTH_RECONNECT_MS);
      return;
    }
    if (!response.ok || !response.body) {
      this.scheduleReconnect(this.bumpReconnectDelay());
      return;
    }

    // Successful connection — reset the backoff so the next fault
    // starts at 1 s again.
    this.nextDelayMs = INITIAL_RECONNECT_MS;

    const reader = response.body.getReader();
    const parser = new SseParser((event) => this.handleEvent(event));
    try {
      while (this.running) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) parser.push(value);
      }
      parser.flush();
    } catch {
      // Network blip — fall through to reconnect.
    } finally {
      try {
        reader.cancel().catch(() => undefined);
      } catch {
        /* ignore */
      }
    }
    if (this.running) {
      // Server closed cleanly (probably the 25 min cap) — retry soon
      // without bumping the backoff.
      this.scheduleReconnect(INITIAL_RECONNECT_MS);
    }
  }

  private handleEvent(event: SseEvent): void {
    switch (event.event) {
      case "notification":
        this.handleNotification(event.data);
        break;
      case "hello":
      case "bye":
      case "error":
        // Lifecycle events from the server. We don't surface them —
        // the reconnect loop already handles disconnects and the
        // user doesn't care about the handshake.
        break;
      default:
        // Future event types arrive here; ignore until handled.
        break;
    }
  }

  private handleNotification(rawData: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawData);
    } catch {
      return;
    }
    if (!isCloudNotification(parsed)) return;

    // Per-id dedup — the server's watermark guarantees no
    // re-delivery in normal operation, but a clock skew could
    // theoretically replay a row on the boundary tick.
    if (this.dedupeIds.has(parsed.id)) return;
    this.dedupeIds.add(parsed.id);
    if (this.dedupeIds.size > 256) {
      // Bound the cache. Since the watermark advances we'll never
      // need to keep more than one poll's worth of ids.
      this.dedupeIds = new Set();
    }

    if (!Notification.isSupported()) return;
    // `cloud` category isn't tracked by the local preferences-manager
    // (which only knows about firstBoot/vpn/usb local lifecycle
    // events). Honour the explicit local-side opt-outs by mapping
    // cloud-side `system` notifications onto the `firstBoot` toggle
    // — operators who disabled first-boot toasts almost certainly
    // also don't want generic system noise.
    if (parsed.category === "system" && !isNotificationEnabled("firstBoot")) {
      return;
    }

    const notif = new Notification({
      title: parsed.title,
      body: parsed.body ?? "",
      silent: parsed.category === "system",
    });
    if (parsed.link) {
      const linkAbsolute = parsed.link.startsWith("http")
        ? parsed.link
        : `${this.deps.baseUrl}${parsed.link}`;
      notif.on("click", () => this.deps.onNotificationClick(linkAbsolute));
    }
    notif.show();
  }
}
