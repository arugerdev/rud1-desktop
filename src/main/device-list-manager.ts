// Polls /api/user/devices on rud1.es to keep the tray menu's "My
// devices" submenu fresh. Hot-path lives in main process, not the
// renderer — the tray menu is rebuilt every time `lastState` changes,
// and the cached state is read synchronously from `getState()` on
// every menu rebuild.
//
// Auth: the desktop loads rud1.es inside a `BrowserWindow` so the
// default Electron session already carries the user's cookie. Calling
// `net.fetch` here implicitly reuses that session — no extra wiring
// or token management.
//
// Cadence: 60s under normal operation, doubled to 120s after a network
// failure (capped at 5 min). The tray itself only shows up after a
// successful response, so a failure on cold start renders an
// inoffensive "—" until the next poll lands.
//
// Lifecycle: `start()` schedules an immediate fetch + an interval,
// `stop()` cancels both. Both are idempotent.

import { net } from "electron";

export type DeviceStatus =
  | "ONLINE"
  | "OFFLINE"
  | "PROVISIONING"
  | "CONNECTING"
  | "REBOOTING"
  | "UPDATING";

export interface DeviceSummary {
  id: string;
  name: string;
  status: DeviceStatus;
  lastSeen: string | null;
  organization: { id: string; name: string; slug: string };
}

export type DeviceListState =
  | { kind: "idle" }
  | { kind: "loading" }
  | {
      kind: "ok";
      devices: DeviceSummary[];
      fetchedAt: number;
    }
  | { kind: "error"; reason: string; lastDevices: DeviceSummary[] | null };

export interface DeviceListManagerOptions {
  /** Base URL of the cloud panel — e.g. "https://www.rud1.es". */
  baseUrl: string;
  /** Notified on every state change so the tray rebuild can run. */
  onStateChange?: (state: DeviceListState) => void;
  /** Override for tests; defaults to electron's net.fetch. */
  fetchFn?: (url: string) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;
  /** Override for tests; defaults to setInterval/clearInterval/etc. */
  timers?: {
    setTimeout: (fn: () => void, ms: number) => unknown;
    clearTimeout: (handle: unknown) => void;
  };
}

const BASE_INTERVAL_MS = 60_000;
const MAX_INTERVAL_MS = 5 * 60_000;

export class DeviceListManager {
  private state: DeviceListState = { kind: "idle" };
  private intervalHandle: unknown = null;
  private currentDelay = BASE_INTERVAL_MS;
  private stopped = false;

  constructor(private readonly opts: DeviceListManagerOptions) {}

  start(): void {
    if (this.intervalHandle != null) return;
    this.stopped = false;
    this.currentDelay = BASE_INTERVAL_MS;
    void this.tick();
  }

  stop(): void {
    this.stopped = true;
    const t = this.opts.timers?.clearTimeout ?? globalThis.clearTimeout;
    if (this.intervalHandle != null) {
      t(this.intervalHandle as never);
      this.intervalHandle = null;
    }
  }

  getState(): DeviceListState {
    return this.state;
  }

  // Convenience: latest known devices regardless of state. The tray
  // uses this so a transient fetch error doesn't blank out the submenu
  // — we keep showing the last-known list with an "(error)" hint.
  getLastDevices(): DeviceSummary[] | null {
    if (this.state.kind === "ok") return this.state.devices;
    if (this.state.kind === "error") return this.state.lastDevices;
    return null;
  }

  async refreshNow(): Promise<void> {
    await this.tick(/* schedule */ false);
  }

  private schedule(delayMs: number): void {
    if (this.stopped) return;
    const s = this.opts.timers?.setTimeout ?? globalThis.setTimeout;
    this.intervalHandle = s(() => {
      void this.tick();
    }, delayMs);
  }

  private async tick(scheduleNext = true): Promise<void> {
    if (this.stopped) return;
    this.setState({ kind: "loading" });
    const url = `${this.opts.baseUrl.replace(/\/+$/, "")}/api/user/devices`;
    const fetcher =
      this.opts.fetchFn ??
      (async (u: string) => {
        // Electron's `net.fetch` reuses the default session's cookie
        // jar, which is what holds the user's signed-in state from
        // the main BrowserWindow.
        const res = await net.fetch(u, { credentials: "include" });
        return {
          ok: res.ok,
          status: res.status,
          json: () => res.json(),
        };
      });
    try {
      const res = await fetcher(url);
      if (!res.ok) {
        const reason = res.status === 401 ? "signed-out" : `http-${res.status}`;
        this.setState({
          kind: "error",
          reason,
          lastDevices: this.getLastDevices(),
        });
        this.currentDelay = Math.min(this.currentDelay * 2, MAX_INTERVAL_MS);
        if (scheduleNext) this.schedule(this.currentDelay);
        return;
      }
      const body = (await res.json()) as { devices?: DeviceSummary[] };
      const devices = Array.isArray(body.devices) ? body.devices : [];
      this.setState({ kind: "ok", devices, fetchedAt: Date.now() });
      this.currentDelay = BASE_INTERVAL_MS;
    } catch (err) {
      const reason = err instanceof Error ? err.message : "unknown";
      this.setState({
        kind: "error",
        reason,
        lastDevices: this.getLastDevices(),
      });
      this.currentDelay = Math.min(this.currentDelay * 2, MAX_INTERVAL_MS);
    }
    if (scheduleNext) this.schedule(this.currentDelay);
  }

  private setState(next: DeviceListState): void {
    this.state = next;
    try {
      this.opts.onStateChange?.(next);
    } catch {
      // never let a renderer-side callback crash the polling loop
    }
  }
}

// Returns a short, locale-agnostic label like "•" for online, "○" for
// offline, etc. Used to keep the tray submenu compact — full status
// strings would exceed the recommended menu-item width on Windows.
export function statusGlyph(status: DeviceStatus): string {
  switch (status) {
    case "ONLINE":
      return "● online";
    case "OFFLINE":
      return "○ offline";
    case "PROVISIONING":
      return "◐ provisioning";
    case "CONNECTING":
      return "◐ connecting";
    case "REBOOTING":
      return "◐ rebooting";
    case "UPDATING":
      return "◐ updating";
    default:
      return "○ unknown";
  }
}
