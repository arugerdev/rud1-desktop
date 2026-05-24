// 10s poll (max 60s con backoff). SSE no aplica: tray cubre N orgs y la SSE de rud1-es es por-org.
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
  /** Fires en transition non-ONLINE → ONLINE; primer poll inicial NO anuncia. */
  onDeviceReady?: (device: DeviceSummary) => void;
  /** Override for tests; defaults to electron's net.fetch. */
  fetchFn?: (url: string) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;
  /** Override for tests; defaults to setInterval/clearInterval/etc. */
  timers?: {
    setTimeout: (fn: () => void, ms: number) => unknown;
    clearTimeout: (handle: unknown) => void;
  };
}

const BASE_INTERVAL_MS = 10_000;
const MAX_INTERVAL_MS = 60_000;

export class DeviceListManager {
  private state: DeviceListState = { kind: "idle" };
  private intervalHandle: unknown = null;
  private currentDelay = BASE_INTERVAL_MS;
  private stopped = false;
  private lastStatusById = new Map<string, DeviceStatus>();
  private seeded = false;

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
      if (this.seeded && this.opts.onDeviceReady) {
        for (const d of devices) {
          const prev = this.lastStatusById.get(d.id);
          if (d.status === "ONLINE" && prev !== "ONLINE") {
            try {
              this.opts.onDeviceReady(d);
            } catch {
              /* don't let notifier kill polling */
            }
          }
        }
      }
      this.lastStatusById = new Map(devices.map((d) => [d.id, d.status]));
      this.seeded = true;
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
      /* don't let callback crash polling */
    }
  }
}

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
