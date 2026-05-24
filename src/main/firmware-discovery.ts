// Probe paralelo a rud1.local + 192.168.50.1:7070, 1.2s timeout, first-success-wins.
import http from "http";
import { URL } from "url";

export interface FirmwareSetupState {
  complete: boolean;
  deviceName: string;
  deviceLocation: string;
  notes: string;
  completedAt: number | null;
  deviceSerial: string;
  firmwareVersion: string;
}

export interface FirmwareProbeResult {
  reachable: boolean;
  host: string;
  panelUrl: string;
  setupUrl: string;
  setup: FirmwareSetupState | null;
  probedAt: number;
  /** Razón del último intento fallido; string serializable, no Error. */
  error?: string;
}

const DEFAULT_HOSTS = ["rud1.local", "192.168.50.1"] as const;
const FIRMWARE_PORT = 7070;
const PROBE_TIMEOUT_MS = 1200;
const SAFE_HOST_RE = /^[a-zA-Z0-9.\-]{1,253}$/;

export async function probeFirmware(
  hosts: readonly string[] = DEFAULT_HOSTS,
  port: number = FIRMWARE_PORT,
): Promise<FirmwareProbeResult> {
  const validHosts = hosts.filter((h) => typeof h === "string" && SAFE_HOST_RE.test(h));
  if (validHosts.length === 0) {
    return {
      reachable: false,
      host: "",
      panelUrl: "",
      setupUrl: "",
      setup: null,
      probedAt: Date.now(),
      error: "no candidate hosts",
    };
  }
  const probedAt = Date.now();
  const attempts = validHosts.map((host) =>
    probeOne(host, port).then((result) => ({ host, result })),
  );
  // First success wins; en fallo total, devolver el ÚLTIMO error (DNS misses son menos accionables).
  const settled = await Promise.allSettled(attempts);
  let lastError = "no firmware detected";
  for (const s of settled) {
    if (s.status === "fulfilled" && s.value.result.ok) {
      const host = s.value.host;
      const panelUrl =
        port === FIRMWARE_PORT ? `http://${host}` : `http://${host}:${port}`;
      return {
        reachable: true,
        host,
        panelUrl,
        setupUrl: `${panelUrl}/setup`,
        setup: s.value.result.setup,
        probedAt,
      };
    }
    if (s.status === "fulfilled" && s.value.result.error) {
      lastError = s.value.result.error;
    } else if (s.status === "rejected") {
      lastError = s.reason instanceof Error ? s.reason.message : String(s.reason);
    }
  }
  return {
    reachable: false,
    host: "",
    panelUrl: "",
    setupUrl: "",
    setup: null,
    probedAt,
    error: lastError,
  };
}

function probeOne(
  host: string,
  port: number,
): Promise<{ ok: boolean; setup: FirmwareSetupState | null; error?: string }> {
  return new Promise((resolve) => {
    const url = new URL(`http://${host}:${port}/api/setup/state`);
    const req = http.request(
      {
        hostname: url.hostname,
        port,
        path: url.pathname,
        method: "GET",
        timeout: PROBE_TIMEOUT_MS,
        headers: { Accept: "application/json" },
      },
      (res) => {
        // 401 means the device is paired and the wizard endpoint is
        // BearerAuth-gated; we still treat the device as reachable but
        // don't try to read the body.
        if (res.statusCode === 401) {
          res.resume();
          resolve({
            ok: true,
            setup: {
              complete: true,
              deviceName: "",
              deviceLocation: "",
              notes: "",
              completedAt: null,
              deviceSerial: "",
              firmwareVersion: "",
            },
          });
          return;
        }
        if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
          res.resume();
          resolve({ ok: false, setup: null, error: `status ${res.statusCode}` });
          return;
        }
        const chunks: Buffer[] = [];
        let total = 0;
        res.on("data", (chunk: Buffer) => {
          total += chunk.length;
          // Cap response size at 16 KB — the setup state payload is well
          // under 1 KB; anything bigger is suspicious.
          if (total > 16 * 1024) {
            res.destroy();
            resolve({ ok: false, setup: null, error: "response too large" });
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          try {
            const text = Buffer.concat(chunks).toString("utf8");
            const parsed = JSON.parse(text) as Partial<FirmwareSetupState> | null;
            if (!parsed || typeof parsed !== "object") {
              resolve({ ok: false, setup: null, error: "non-object response" });
              return;
            }
            resolve({
              ok: true,
              setup: {
                complete: Boolean(parsed.complete),
                deviceName: typeof parsed.deviceName === "string" ? parsed.deviceName : "",
                deviceLocation:
                  typeof parsed.deviceLocation === "string" ? parsed.deviceLocation : "",
                notes: typeof parsed.notes === "string" ? parsed.notes : "",
                completedAt:
                  typeof parsed.completedAt === "number" ? parsed.completedAt : null,
                deviceSerial:
                  typeof parsed.deviceSerial === "string" ? parsed.deviceSerial : "",
                firmwareVersion:
                  typeof parsed.firmwareVersion === "string"
                    ? parsed.firmwareVersion
                    : "",
              },
            });
          } catch (e) {
            resolve({
              ok: false,
              setup: null,
              error: e instanceof Error ? e.message : "parse failure",
            });
          }
        });
        res.on("error", (e) => {
          resolve({ ok: false, setup: null, error: e.message });
        });
      },
    );
    req.on("timeout", () => {
      req.destroy();
      resolve({ ok: false, setup: null, error: "timeout" });
    });
    req.on("error", (e) => {
      resolve({ ok: false, setup: null, error: e.message });
    });
    req.end();
  });
}

/**
 * isFirstBoot — convenience predicate for callers that just want to know
 * whether the operator should be nudged toward the wizard. Treats
 * `reachable=false` as NOT-first-boot (we can't detect what we can't see)
 * so the tray menu stays clean when no device is on the LAN.
 */
export function isFirstBoot(probe: FirmwareProbeResult): boolean {
  return probe.reachable && probe.setup !== null && probe.setup.complete === false;
}

/**
 * shouldNotifyFirstBoot — rising-edge predicate for the desktop notification.
 *
 * Returns true exactly when the operator should see ONE OS notification
 * because a first-boot device just became visible on the LAN. We notify on:
 *
 *   - prev=null               → next=first-boot   (cold app start with a Pi
 *                                                   already in setup mode)
 *   - prev=anything-not-fb    → next=first-boot   (Pi just plugged in)
 *   - prev=first-boot(hostA)  → next=first-boot(hostB) when hostA != hostB
 *     (a different unconfigured device replaced the previous one — rare but
 *     plausible if the operator finishes one and powers another)
 *
 * We deliberately do NOT notify when:
 *
 *   - next.reachable=false                       (silence on disconnect)
 *   - next.reachable=true && next.setup.complete (already-paired device)
 *   - prev was already first-boot at the same host (still the same device,
 *     no point spamming)
 *
 * Pure function — no Electron / IPC dependency so the rising-edge logic
 * can be exercised by unit tests without a real Notification surface.
 */
export function shouldNotifyFirstBoot(
  prev: FirmwareProbeResult | null,
  next: FirmwareProbeResult,
): boolean {
  if (!isFirstBoot(next)) return false;
  if (prev == null) return true;
  if (!isFirstBoot(prev)) return true;
  return prev.host !== next.host;
}
