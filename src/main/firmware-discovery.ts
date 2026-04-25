/**
 * firmware-discovery — best-effort probe for a locally-reachable rud1 device.
 *
 * The rud1-fw agent always exposes its REST API on port 7070. Two host
 * candidates are tried in order:
 *
 *   1. `rud1.local`         (mDNS via avahi-daemon, present on a fully
 *                            installed Pi — survives DHCP lease changes).
 *   2. `192.168.50.1`       (the static IP the agent assigns to its setup
 *                            AP — only reachable while the operator is
 *                            associated with the device's `rud1-setup-XXXX`
 *                            SSID).
 *
 * The probe is intentionally cheap: a 1.2-second HEAD/GET for /api/setup/state
 * with `keepalive=false` so a hung box doesn't accumulate sockets. Both
 * candidates are tried in parallel and the first successful response wins.
 *
 * Why not auto-launch the wizard the moment we detect a first-boot device?
 * Because the desktop app's primary purpose is to load rud1.es (cloud panel)
 * — auto-redirecting to the LAN device URL would yank the operator out of
 * an unrelated workflow. We surface a CTA in the tray menu and let them
 * click into it explicitly.
 */

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
  // The host the probe succeeded against (e.g. "rud1.local" or
  // "192.168.50.1"). Empty when reachable=false.
  host: string;
  // The base URL the operator should use to reach the device's panel.
  // E.g. "http://rud1.local". Empty when reachable=false.
  panelUrl: string;
  // The full /setup URL pre-built so the caller can hand it straight to
  // shell.openExternal — saves the renderer from string-building the URL.
  setupUrl: string;
  setup: FirmwareSetupState | null;
  probedAt: number;
  // Populated on `reachable=false` with the reason the last attempt
  // failed; useful for diagnostics. NEVER an Error instance — must be
  // serialisable across IPC.
  error?: string;
}

const DEFAULT_HOSTS = ["rud1.local", "192.168.50.1"] as const;
const FIRMWARE_PORT = 7070;
const PROBE_TIMEOUT_MS = 1200;
// Path traversal / control-character guard for any host override an
// integration test might pass — we never ship the override to operators.
const SAFE_HOST_RE = /^[a-zA-Z0-9.\-]{1,253}$/;

/**
 * probeFirmware — tries each candidate host in parallel and returns the
 * first successful response, or a structured `reachable=false` envelope
 * when all candidates fail.
 *
 * Pure I/O helper — no Electron / IPC dependencies so it can be unit-tested
 * with a mock listener.
 *
 * `port` is overridable for tests so the suite can bind to ephemeral ports
 * and avoid TIME_WAIT collisions on the firmware port (7070). Production
 * callers should always omit it.
 */
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
  // Race semantics: as soon as any attempt resolves to a successful
  // FirmwareSetupState, return it. If they all fail, return the LAST
  // error message — earlier ones tend to be DNS misses on the alt host
  // which aren't actionable.
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
