/**
 * Preload script — runs in an isolated context before the renderer page loads.
 * Exposes the native API to the web app via contextBridge.
 *
 * The web app accesses these methods via window.electronAPI.
 * Type declarations for window.electronAPI are in src/types/electron.d.ts
 * (or defined in the web app itself).
 */

import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("electronAPI", {
  vpn: {
    connect: (wgConfig: string) =>
      ipcRenderer.invoke("vpn:connect", wgConfig) as Promise<{ ok: boolean; error?: string }>,

    disconnect: () =>
      ipcRenderer.invoke("vpn:disconnect") as Promise<{ ok: boolean; error?: string }>,

    status: () =>
      ipcRenderer.invoke("vpn:status") as Promise<{ connected: boolean; ip?: string }>,
  },

  usb: {
    attach: (host: string, busId: string) =>
      ipcRenderer.invoke("usb:attach", host, busId) as Promise<{ ok: boolean; port?: number; error?: string }>,

    detach: (port: number) =>
      ipcRenderer.invoke("usb:detach", port) as Promise<{ ok: boolean; error?: string }>,

    list: () =>
      ipcRenderer.invoke("usb:list") as Promise<{ port: number; host: string; busId: string }[]>,
  },

  net: {
    ping: (host: string) =>
      ipcRenderer.invoke("net:ping", host) as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          host: string;
          alive: boolean;
          avgRttMs: number | null;
          lossPct: number;
          raw: string;
        };
      }>,

    interfaces: () =>
      ipcRenderer.invoke("net:interfaces") as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          name: string;
          mac: string;
          up: boolean;
          internal: boolean;
          addresses: { address: string; cidr: string | null; family: "IPv4" | "IPv6" }[];
        }[];
      }>,

    resolveRoute: (destination: string) =>
      ipcRenderer.invoke("net:resolveRoute", destination) as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          destination: string;
          iface: string | null;
          gateway: string | null;
          raw: string;
        };
      }>,

    traceroute: (host: string) =>
      ipcRenderer.invoke("net:traceroute", host) as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          host: string;
          hops: { index: number; host: string | null; rttMs: number | null }[];
          raw: string;
        };
      }>,

    dnsLookup: (hostname: string) =>
      ipcRenderer.invoke("net:dnsLookup", hostname) as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          hostname: string;
          a: string[];
          aaaa: string[];
          cname: string | null;
        };
      }>,

    publicIp: () =>
      ipcRenderer.invoke("net:publicIp") as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          ipv4: string | null;
          ipv6: string | null;
          source: string;
        };
      }>,

    portCheck: (opts: { host: string; port: number; timeoutMs?: number }) =>
      ipcRenderer.invoke("net:portCheck", opts) as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          open: boolean;
          errorCode: string | null;
          latencyMs: number | null;
        };
      }>,
  },

  diag: {
    // Parsed `wg show [tunnelName]` output. tunnelName must match
    // /^[a-zA-Z0-9_-]{1,32}$/ — omit to list all tunnels. Never throws:
    // missing binary / invalid input surface as {available:false, reason}.
    wgStatus: (tunnelName?: string) =>
      ipcRenderer.invoke("diag:wgStatus", tunnelName) as Promise<{
        ok: boolean;
        error?: string;
        result?:
          | {
              available: true;
              tunnels: {
                interface: string;
                publicKey: string | null;
                listenPort: number | null;
                peers: {
                  publicKey: string;
                  endpoint: string | null;
                  allowedIps: string[];
                  latestHandshake: number;
                  transferRx: number;
                  transferTx: number;
                  persistentKeepalive: number | null;
                }[];
              }[];
            }
          | { available: false; reason: string };
      }>,

    // Combined probe: ping(wgHost) + ping(publicHost) + TCP portCheck
    // against publicHost:publicPort. Returns a verdict + actionable hints.
    // WG uses UDP, so the TCP probe only verifies the host is up, not the
    // actual WG listen port.
    tunnelHealth: (opts: {
      wgHost: string;
      publicHost: string;
      publicPort: number;
      timeoutMs?: number;
      /** Opt-in: run MTU bisect when verdict is degraded/broken. */
      autoMtuProbe?: boolean;
      /** Outer budget for the auxiliary MTU probe (default 12000ms). */
      mtuProbeTimeoutMs?: number;
    }) =>
      ipcRenderer.invoke("diag:tunnelHealth", opts) as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          wgPing:
            | { reachable: boolean; rttMs: number | null }
            | { error: string };
          publicPing:
            | { reachable: boolean; rttMs: number | null }
            | { error: string };
          tcpProbe:
            | { open: boolean; errorCode: string | null; latencyMs: number | null }
            | { error: string };
          verdict: "healthy" | "degraded" | "broken";
          hints: string[];
          mtu?: { discovered: number; simulated?: boolean };
        };
      }>,

    // DF-flagged progressive ping bisect to discover effective path MTU to
    // `host`. Useful for spotting WG-over-WG / PPPoE MTU mismatches that
    // present as "handshake works, big transfers stall". Bounded by
    // `timeoutMs` (outer budget, default 15000ms) with at most 8 bisect
    // iterations. Returns `mtu: null` on unsupported platforms, full-path
    // failure, or timeout — partial `attempts` are always surfaced.
    mtuProbe: (args: {
      host: string;
      opts?: { start?: number; min?: number; timeoutMs?: number };
    }) =>
      ipcRenderer.invoke("diag:mtuProbe", args) as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          host: string;
          mtu: number | null;
          attempts: { size: number; ok: boolean; errorMsg?: string }[];
          durationMs: number;
          platform: "linux" | "darwin" | "win32" | "other";
          errorMsg?: string;
        };
      }>,

    // Consolidated one-call probe: runs wgStatus + tunnelHealth (with
    // autoMtuProbe defaulted to true) + system.getStats() in parallel using
    // Promise.allSettled under the hood. Each sub-call is isolated — a
    // single failure surfaces in its `*Error` field while the other probes
    // still populate. Outer budget is 30s to accommodate the MTU bisect.
    // When `publicHost`/`publicPort` are omitted, `wgHost` is reused as the
    // public host and port 51820 (WG's default listen port) is assumed.
    fullDiagnosis: (opts?: {
      wgInterface?: string;
      wgHost?: string;
      publicHost?: string;
      publicPort?: number;
      autoMtuProbe?: boolean;
      mtuProbeTimeoutMs?: number;
    }) =>
      ipcRenderer.invoke("diag:fullDiagnosis", opts) as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          timestamp: number;
          wgStatus:
            | {
                available: true;
                tunnels: {
                  interface: string;
                  publicKey: string | null;
                  listenPort: number | null;
                  peers: {
                    publicKey: string;
                    endpoint: string | null;
                    allowedIps: string[];
                    latestHandshake: number;
                    transferRx: number;
                    transferTx: number;
                    persistentKeepalive: number | null;
                  }[];
                }[];
              }
            | { available: false; reason: string }
            | null;
          wgStatusError: string | null;
          tunnelHealth:
            | {
                wgPing:
                  | { reachable: boolean; rttMs: number | null }
                  | { error: string };
                publicPing:
                  | { reachable: boolean; rttMs: number | null }
                  | { error: string };
                tcpProbe:
                  | {
                      open: boolean;
                      errorCode: string | null;
                      latencyMs: number | null;
                    }
                  | { error: string };
                verdict: "healthy" | "degraded" | "broken";
                hints: string[];
                mtu?: { discovered: number; simulated?: boolean };
              }
            | null;
          tunnelHealthError: string | null;
          systemStats:
            | {
                hostname: string;
                platform: NodeJS.Platform;
                release: string;
                arch: string;
                uptimeSec: number;
                appUptimeSec: number;
                cpu: {
                  model: string;
                  speedMhz: number;
                  count: number;
                  loadavg: [number, number, number];
                  utilisation: number | null;
                };
                memory: {
                  totalBytes: number;
                  freeBytes: number;
                  usedBytes: number;
                  usagePct: number;
                };
                interfaces: {
                  name: string;
                  mac: string;
                  up: boolean;
                  internal: boolean;
                  addresses: {
                    family: "IPv4" | "IPv6";
                    address: string;
                    cidr: string | null;
                  }[];
                }[];
                capturedAt: string;
              }
            | null;
          systemStatsError: string | null;
        };
      }>,

    // Serialize a `fullDiagnosis` run to a timestamped JSON file under
    // `~/.rud1/diag/` and return its absolute path plus a SHA-256 of the
    // written bytes. Probe failures inside the diagnosis are preserved as
    // `*Error` fields in the embedded result, NOT thrown — so the export
    // always succeeds even on a sick device, as long as mkdir/write work.
    // The caller gets `ok:false` only on filesystem errors.
    exportReport: (opts?: {
      wgInterface?: string;
      wgHost?: string;
      publicHost?: string;
      publicPort?: number;
      autoMtuProbe?: boolean;
      mtuProbeTimeoutMs?: number;
    }) =>
      ipcRenderer.invoke("diag:exportReport", opts) as Promise<
        | {
            ok: true;
            result: {
              path: string;
              bytes: number;
              sha256: string;
              diagnosis: {
                timestamp: number;
                wgStatus:
                  | {
                      available: true;
                      tunnels: {
                        interface: string;
                        publicKey: string | null;
                        listenPort: number | null;
                        peers: {
                          publicKey: string;
                          endpoint: string | null;
                          allowedIps: string[];
                          latestHandshake: number;
                          transferRx: number;
                          transferTx: number;
                          persistentKeepalive: number | null;
                        }[];
                      }[];
                    }
                  | { available: false; reason: string }
                  | null;
                wgStatusError: string | null;
                tunnelHealth:
                  | {
                      wgPing:
                        | { reachable: boolean; rttMs: number | null }
                        | { error: string };
                      publicPing:
                        | { reachable: boolean; rttMs: number | null }
                        | { error: string };
                      tcpProbe:
                        | {
                            open: boolean;
                            errorCode: string | null;
                            latencyMs: number | null;
                          }
                        | { error: string };
                      verdict: "healthy" | "degraded" | "broken";
                      hints: string[];
                      mtu?: { discovered: number; simulated?: boolean };
                    }
                  | null;
                tunnelHealthError: string | null;
                systemStats:
                  | {
                      hostname: string;
                      platform: NodeJS.Platform;
                      release: string;
                      arch: string;
                      uptimeSec: number;
                      appUptimeSec: number;
                      cpu: {
                        model: string;
                        speedMhz: number;
                        count: number;
                        loadavg: [number, number, number];
                        utilisation: number | null;
                      };
                      memory: {
                        totalBytes: number;
                        freeBytes: number;
                        usedBytes: number;
                        usagePct: number;
                      };
                      interfaces: {
                        name: string;
                        mac: string;
                        up: boolean;
                        internal: boolean;
                        addresses: {
                          family: "IPv4" | "IPv6";
                          address: string;
                          cidr: string | null;
                        }[];
                      }[];
                      capturedAt: string;
                    }
                  | null;
                systemStatsError: string | null;
              };
            };
          }
        | { ok: false; error: string }
      >,

    // Enumerate JSON reports previously written by exportReport under
    // `~/.rud1/diag/`. Returns an array sorted newest-first. Metadata only —
    // sha256 is NOT computed here (use readReport to get bytes + hash). If
    // the directory doesn't exist yet the list is empty, never an error.
    listReports: () =>
      ipcRenderer.invoke("diag:listReports") as Promise<
        | {
            ok: true;
            result: {
              path: string;
              filename: string;
              bytes: number;
              createdAt: string;
            }[];
          }
        | { ok: false; error: string }
      >,

    // Read + sha256-hash + JSON.parse a report by absolute path. The path
    // must resolve under `~/.rud1/diag/` AND match `rud1-diag-*.json`;
    // anything else yields `{ok:false, error:"path outside allowed directory"}`.
    readReport: (reportPath: string) =>
      ipcRenderer.invoke("diag:readReport", reportPath) as Promise<
        | {
            ok: true;
            result: {
              path: string;
              bytes: number;
              sha256: string;
              content: unknown;
            };
          }
        | { ok: false; error: string }
      >,

    // Unlink a report file. Same path-traversal + filename-shape guards as
    // readReport. Missing files surface as `{ok:false, error:"report not found"}`.
    deleteReport: (reportPath: string) =>
      ipcRenderer.invoke("diag:deleteReport", reportPath) as Promise<
        | { ok: true; result: { path: string; deleted: true } }
        | { ok: false; error: string }
      >,

    // Reveal `~/.rud1/diag/` in the OS file explorer (Finder/Explorer/xdg-open).
    // The directory is mkdir -p'd first so first-run with no reports yet
    // doesn't fail — the user gets an empty folder instead of an error.
    openReportsFolder: () =>
      ipcRenderer.invoke("diag:openReportsFolder") as Promise<
        | { ok: true; result: { opened: boolean; path: string } }
        | { ok: false; error: string }
      >,

    // Copy a report out of `~/.rud1/diag/` to a user-chosen location via the
    // native "Save As" dialog. Same path-traversal guard as read/delete. The
    // dialog defaults to `~/Downloads/<defaultFilename or source basename>`.
    // Three-way result: success, explicit user cancel, or thrown error
    // (wrapped in the `{ok:false, error}` envelope by the main process).
    saveReportCopy: (opts: { path: string; defaultFilename?: string }) =>
      ipcRenderer.invoke("diag:saveReportCopy", opts) as Promise<
        | {
            ok: true;
            result:
              | { savedPath: string; bytes: number }
              | { cancelled: true };
          }
        | { ok: false; error: string }
      >,

    // Read two previously-exported reports (same path-traversal + filename
    // guard as readReport/deleteReport) and return a structured diff. The
    // `a`/`b` fields in the result are always ordered by exportedAt
    // (earlier → later); `swapped: true` means the input order was reversed
    // so the UI can still render in the order the caller requested. Deltas
    // are always "newer minus older" (i.e. `b - a`) and individual fields
    // fall back to `null` when either side's value is missing. Throws
    // `"report not parseable"` if either file isn't valid JSON.
    // Opt-in periodic snapshotter. Persists `{enabled, intervalMs, opts, history}`
    // to `~/.rud1/diag/autosnapshot.json` so the schedule + run history
    // survive app restarts. Interval is clamped server-side: minimum 5 min
    // (300_000 ms), maximum 24 h (86_400_000 ms). Out-of-range values are
    // silently coerced rather than rejected.
    // `runNow` triggers an immediate snapshot without altering the schedule;
    // it returns `{ok:false, error:"already running", result:<status>}` when
    // a scheduled (or other manual) run is already in flight.
    // `history` is a rolling ring buffer of the last 20 runs (success + error)
    // for the renderer to draw a timeline.
    autoSnapshotStatus: () =>
      ipcRenderer.invoke("diag:autoSnapshotStatus") as Promise<
        | {
            ok: true;
            result: {
              enabled: boolean;
              intervalMs: number;
              opts?: {
                wgInterface?: string;
                wgHost?: string;
                publicHost?: string;
                publicPort?: number;
                autoMtuProbe?: boolean;
                mtuProbeTimeoutMs?: number;
              };
              lastRunAt?: string;
              lastStatus?: "ok" | "error";
              lastError?: string;
              lastPath?: string;
              history?: {
                startedAt: string;
                finishedAt: string;
                status: "success" | "error";
                durationMs: number;
                path?: string;
                error?: string;
              }[];
              nextRunAt: string | null;
              running: boolean;
            };
          }
        | { ok: false; error: string }
      >,

    autoSnapshotConfigure: (next: {
      enabled: boolean;
      intervalMs?: number;
      opts?: {
        wgInterface?: string;
        wgHost?: string;
        publicHost?: string;
        publicPort?: number;
        autoMtuProbe?: boolean;
        mtuProbeTimeoutMs?: number;
      };
    }) =>
      ipcRenderer.invoke("diag:autoSnapshotConfigure", next) as Promise<
        | {
            ok: true;
            result: {
              enabled: boolean;
              intervalMs: number;
              nextRunAt: string | null;
              running: boolean;
              lastRunAt?: string;
              lastStatus?: "ok" | "error";
              lastError?: string;
              lastPath?: string;
              history?: {
                startedAt: string;
                finishedAt: string;
                status: "success" | "error";
                durationMs: number;
                path?: string;
                error?: string;
              }[];
            };
          }
        | { ok: false; error: string }
      >,

    autoSnapshotRunNow: () =>
      ipcRenderer.invoke("diag:autoSnapshotRunNow") as Promise<
        | {
            ok: true;
            result: {
              enabled: boolean;
              intervalMs: number;
              nextRunAt: string | null;
              running: boolean;
              lastRunAt?: string;
              lastStatus?: "ok" | "error";
              lastError?: string;
              lastPath?: string;
              history?: {
                startedAt: string;
                finishedAt: string;
                status: "success" | "error";
                durationMs: number;
                path?: string;
                error?: string;
              }[];
            };
          }
        | {
            ok: false;
            error: string;
            // Present when error === "already running"; absent on transport errors.
            result?: {
              enabled: boolean;
              intervalMs: number;
              nextRunAt: string | null;
              running: boolean;
              lastRunAt?: string;
              lastStatus?: "ok" | "error";
              lastError?: string;
              lastPath?: string;
              history?: {
                startedAt: string;
                finishedAt: string;
                status: "success" | "error";
                durationMs: number;
                path?: string;
                error?: string;
              }[];
            };
          }
      >,

    compareReports: (args: { pathA: string; pathB: string }) =>
      ipcRenderer.invoke("diag:compareReports", args) as Promise<
        | {
            ok: true;
            result: {
              a: {
                path: string;
                exportedAt: string | null;
                verdict: "healthy" | "degraded" | "broken" | null;
                wgPeerCount: number | null;
                activePeers: number | null;
                lastHandshake: number | null;
                mtu: number | null;
                cpuPct: number | null;
                memPct: number | null;
                tempCpu: number | null;
              };
              b: {
                path: string;
                exportedAt: string | null;
                verdict: "healthy" | "degraded" | "broken" | null;
                wgPeerCount: number | null;
                activePeers: number | null;
                lastHandshake: number | null;
                mtu: number | null;
                cpuPct: number | null;
                memPct: number | null;
                tempCpu: number | null;
              };
              deltas: {
                timeBetweenMs: number | null;
                verdictChanged: boolean;
                wgPeerCountDelta: number | null;
                activePeersDelta: number | null;
                mtuDelta: number | null;
                cpuPctDelta: number | null;
                memPctDelta: number | null;
                tempDelta: number | null;
              };
              swapped: boolean;
            };
          }
        | { ok: false; error: string }
      >,
  },

  system: {
    // Snapshot of the operator's machine — dashboards pair this with the
    // Pi's reported stats so the user can diff "which side is sick" at a
    // glance. Never throws; on failure the renderer sees `ok: false`.
    getStats: () =>
      ipcRenderer.invoke("system:stats") as Promise<{
        ok: boolean;
        error?: string;
        result?: {
          hostname: string;
          platform: NodeJS.Platform;
          release: string;
          arch: string;
          uptimeSec: number;
          appUptimeSec: number;
          cpu: {
            model: string;
            speedMhz: number;
            count: number;
            loadavg: [number, number, number];
            utilisation: number | null;
          };
          memory: {
            totalBytes: number;
            freeBytes: number;
            usedBytes: number;
            usagePct: number;
          };
          interfaces: {
            name: string;
            mac: string;
            up: boolean;
            internal: boolean;
            addresses: {
              family: "IPv4" | "IPv6";
              address: string;
              cidr: string | null;
            }[];
          }[];
          capturedAt: string;
        };
      }>,
  },

  app: {
    getVersion: () =>
      ipcRenderer.invoke("app:version") as Promise<string>,

    getPlatform: () =>
      ipcRenderer.invoke("app:platform") as Promise<NodeJS.Platform>,
  },

  setup: {
    // Best-effort probe of the operator's LAN for a rud1 device. Tries
    // `rud1.local` (mDNS) and `192.168.50.1` (setup-AP fallback) in parallel.
    // The renderer uses this to decide whether to surface a "Configure your
    // rud1 now" banner — `reachable=false` means no device responded within
    // the budget and the banner stays hidden.
    probeFirmware: () =>
      ipcRenderer.invoke("setup:probeFirmware") as Promise<
        | {
            ok: true;
            result: {
              reachable: boolean;
              host: string;
              panelUrl: string;
              setupUrl: string;
              setup:
                | {
                    complete: boolean;
                    deviceName: string;
                    deviceLocation: string;
                    notes: string;
                    completedAt: number | null;
                    deviceSerial: string;
                    firmwareVersion: string;
                  }
                | null;
              probedAt: number;
              error?: string;
            };
          }
        | { ok: false; error: string }
      >,
  },
});
