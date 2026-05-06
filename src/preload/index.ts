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
      ipcRenderer.invoke("vpn:status") as Promise<{
        connected: boolean;
        ip?: string;
        // Iter 57: lifecycle freshness signals. ISO 8601 (UTC) so the
        // renderer can format them the same way it formats the cloud's
        // lan.lastAppliedAt chip. Null until the corresponding action
        // (connect/disconnect) has succeeded at least once this session.
        lastConnectedAt: string | null;
        lastDisconnectedAt: string | null;
        // Iter 58: derived convenience field — `Date.now() - lastConnectedAt`
        // when the tunnel is up AND we have a connect stamp from this
        // session. Null otherwise (disconnected, no stamp, or clock skew).
        // Lets the renderer paint "Tunnel up 12m" without re-parsing the
        // ISO stamps. Older desktop builds (< iter 58) omit this field;
        // renderers should feature-detect with `??`.
        tunnelUptimeMs: number | null;
      }>,
  },

  usb: {
    /**
     * Attach a remote USB device. The optional `label` is forwarded to
     * the OS notification so the toast reads "SanDisk Cruzer attached"
     * instead of "USB 1-1.4 attached" — the renderer assembles the
     * label from the cloud's UsbDevice row (`vendorName + productName`).
     * Backwards-compatible: omitting it falls back to the bus ID.
     *
     * On Windows when usbip-win2 isn't installed, the response carries
     * `usbipMissing: true` + the absolute path to the bundled
     * installer so the renderer can offer a one-click Install CTA.
     */
    attach: (host: string, busId: string, label?: string) =>
      ipcRenderer.invoke("usb:attach", host, busId, label) as Promise<{
        ok: boolean;
        port?: number;
        error?: string;
        usbipMissing?: boolean;
        installerPath?: string | null;
      }>,

    detach: (port: number) =>
      ipcRenderer.invoke("usb:detach", port) as Promise<{
        ok: boolean;
        error?: string;
        usbipMissing?: boolean;
        installerPath?: string | null;
      }>,

    /**
     * Detach by bus ID. Used by the panel as a fallback when its local
     * attach state was lost (page reload, app restart, navigation) and
     * only the bus id is known. The main process resolves the bus id
     * to a vhci port from the live `usbip port` snapshot. Idempotent:
     * a bus id not currently attached resolves to a silent success.
     */
    detachByBusId: (busId: string) =>
      ipcRenderer.invoke("usb:detachByBusId", busId) as Promise<{
        ok: boolean;
        error?: string;
        usbipMissing?: boolean;
        installerPath?: string | null;
      }>,

    list: () =>
      ipcRenderer.invoke("usb:list") as Promise<{ port: number; host: string; busId: string }[]>,

    /**
     * Probe whether the USB/IP userspace tool is reachable. Useful for
     * showing an "Install USB/IP" banner before the user even clicks
     * Attach. `installerPath` is non-null only on Windows builds with
     * the bundled NSIS installer present (developer ran `fetch:usbip-win`).
     */
    status: () =>
      ipcRenderer.invoke("usb:status") as Promise<
        | {
            ok: true;
            installed: boolean;
            installerPath: string | null;
            platform: NodeJS.Platform;
          }
        | { ok: false; error: string }
      >,

    /**
     * Run the bundled USB/IP NSIS installer (Windows only). The user
     * sees the usbip-win2 install dialog and walks through driver
     * acceptance; we don't await completion. Renderer should retry
     * `usb.status()` after the user closes the installer.
     */
    launchInstaller: () =>
      ipcRenderer.invoke("usb:launchInstaller") as Promise<
        { ok: true } | { ok: false; error: string }
      >,
  },

  /**
   * Serial bridge — alternate transport for CDC-class devices
   * (Arduinos, ESP32 dev boards, USB-serial dongles). The cloud's
   * Connect tab feature-detects this whole namespace; older desktop
   * builds (< this iter) don't expose it and the panel falls back
   * to USB/IP for every device, which is the pre-bridge behaviour.
   */
  serial: {
    /** Spin up a TCP↔serial bridge for `busId`. Returns the local
     *  path (Windows COM port the user opens, or Unix pty symlink)
     *  once rud1-bridge has bound the endpoint. */
    open: (opts: {
      busId: string;
      piHost: string;
      baud?: number;
      dataBits?: number;
      parity?: string;
      stopBits?: string;
      label?: string;
    }) =>
      ipcRenderer.invoke("serial:open", opts) as Promise<
        | {
            ok: true;
            result: {
              busId: string;
              endpointPath: string;
              userVisiblePath: string;
              pid: number;
            };
          }
        | {
            ok: false;
            error: string;
            /** Set when com0com is missing or has no pairs configured.
             *  The renderer surfaces a CTA banner with setup steps. */
            com0comMissing?: boolean;
            setupcPath?: string | null;
            hasPairs?: boolean;
            /** Set when a com0com pair exists but lacks COMxx aliases —
             *  Arduino IDE won't list CNCAx/CNCBx in its port picker.
             *  Renderer surfaces the "Configurar par COM" CTA. */
            com0comPairNotAliased?: boolean;
            /** Set when a com0com pair has COM aliases but is missing
             *  EmuBR=yes on the user side — Arduino IDE 2.x filters
             *  Tools > Port on the PNP attributes EmuBR enables, so
             *  the COM is reachable via `mode COMx` but invisible to
             *  the IDE. Same recovery path as `com0comPairNotAliased`
             *  (the Configure CTA re-runs setupc with EmuBR=yes). */
            com0comPairNoEmuBR?: boolean;
            pair?: {
              pairId: string;
              userPort: string;
              bridgePort: string;
              hasComAlias: boolean;
              emuBR?: boolean;
            };
          }
      >,

    /** Tear down the bridge for `busId`. Idempotent. */
    close: (busId: string) =>
      ipcRenderer.invoke("serial:close", busId) as Promise<
        { ok: true } | { ok: false; error: string }
      >,

    /**
     * Manual DTR pulse for an open bridge session. The firmware drives
     * DTR low on the live `/dev/ttyACMx` for `pulseMs` (default 50)
     * then re-asserts it — same shape Arduino's reset circuit expects.
     * The session must already be open (Connect first); the firmware
     * returns 404 otherwise. `pulseMs` is clamped firmware-side to
     * [10, 5000].
     */
    reset: (opts: { busId: string; piHost: string; pulseMs?: number }) =>
      ipcRenderer.invoke("serial:reset", opts) as Promise<
        { ok: true } | { ok: false; error: string }
      >,

    /** Snapshot of the bridge subsystem: bundled binary present,
     *  com0com state on Windows, currently-active sessions. */
    status: () =>
      ipcRenderer.invoke("serial:status") as Promise<
        | {
            ok: true;
            result: {
              binaryAvailable: boolean;
              com0com: {
                installed: boolean;
                setupcPath: string | null;
                pairs: { pairId: string; userPort: string; bridgePort: string }[];
                error?: string;
              } | null;
              sessions: {
                busId: string;
                pid: number;
                endpointPath: string;
                startedAt: string;
                lastEvent?: string;
              }[];
            };
          }
        | { ok: false; error: string }
      >,

    /** Drill-down: live session for one bus id, or null. */
    sessionFor: (busId: string) =>
      ipcRenderer.invoke("serial:sessionFor", busId) as Promise<
        | {
            ok: true;
            result: {
              busId: string;
              pid: number;
              endpointPath: string;
              startedAt: string;
              lastEvent?: string;
            } | null;
          }
        | { ok: false; error: string }
      >,

    /**
     * Run the bundled com0com installer (Windows only). Symmetric to
     * `usb.launchInstaller` for the USB/IP driver. The user sees the
     * com0com install dialog and walks through driver acceptance; the
     * panel should retry `serial.status()` after the user closes the
     * installer to detect the new install.
     */
    launchInstaller: () =>
      ipcRenderer.invoke("serial:launchInstaller") as Promise<
        { ok: true } | { ok: false; error: string }
      >,

    /**
     * Assign COMxx aliases to a com0com pair that's currently named
     * CNCAxxx/CNCBxxx. Triggers UAC because setupc.exe needs admin
     * to drive the kernel driver's IOCTLs. Defaults to COM200/COM201
     * so we don't collide with real COM ports the user may have.
     * Idempotent: returns the existing aliased pair if one already
     * exists.
     */
    configurePair: (opts?: { userPortAlias?: string; bridgePortAlias?: string }) =>
      ipcRenderer.invoke("serial:configurePair", opts) as Promise<
        | {
            ok: true;
            result: {
              pairId: string;
              userPort: string;
              bridgePort: string;
              hasComAlias: boolean;
            };
          }
        | { ok: false; error: string; com0comMissing?: boolean }
      >,
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

    /**
     * Read the OS-level "launch at login" preference plus a feature-
     * gating flag. `unsupported: true` means the desktop is running
     * unpackaged (dev) or on an exotic platform; the renderer should
     * disable the toggle and show `reason` as a tooltip.
     */
    getAutoStart: () =>
      ipcRenderer.invoke("app:getAutoStart") as Promise<
        | {
            ok: true;
            result: {
              enabled: boolean;
              unsupported: boolean;
              reason?: string;
              platform: NodeJS.Platform;
            };
          }
        | { ok: false; error: string }
      >,

    /**
     * Toggle "launch at login". Returns the OS-confirmed state — the
     * renderer should mirror that value rather than its optimistic
     * pre-flip, so a refusal (sandbox, missing perms) shows up as a
     * snap-back of the switch.
     */
    setAutoStart: (enabled: boolean) =>
      ipcRenderer.invoke("app:setAutoStart", enabled) as Promise<
        | {
            ok: true;
            result: {
              enabled: boolean;
              unsupported: boolean;
              reason?: string;
              platform: NodeJS.Platform;
            };
          }
        | { ok: false; error: string }
      >,

    /**
     * Read the persisted preferences blob (theme override + per-category
     * notification toggles). The Settings window calls this on mount and
     * after every toggle to mirror the canonical post-merge shape.
     */
    getPreferences: () =>
      ipcRenderer.invoke("app:getPreferences") as Promise<
        | {
            ok: true;
            result: {
              theme: "system" | "light" | "dark";
              notifications: { firstBoot: boolean; vpn: boolean; usb: boolean };
            };
          }
        | { ok: false; error: string }
      >,

    /**
     * Patch the persisted preferences. Fields omitted from the patch are
     * preserved; the response carries the post-merge state so the renderer
     * can render the canonical shape rather than its optimistic prediction.
     */
    setPreferences: (patch: {
      theme?: "system" | "light" | "dark";
      notifications?: Partial<{ firstBoot: boolean; vpn: boolean; usb: boolean }>;
    }) =>
      ipcRenderer.invoke("app:setPreferences", patch) as Promise<
        | {
            ok: true;
            result: {
              theme: "system" | "light" | "dark";
              notifications: { firstBoot: boolean; vpn: boolean; usb: boolean };
            };
          }
        | { ok: false; error: string }
      >,
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

  // Iter 28 — Settings UI for the persisted first-boot dedupe set.
  // Surfaces the iter-27 `<userData>/first-boot-notifications.json` to a
  // small inspector window opened from the tray submenu. Three operations:
  //   list      — read the in-memory mirror (fast; never touches disk)
  //   clearHost — drop one host + atomically rewrite the file
  //   clearAll  — drop everything + atomically rewrite the file
  // The main process ALSO pushes a `firstBootDedupe:update` event after
  // any mutation so the inspector window can refresh without polling;
  // `onUpdate` registers a listener and returns an unsubscribe handle.
  firstBootDedupe: {
    list: () =>
      ipcRenderer.invoke("firstBootDedupe:list") as Promise<
        | { ok: true; result: { host: string; notifiedAt: string }[] }
        | { ok: false; error: string }
      >,

    clearHost: (host: string) =>
      ipcRenderer.invoke("firstBootDedupe:clearHost", host) as Promise<
        | { ok: true; result: { host: string; notifiedAt: string }[] }
        | { ok: false; error: string }
      >,

    clearAll: () =>
      ipcRenderer.invoke("firstBootDedupe:clearAll") as Promise<
        | { ok: true }
        | { ok: false; error: string }
      >,

    onUpdate: (cb: (hosts: { host: string; notifiedAt: string }[]) => void) => {
      const listener = (
        _event: Electron.IpcRendererEvent,
        hosts: { host: string; notifiedAt: string }[],
      ) => cb(hosts);
      ipcRenderer.on("firstBootDedupe:update", listener);
      return () => ipcRenderer.removeListener("firstBootDedupe:update", listener);
    },
  },

  // Iter 37 — Settings/About panel "Updates" section. Surfaces the live
  // `VersionCheckState` to a small inspector window opened from the tray
  // submenu. The blocked-by-min-bootstrap state in particular is the
  // headline addition: an operator running an old enough version sees a
  // banner with a "Copy download URL" button (clipboard via IPC) so they
  // can install the bridge build manually.
  //   state    — read the current VersionCheckState
  //   recheck  — trigger an immediate refetch of the manifest
  //   onUpdate — subscribe to push updates broadcast by main on every
  //              state transition (no polling required)
  versionCheck: {
    state: () =>
      ipcRenderer.invoke("versionCheck:state") as Promise<
        | { ok: true; result: import("../main/version-check-manager").VersionCheckState }
        | { ok: false; error: string }
      >,
    recheck: () =>
      ipcRenderer.invoke("versionCheck:recheck") as Promise<
        | { ok: true }
        | { ok: false; error: string }
      >,
    onUpdate: (
      cb: (state: import("../main/version-check-manager").VersionCheckState) => void,
    ) => {
      const listener = (
        _event: Electron.IpcRendererEvent,
        state: import("../main/version-check-manager").VersionCheckState,
      ) => cb(state);
      ipcRenderer.on("versionCheck:update", listener);
      return () => ipcRenderer.removeListener("versionCheck:update", listener);
    },
  },

  // Iter 37 — clipboard + shell:openExternal for the Settings/About panel.
  // `clipboard.writeText` is invoked from main rather than the renderer's
  // `navigator.clipboard` so the data:-URL panel doesn't need a permission
  // grant. `shell.openExternal` is allowlisted main-side to http/https only.
  clipboard: {
    writeText: (text: string) =>
      ipcRenderer.invoke("clipboard:writeText", text) as Promise<
        | { ok: true }
        | { ok: false; error: string }
      >,
  },
  shell: {
    openExternal: (url: string) =>
      ipcRenderer.invoke("shell:openExternal", url) as Promise<
        | { ok: true }
        | { ok: false; error: string }
      >,
  },
});
