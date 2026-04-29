/**
 * Serial bridge manager — the desktop-side counterpart to rud1-fw's
 * serial-bridge package. Spawns the bundled `rud1-bridge` Go binary
 * for each CDC-class device the operator wants to connect, manages
 * its lifecycle, and surfaces the local endpoint path (Windows COM
 * the user opens in Arduino IDE, or Unix pty) back to the renderer.
 *
 * Why a Go subprocess instead of an in-process Node module: see the
 * planning notes — the short version is that the native `serialport`
 * npm package introduces a build/CI tax (electron-rebuild against
 * each Electron version, signing the .node on macOS, AV false-positive
 * pressure) that doesn't pay off for a bridge that's a couple
 * hundred lines of pure-Go forwarding logic. The Go binary cross-
 * compiles trivially from one Windows dev box to all three target
 * platforms.
 *
 * Lifecycle:
 *   1. Renderer calls electronAPI.serial.open({ busId, piHost, piPort,
 *      baud? }).
 *   2. We pre-flight com0com (Windows only) to discover an unused
 *      pair and pick its B-side as our endpoint.
 *   3. We spawn rud1-bridge with the right flags, wait for the
 *      "BRIDGE-READY" line on stdout, parse the JSON envelope to
 *      learn the endpoint path, and reply to the renderer.
 *   4. The renderer surfaces "Open COMx in your Arduino IDE" in the
 *      Connect tab.
 *   5. On close (renderer click, app quit, VPN disconnect), we send
 *      SIGTERM (Unix) / signal-the-process (Windows) and the binary
 *      cleans up the endpoint.
 */

import { spawn, ChildProcess } from "child_process";
import path from "path";
import readline from "readline";

import {
  rud1BridgePath,
  isRud1BridgeAvailable,
} from "./binary-helper";
import {
  detectCom0com,
  pickPair,
  pickFreePair,
  Com0comPair,
  Com0comStatus,
} from "./com0com-detector";

// Argument validators. Keep these strict — the values flow into a
// child_process spawn argv and we want the same crisp pre-spawn rejection
// pattern usb-manager uses.
const HOST_REGEX = /^[a-zA-Z0-9.\-:]{1,253}$/;
const BUS_ID_REGEX = /^[0-9]+-[0-9]+(?:\.[0-9]+)*$/;

function assertHost(host: unknown): asserts host is string {
  if (typeof host !== "string" || host.startsWith("-") || !HOST_REGEX.test(host)) {
    throw new Error("invalid host");
  }
}

function assertBusId(busId: unknown): asserts busId is string {
  if (typeof busId !== "string" || !BUS_ID_REGEX.test(busId)) {
    throw new Error("invalid busId");
  }
}

function assertPort(port: unknown): asserts port is number {
  if (
    typeof port !== "number" ||
    !Number.isInteger(port) ||
    port <= 0 ||
    port > 65535
  ) {
    throw new Error("invalid port");
  }
}

export interface OpenOptions {
  /** USB bus id of the device on the Pi (e.g. "1-1.3"). */
  busId: string;
  /** VPN-reachable host of the Pi. The desktop holds the WG tunnel;
   *  the cloud doesn't (Vercel functions have no route to a private
   *  WG subnet), so the manager hits the Pi's
   *  /api/serial-bridge/open directly — same pattern as
   *  usb-manager.ts's `bindOnPi` for USB/IP attaches. */
  piHost: string;
  /** Initial line settings. Defaults to 115200 8N1 — the universal
   *  Arduino upload speed. Override only when the cloud has a
   *  device-specific value (rare). */
  baud?: number;
  dataBits?: number;
  parity?: string;
  stopBits?: string;
  /** Optional human-readable label for diagnostics chips. */
  label?: string;
}

export interface OpenResult {
  busId: string;
  endpointPath: string;
  /** Absolute path to the symlink (Unix) or the COM port name
   *  (Windows) the user should open. Same value as endpointPath
   *  but explicitly named so the renderer can render the right
   *  copy ("Open /tmp/..." vs "Open COM7"). */
  userVisiblePath: string;
  /** Process id of the spawned rud1-bridge — useful for the
   *  diagnostics chip. */
  pid: number;
}

export interface BridgeStatus {
  /** Bundled binary present? false ⇒ developer skipped build:bridge. */
  binaryAvailable: boolean;
  /** com0com installed (Windows only; always true elsewhere because
   *  PTY support is in-kernel). */
  com0com: Com0comStatus | null;
  /** Currently-open sessions, keyed by bus id. */
  sessions: BridgeSessionInfo[];
}

export interface BridgeSessionInfo {
  busId: string;
  pid: number;
  endpointPath: string;
  startedAt: string;
  /** Last line of stderr (truncated to 200 chars). Useful for the
   *  panel's diagnostics chip when the session is misbehaving. */
  lastEvent?: string;
}

interface ActiveSession {
  busId: string;
  proc: ChildProcess;
  endpointPath: string;
  startedAt: number;
  lastEvent?: string;
  /** com0com pair we claimed for this session (Windows only). The
   *  manager doesn't release/reclaim pairs across sessions in MVP
   *  scope — Windows operators typically have one pair and we round-
   *  robin sessions on it via lifecycle, not via parallel pairs. */
  pair?: Com0comPair;
}

const sessions = new Map<string, ActiveSession>();

/**
 * Allocate a bridge slot on the Pi. The Pi's
 * `/api/serial-bridge/open` endpoint binds /dev/ttyACMx in
 * userspace, allocates a TCP listener slot from the configured
 * BasePort range, and returns the actual port the desktop should
 * dial. Mirror of `bindOnPi` in usb-manager.ts — same call site,
 * same VPN reachability requirement, same "swallow network errors
 * so the underlying connect surfaces a more specific message"
 * pattern.
 *
 * Errors mapped to the panel's CTA shapes:
 *   - 503  → bridge disabled in firmware config (operator hasn't
 *            set `usb.serial_bridge.enabled: true`)
 *   - 404  → device unplugged between heartbeat and click, OR the
 *            firmware predates the bridge support
 *   - 423  → /dev/ttyACMx held by another process (ModemManager,
 *            brltty, a stale handle)
 *   - 422  → device isn't actually CDC-class (panel's auto-mode
 *            misfired; should fall back to USB/IP)
 *   - 409  → all session slots taken (bump cfg.MaxSessions)
 *   - 5xx  → genuine firmware error
 *   - network failure → tunnel is down OR firmware not running;
 *                       surfaced as a single human-readable hint.
 */
async function allocateOnPi(piHost: string, busId: string): Promise<{
  tcpPort: number;
  devicePath: string;
}> {
  const url = `http://${piHost}:7070/api/serial-bridge/open`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ busId }),
      signal: AbortSignal.timeout(8000),
    });
  } catch (err) {
    throw new Error(
      "Could not reach the device's serial-bridge endpoint. " +
      "Check that the WireGuard tunnel is up and that the Pi has " +
      "`usb.serial_bridge.enabled: true` in /etc/rud1-agent/config.yaml" +
      (err instanceof Error ? ` (cause: ${err.message})` : ""),
    );
  }

  if (!res.ok) {
    let detail = "";
    try { detail = (await res.text()).slice(0, 500).trim(); } catch { /* ignore */ }
    if (res.status === 503) {
      throw new Error(
        "Serial bridge is disabled on the device. " +
        "Set `usb.serial_bridge.enabled: true` in /etc/rud1-agent/config.yaml " +
        "on the Pi and restart rud1-fw, then retry.",
      );
    }
    if (res.status === 423) {
      throw new Error(
        "The serial port is held by another process on the Pi (likely " +
        "ModemManager or brltty). Apply the udev rule for your USB-serial " +
        "vendor and replug, then retry.",
      );
    }
    if (res.status === 422) {
      throw new Error(
        "The Pi reports this device is not CDC-class. Use the USB/IP " +
        "transport instead (Connect tab will fall back automatically).",
      );
    }
    if (res.status === 404) {
      throw new Error(
        "The Pi has no /dev/ttyACMx for this bus id. Either the device " +
        "was unplugged, or the firmware predates the bridge feature " +
        "(re-deploy rud1-fw on the Pi).",
      );
    }
    throw new Error(
      `Pi rejected serial-bridge open for ${busId} (HTTP ${res.status})` +
      (detail ? `: ${detail}` : ""),
    );
  }

  const body = await res.json().catch(() => null) as
    | { busId?: string; tcpPort?: number; devicePath?: string }
    | null;
  if (!body || typeof body.tcpPort !== "number") {
    throw new Error("Pi returned malformed serial-bridge session");
  }
  return {
    tcpPort: body.tcpPort,
    devicePath: typeof body.devicePath === "string" ? body.devicePath : "",
  };
}

/**
 * Best-effort release of a Pi-side bridge slot. Used as the
 * compensating action when local rud1-bridge spawn fails AFTER we
 * already allocated a slot — we don't want to strand the slot until
 * the firmware GCs it. Network failures here are silent because the
 * caller is already on the error path; the firmware will notice the
 * dropped TCP socket and clean up regardless.
 */
async function releaseOnPi(piHost: string, busId: string): Promise<void> {
  const url = `http://${piHost}:7070/api/serial-bridge/open`;
  try {
    await fetch(url, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ busId }),
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    /* swallow — best-effort */
  }
}

/**
 * Manual DTR-pulse reset for an open bridge session. Hits the Pi's
 * `/api/serial-bridge/reset` directly over the WG tunnel — same pattern
 * as `allocateOnPi`/`releaseOnPi`. Use case: clients that don't
 * synthesize DTR via RFC 2217 (raw-TCP scopes, com0com pairs that
 * mishandle modem-control IOCTLs across the pair). The session must
 * already be open; the firmware returns 404 otherwise and we surface
 * a clear "Open the bridge first" hint.
 *
 * `pulseMs` is optional and clamped firmware-side to [10, 5000]; 50 ms
 * is the optiboot reference width.
 */
export async function serialBridgeReset(opts: {
  piHost: string;
  busId: string;
  pulseMs?: number;
}): Promise<void> {
  assertHost(opts.piHost);
  assertBusId(opts.busId);
  if (
    opts.pulseMs != null &&
    (!Number.isInteger(opts.pulseMs) || opts.pulseMs < 1 || opts.pulseMs > 5000)
  ) {
    throw new Error("invalid pulseMs (1..5000)");
  }
  const url = `http://${opts.piHost}:7070/api/serial-bridge/reset`;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        busId: opts.busId,
        ...(opts.pulseMs ? { pulseMs: opts.pulseMs } : {}),
      }),
      signal: AbortSignal.timeout(8000),
    });
  } catch (err) {
    throw new Error(
      "Could not reach the device's serial-bridge reset endpoint. " +
        "Check that the WireGuard tunnel is up and the bridge listener is running" +
        (err instanceof Error ? ` (cause: ${err.message})` : ""),
    );
  }
  if (res.ok) return;
  let detail = "";
  try { detail = (await res.text()).slice(0, 500).trim(); } catch { /* ignore */ }
  if (res.status === 404) {
    throw new Error(
      "No live bridge session for this device on the Pi. Click Connect on " +
        "the device first, then try Reset again.",
    );
  }
  if (res.status === 503) {
    throw new Error(
      "Serial bridge is disabled on the device. Enable " +
        "`usb.serial_bridge.enabled: true` in /etc/rud1-agent/config.yaml on the Pi.",
    );
  }
  throw new Error(
    `Pi rejected serial-bridge reset for ${opts.busId} (HTTP ${res.status})` +
      (detail ? `: ${detail}` : ""),
  );
}

/**
 * Stable error class so the IPC handler can recognise the "com0com
 * not installed / pair not configured" failure mode without grepping
 * messages. The renderer turns this into a CTA banner.
 */
export class Com0comMissingError extends Error {
  readonly setupcPath: string | null;
  readonly hasPairs: boolean;
  constructor(status: Com0comStatus) {
    const reason = !status.installed
      ? "com0com is not installed. Download the signed installer from " +
        "https://sourceforge.net/projects/com0com/ and create a virtual " +
        "COM port pair (default settings are fine)."
      : "com0com is installed but no virtual COM port pairs are " +
        "configured. Run com0com's setupc.exe and add a pair " +
        "(`install PortName=COM7 PortName=COM8`).";
    super(reason);
    this.name = "Com0comMissingError";
    this.setupcPath = status.setupcPath;
    this.hasPairs = status.pairs.length > 0;
  }
}

/**
 * Raised when com0com is installed AND has at least one pair, but no
 * pair carries a COMxx alias. Arduino IDE (and most other tools that
 * enumerate ports by COM name) won't show CNCAx/CNCBx in their port
 * pickers, so without a COMxx alias the bridge spawn succeeds but the
 * operator can't actually open it. Distinct from `Com0comMissingError`
 * because the recovery path is different: the user runs
 * `setupc change CNCAn PortName=COMxx` (one UAC) instead of running
 * the full installer.
 */
export class Com0comPairNotAliasedError extends Error {
  readonly pair: Com0comPair;
  readonly setupcPath: string | null;
  constructor(pair: Com0comPair, setupcPath: string | null) {
    super(
      `The com0com pair (${pair.userPort} / ${pair.bridgePort}) has no COMxx ` +
      "alias, so Arduino IDE won't show it in its port picker. Use the " +
      "'Configure COM port pair' action in the Connect tab to assign " +
      "aliases (one UAC prompt), or run setupc.exe manually: " +
      `\`setupc change ${pair.userPort} PortName=COM200\` and ` +
      `\`setupc change ${pair.bridgePort} PortName=COM201\`.`,
    );
    this.name = "Com0comPairNotAliasedError";
    this.pair = pair;
    this.setupcPath = setupcPath;
  }
}

/**
 * Brings up a serial bridge session. Returns once the bundled
 * rud1-bridge has bound the local endpoint AND printed its ready
 * line — at that point the renderer can tell the operator which
 * path to open. Subsequent failures (TCP handshake, byte pumps)
 * surface via the close event, not this promise.
 */
export async function serialBridgeOpen(opts: OpenOptions): Promise<OpenResult> {
  assertBusId(opts.busId);
  assertHost(opts.piHost);
  if (opts.baud != null && (!Number.isInteger(opts.baud) || opts.baud < 50 || opts.baud > 4_000_000)) {
    throw new Error("invalid baud");
  }

  if (!isRud1BridgeAvailable()) {
    throw new Error(
      "rud1-bridge binary missing. Run `npm run build:bridge` to compile " +
      "the cross-platform bridge for win32 / linux / darwin.",
    );
  }

  if (sessions.has(opts.busId)) {
    // Idempotent: returning the existing session matches USB/IP
    // attach semantics and lets the renderer click Open twice
    // without an error toast.
    const s = sessions.get(opts.busId)!;
    return {
      busId: s.busId,
      endpointPath: s.endpointPath,
      userVisiblePath: s.endpointPath,
      pid: s.proc.pid ?? -1,
    };
  }

  // Step 1: resolve the local endpoint based on platform. We do this
  // BEFORE allocating on the Pi so a local-side failure (com0com
  // missing on Windows, no pty on Unix) doesn't strand a Pi-side
  // slot that we'd then have to rollback.
  let pair: Com0comPair | undefined;
  let portArg: string[] = [];
  let linkArg: string[] = [];
  if (process.platform === "win32") {
    const status = await detectCom0com();
    const picked = pickPair(status);
    if (!picked) throw new Com0comMissingError(status);
    if (!picked.hasComAlias) {
      // The bridge subprocess CAN open `\\.\CNCB0` and the bytes
      // would flow, but Arduino IDE / most other COM-aware tools
      // enumerate by COMxx prefix and won't show CNCBx in their
      // pickers. Surface a precise "configure aliases" error so the
      // panel renders the dedicated CTA instead of letting the user
      // start a session they can't actually use.
      throw new Com0comPairNotAliasedError(picked, status.setupcPath);
    }
    pair = picked;
    // Pass the B-side to rud1-bridge; the user opens the A-side.
    portArg = ["--local-port", pair.bridgePort];
  } else {
    // Unix pty: derive a stable symlink from the bus id so the user
    // can build muscle memory ("Arduino on bus 1-1.3 is always at
    // /tmp/rud1-bridge-1-1.3"). We sanitise dots to dashes for
    // tools that don't like dots in tty names.
    const safeBus = opts.busId.replace(/\./g, "-");
    const linkPath = path.join("/tmp", `rud1-bridge-${safeBus}`);
    linkArg = ["--link-path", linkPath];
  }

  // Step 2: allocate the slot on the Pi. The desktop has the WG
  // tunnel up; the cloud doesn't, so this call is desktop-direct
  // (same pattern as usb-manager.ts's `bindOnPi` for USB/IP).
  const piSession = await allocateOnPi(opts.piHost, opts.busId);

  const baud = opts.baud ?? 115200;
  const dataBits = opts.dataBits ?? 8;
  const parity = opts.parity ?? "N";
  const stopBits = opts.stopBits ?? "1";

  const args = [
    "--pi-host", opts.piHost,
    "--pi-port", String(piSession.tcpPort),
    "--baud", String(baud),
    "--data-bits", String(dataBits),
    "--parity", parity,
    "--stop-bits", stopBits,
    ...portArg,
    ...linkArg,
  ];

  // Step 3: spawn rud1-bridge. From here on out, ANY failure must
  // release the Pi-side slot we allocated above (rollback) so we
  // don't strand it.
  const binPath = rud1BridgePath();
  let proc: ChildProcess;
  try {
    proc = spawn(binPath, args, {
      windowsHide: true,
      // We pipe stderr (structured JSON events). stdin is ignored
      // because the binary doesn't read it, but a 'pipe' would
      // create a writable handle that can deadlock if it ever did.
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    await releaseOnPi(opts.piHost, opts.busId);
    throw err;
  }

  const session: ActiveSession = {
    busId: opts.busId,
    proc,
    endpointPath: "", // populated by the ready line below
    startedAt: Date.now(),
    pair,
  };
  sessions.set(opts.busId, session);

  // Stream stderr through readline so we capture one event per line
  // even if the kernel hands us partial buffers. We keep only the
  // most recent line for the diagnostics chip; older lines roll off.
  if (proc.stderr) {
    const rl = readline.createInterface({ input: proc.stderr });
    rl.on("line", (line) => {
      session.lastEvent = line.length > 200 ? line.slice(0, 200) + "…" : line;
    });
  }

  proc.on("exit", (code, signal) => {
    sessions.delete(opts.busId);
    // When the binary exits the Pi-side TCP socket closes, which
    // tells the firmware to release the slot — no explicit rollback
    // needed here. The diagnostics chip surfaces lastEvent so the
    // operator can correlate.
    void code; void signal;
    // Best-effort explicit release for cases where the firmware's
    // socket-close detection lags (slow network, half-open TCP):
    // tells the Pi to drop the slot now rather than waiting for
    // its keepalive timeout to fire.
    void releaseOnPi(opts.piHost, opts.busId);
  });

  // Step 4: wait for the BRIDGE-READY line on stdout. 8s is
  // generous — typical case is <100ms.
  let ready: { path: string };
  try {
    ready = await waitForReady(proc, 8000);
  } catch (err) {
    // Rollback: kill the binary and release the Pi slot. The exit
    // handler above will also attempt a release, but doing it here
    // explicitly reduces the gap between local failure and the slot
    // being available again.
    try { proc.kill(); } catch { /* ignore */ }
    sessions.delete(opts.busId);
    await releaseOnPi(opts.piHost, opts.busId);
    throw err;
  }
  session.endpointPath = ready.path;

  // On Windows, the user opens the A-side of the pair, not the
  // B-side rud1-bridge took. We swap the path so the renderer
  // surfaces the right COMx number.
  const userVisible =
    process.platform === "win32" && pair ? pair.userPort : ready.path;

  return {
    busId: opts.busId,
    endpointPath: ready.path,
    userVisiblePath: userVisible,
    pid: proc.pid ?? -1,
  };
}

/**
 * Tear down a session. Idempotent: closing a non-existent bus id
 * is not an error.
 */
export async function serialBridgeClose(busId: string): Promise<void> {
  assertBusId(busId);
  const s = sessions.get(busId);
  if (!s) return;
  // Send SIGTERM. On Windows that translates to a polite kill —
  // rud1-bridge's signal.NotifyContext handler will fire and the
  // bridge unwinds cleanly, releasing the COM port.
  s.proc.kill();
  // Wait up to 3s for the process to exit; fall through if it
  // hangs (kill -9 is the next escalation).
  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      try { s.proc.kill("SIGKILL"); } catch { /* ignore */ }
      resolve();
    }, 3000);
    s.proc.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
  });
  sessions.delete(busId);
}

/**
 * Tear down every active session. Used as the symmetric counterpart
 * to the VPN-disconnect cleanup that already exists for USB/IP.
 */
export async function serialBridgeCloseAll(): Promise<void> {
  const ids = Array.from(sessions.keys());
  await Promise.all(ids.map((id) => serialBridgeClose(id)));
}

/**
 * Drives `setupc.exe change` to assign COMxx aliases to a com0com
 * pair that's currently named CNCAxxx/CNCBxxx. Runs setupc with
 * elevation so the kernel-driver IOCTL succeeds; UAC prompts the
 * user once, after which the alias persists across reboots.
 *
 * The default aliases (COM200 / COM201) are deliberately high to
 * dodge collisions with real COM ports the operator may already
 * have. They're surfaced via Com0comPair.userPort once the
 * configuration completes, so the next attach picks them up.
 *
 * Idempotent: if the pair is already aliased, this is a no-op.
 * Returns the new pair shape on success so the renderer can flip
 * its state without a fresh status round-trip.
 */
export async function serialBridgeConfigurePair(opts?: {
  userPortAlias?: string;
  bridgePortAlias?: string;
}): Promise<Com0comPair> {
  if (process.platform !== "win32") {
    throw new Error("serialBridgeConfigurePair is Windows-only");
  }
  const status = await detectCom0com();
  if (!status.installed || !status.setupcPath) {
    throw new Com0comMissingError(status);
  }
  // Pick the first pair without a COM alias; if every pair already
  // has one, fall through and treat as no-op.
  const target = status.pairs.find((p) => !p.hasComAlias);
  if (!target) {
    const aliased = status.pairs.find((p) => p.hasComAlias);
    if (!aliased) throw new Com0comMissingError(status);
    return aliased;
  }
  // Default to a low pair (e.g. COM7/COM8) when one is free, fall
  // through to the legacy COM200/COM201 backstop otherwise. The low
  // numbers dodge a class of vendor-tool bugs ("can't enumerate
  // 3-digit COM names") while still staying clear of the conventional
  // modem (COM1) and common USB-serial slots (COM3/COM4). Operators
  // with strong opinions can still pass `userPortAlias`/
  // `bridgePortAlias` to override.
  const defaults = await pickFreePair(status);
  const userAlias = opts?.userPortAlias ?? defaults.user;
  const bridgeAlias = opts?.bridgePortAlias ?? defaults.bridge;

  // Validate aliases as a guardrail — the values flow through to a
  // child_process spawn argv; we don't want a crafted IPC message
  // to smuggle quotes or shell metacharacters into setupc.
  if (!/^COM\d{1,4}$/i.test(userAlias) || !/^COM\d{1,4}$/i.test(bridgeAlias)) {
    throw new Error(`invalid COM alias (expected COM<n>): ${userAlias} / ${bridgeAlias}`);
  }
  if (userAlias.toLowerCase() === bridgeAlias.toLowerCase()) {
    throw new Error("user and bridge aliases must differ");
  }

  // setupc requires admin. We run it via PowerShell's Start-Process
  // -Verb RunAs so the OS handles the UAC prompt — invoking setupc
  // directly from a non-elevated process would silently fail with
  // "ACCESS_DENIED" inside its own log instead of triggering a
  // user-visible elevation dialog. Two `change` invocations because
  // setupc takes one comma-list of options per run.
  //
  // EmuBR=yes + EmuOverrun=yes: makes Windows enumerate the port as
  // "real hardware" rather than a generic virtual COM. Arduino IDE
  // 2.x's port picker filters out ports without the hardware-class
  // PNP attributes — without these, COM200 exists in `mode COM200`
  // but never appears in the IDE's Tools > Port dropdown. This is
  // the most-reported gotcha from operators new to com0com; setting
  // it at alias time means the first Conectar Just Works.
  const opts2 = "EmuBR=yes,EmuOverrun=yes";
  const setupc = status.setupcPath;
  const psCmd = [
    `Start-Process -FilePath '${setupc}' -ArgumentList 'change',` +
    `'${target.userPort}','PortName=${userAlias},${opts2}' -Verb RunAs -Wait;`,
    `Start-Process -FilePath '${setupc}' -ArgumentList 'change',` +
    `'${target.bridgePort}','PortName=${bridgeAlias},${opts2}' -Verb RunAs -Wait`,
  ].join(" ");
  await execFileAsyncImport()(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", psCmd],
    { windowsHide: true, timeout: 60_000 },
  );

  // Re-detect to confirm the alias landed. The kernel IOCTL is
  // synchronous on success, so we don't need a poll loop here — but
  // we DO need to give Windows a moment to refresh the COM port
  // enumeration cache, otherwise the next setupc list still shows
  // the old name.
  await new Promise((r) => setTimeout(r, 500));
  const fresh = await detectCom0com();
  const updated = fresh.pairs.find(
    (p) => p.userPort === userAlias && p.bridgePort === bridgeAlias,
  );
  if (!updated) {
    throw new Error(
      `Configure pair completed but the alias (${userAlias} / ${bridgeAlias}) ` +
      "isn't reflected in setupc list yet. Try clicking Connect again — if " +
      "it still fails, run setupc list manually as admin to inspect.",
    );
  }
  return updated;
}

// Lazy execFile import: keep the top-of-file imports lean so the
// hot path doesn't pay for promisify on every load.
let _execFileAsync: ReturnType<typeof makeExecFileAsync> | null = null;
function execFileAsyncImport() {
  if (!_execFileAsync) _execFileAsync = makeExecFileAsync();
  return _execFileAsync;
}
function makeExecFileAsync() {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { execFile } = require("child_process") as typeof import("child_process");
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { promisify } = require("util") as typeof import("util");
  return promisify(execFile);
}

/** Status snapshot for the renderer's diagnostics chip. */
export async function serialBridgeStatus(): Promise<BridgeStatus> {
  const com0com =
    process.platform === "win32" ? await detectCom0com() : null;
  return {
    binaryAvailable: isRud1BridgeAvailable(),
    com0com,
    sessions: Array.from(sessions.values()).map((s) => ({
      busId: s.busId,
      pid: s.proc.pid ?? -1,
      endpointPath: s.endpointPath,
      startedAt: new Date(s.startedAt).toISOString(),
      lastEvent: s.lastEvent,
    })),
  };
}

/** Return the live session for a bus id (or null). */
export function serialBridgeSessionFor(busId: string): BridgeSessionInfo | null {
  const s = sessions.get(busId);
  if (!s) return null;
  return {
    busId: s.busId,
    pid: s.proc.pid ?? -1,
    endpointPath: s.endpointPath,
    startedAt: new Date(s.startedAt).toISOString(),
    lastEvent: s.lastEvent,
  };
}

/**
 * Wait for the BRIDGE-READY line on stdout. Times out with a
 * descriptive error if the binary fails to bind the endpoint within
 * `timeoutMs`. The error message includes the latest stderr line
 * so the renderer can paint a useful toast without round-tripping
 * back to the binary.
 */
function waitForReady(proc: ChildProcess, timeoutMs: number): Promise<{ path: string }> {
  return new Promise((resolve, reject) => {
    if (!proc.stdout) {
      reject(new Error("rud1-bridge spawned without stdout"));
      return;
    }
    let lastErrLine = "";
    if (proc.stderr) {
      proc.stderr.on("data", (chunk) => {
        lastErrLine = chunk.toString().split(/\r?\n/).pop() || lastErrLine;
      });
    }
    const rl = readline.createInterface({ input: proc.stdout });
    const timer = setTimeout(() => {
      rl.close();
      reject(new Error(
        `rud1-bridge did not bind endpoint within ${timeoutMs}ms` +
        (lastErrLine ? ` (stderr: ${lastErrLine})` : ""),
      ));
    }, timeoutMs);
    rl.on("line", (line) => {
      const idx = line.indexOf("BRIDGE-READY ");
      if (idx < 0) return;
      try {
        const json = JSON.parse(line.slice(idx + "BRIDGE-READY ".length));
        if (typeof json.path !== "string") {
          throw new Error("ready envelope missing 'path'");
        }
        clearTimeout(timer);
        rl.close();
        resolve({ path: json.path });
      } catch (err) {
        clearTimeout(timer);
        rl.close();
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
    proc.once("exit", (code) => {
      clearTimeout(timer);
      rl.close();
      reject(new Error(
        `rud1-bridge exited before ready (code=${code})` +
        (lastErrLine ? `: ${lastErrLine}` : ""),
      ));
    });
  });
}

/** Test-only hatch — exposes the validators so unit tests can pin
 *  the regex behaviour without spawning a real subprocess. */
export const __test = { assertHost, assertBusId, assertPort };
