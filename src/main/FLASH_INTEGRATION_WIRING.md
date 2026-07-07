# Flasher shim — desktop wiring guide

The modules are complete and typecheck: `binary-helper.ts` (`rud1shimPath`),
`ide-detector.ts`, `shim-lifecycle-manager.ts`, `shim-orchestrator.ts`,
`flash-integration.ts`. The shim binary is bundled in `resources/<platform>/`.

Three small wiring steps remain in the app (they need the running app + real
hardware to verify, so they're left explicit rather than done blind):

## 1. Track the COM port on the session (usb-session-state.ts)

Add `comPort?: string` to `AttachedUsbSession`:

```ts
export interface AttachedUsbSession {
  host: string;
  busId: string;
  label?: string;
  port?: number;      // vhci port
  comPort?: string;   // Windows COM assigned by the attach (for flasher shim)
  attachedAt: string;
}
```

## 2. Init + attach/detach/quit hooks (index.ts)

At `app.whenReady()` init (near the other managers, ~line 1100):

```ts
import { initFlashIntegration, listComPorts, captureComPort } from "./flash-integration";
import { usbAttach, usbDetach } from "./usb-manager";

const flash = initFlashIntegration({
  detach: (vhciPort) => usbDetach(vhciPort),
  attach: (host, busId) => usbAttach(host, busId).then(() => undefined),
});
```

Where the app performs a usbip attach (the IPC handler that calls `usbAttach`),
bracket it to capture the COM and register the device:

```ts
const before = await listComPorts();
const vhciPort = await usbAttach(host, busId);
const comPort = await captureComPort(before);
if (comPort) flash.registerDevice(comPort, { host, busId, vhciPort });
// also persist comPort on the session via recordAttach({ ..., comPort })
```

On detach (`recordDetachByBusId` / `recordDetachByPort`):

```ts
flash.unregisterByBusId(busId);
```

In the `before-quit` handler (~line 1320), after `usbDetachAll()`:

```ts
flash.shutdown();   // restores every wrapped flasher + stops the orchestrator
```

On `onVpnConnected` reattach of stored sessions, re-register each session's
`comPort` (or re-capture) so the shim map matches reality after a reconnect.

## 3. Bundle check

`resources/win32/rud1shim.exe` (+ linux/darwin) are built by
`scripts/build-rud1shim.ps1` and bundled via the existing `extraResources`
(`resources/<platform>` → `bin/`). Add a build step to CI next to
`build-rud1-bridge`.

## How it behaves once wired

- On rud1 serial-device attach: `flash.registerDevice` adds `COMx→busId`, and
  `ShimManager.syncPorts` wraps any detected IDE flasher (Arduino IDE,
  PlatformIO, …) with the shim and writes a config listing the live ports.
- User uploads from their own IDE unchanged → the IDE's avrdude/esptool is our
  shim → it POSTs the job to `127.0.0.1:25341/flash` → the orchestrator detaches
  the COM, calls the device's `POST :7070/api/flash` (runs the real flasher on
  the Pi, ~0 ms), re-attaches the COM, returns the log. Latency-immune.
- Upload to any non-rud1 board, or with the desktop closed → the shim passes
  through to the real flasher, untouched ("no molestar").
- On detach / quit: shims restored, orchestrator stopped.

## Verified so far (prototype, over the production VPN)

Real Arduino IDE upload routed to the device job-runner: write+verify 100%,
rc=0, ~1.5 s, back-to-back repeatable, independent of the ~110 ms VPN RTT.
Passthrough confirmed for non-registered ports. The fw Go handler
(`rud1-fw` `POST /api/flash`) compiles into the agent; it ships on the next
`installOnPI`. Until then the durable prototype runner (`rud1-jobrunner`
systemd service on the device, port 8090) provides the same endpoint.
