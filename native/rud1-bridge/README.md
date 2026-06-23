# rud1-bridge

Auxiliary cross-platform Go binary that bridges a local serial endpoint
(Windows COM via com0com, or Unix pty) to a TCP socket talking RFC 2217
against the rud1-fw `serbridge` listener on the Pi.

Used by `rud1-desktop` as a subprocess when the operator opens a CDC-class
device (Arduino, ESP32 dev board, USB-serial dongle) through the Connect
tab. Sidesteps the kernel `usbip_host` race that bites on DTR-toggle
resets — the entire reason USB/IP fails for these devices.

## Build

From `rud1-desktop/`:
```
npm run build:bridge
```

Cross-compiles for `win32`, `linux`, `darwin` (x64 + arm64) into
`rud1-desktop/resources/<platform>/`. Pure Go, no cgo, runs on any
machine with `go` on PATH.

## Standalone use (debugging)

```
rud1-bridge --pi-host 10.99.91.243 --pi-port 7700 --local-port COM7 \
            --baud 115200 --data-bits 8 --parity N --stop-bits 1
```

On Unix:
```
rud1-bridge --pi-host 10.99.91.243 --pi-port 7700 \
            --link-path /tmp/rud1-bridge-1-3 --baud 115200
```

The binary prints `BRIDGE-READY <json>` on stdout once the local
endpoint is bound, then JSON event records on stderr. SIGTERM cleans
up. Exit code 0 on clean shutdown, non-zero on any I/O error.

## Why a Go subprocess instead of an in-process Node module

Native Node addons (e.g. `serialport` npm package) require electron-rebuild
against each Electron version, signing on macOS, and routinely trip
antivirus heuristics on Windows. A standalone Go binary cross-compiles
in seconds, has no install-time native build step, and can ship through
the same release pipeline as the rest of rud1-desktop's bundled tools
(OpenVPN + TAP-Windows V9 driver, usbip-win2). See the planning notes in
the repo's main discussion threads for the full trade-off.

## Layout

- `cmd/rud1-bridge/` — CLI entry point.
- `internal/bridge/` — TCP client, RFC 2217 generator/parser, byte pumps.
- `internal/serialport/` — platform-specific endpoint (com0com on Windows,
  pty on Linux/macOS).
