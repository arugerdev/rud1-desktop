# rud1shim — generic flasher interceptor

A drop-in replacement for a CLI flasher (`avrdude.exe`, `esptool.exe`, …) that
reroutes uploads to a rud1 device's local job-runner so latency-sensitive
programming runs next to the hardware (immune to WAN latency), while leaving all
non-rud1 usage untouched. See `../../rud1-fw/docs/serial-jobrunner/README.md`
for the full architecture and the "no molestar" guarantees.

## Behaviour

1. Loads `rud1shim.json` (next to the exe) — see `rud1shim.example.json`.
2. Finds the COM port in the args. If it is **not** a managed rud1 port (or no
   config / desktop not active) → **passthrough**: exec `<name>-real.exe` with
   the original args, unchanged. Third-party uploads are never disturbed.
3. For a rud1 port: uploads referenced files (any argv token that is a local
   file, incl. avrdude `-U mem:op:FILE:fmt`), rewrites the port token to the
   device's local tty, POSTs the job, relays the flasher log + exit code, then
   re-attaches the usbip port so the serial monitor / next upload find it.

Generic: keys off its own basename, so the same binary works as any flasher
shim. Only per-tool rule so far: avrdude's `-C` host config is dropped (the
device uses its own). Windows COM names are device files, so the port is matched
before file detection.

## Build

    go build -o rud1shim.exe rud1shim.go        # Windows
    GOOS=linux  go build -o rud1shim  rud1shim.go
    GOOS=darwin go build -o rud1shim  rud1shim.go

## Install (done by rud1-desktop at runtime, reversibly)

Rename the IDE's real flasher `avrdude.exe`→`avrdude-real.exe`, copy
`rud1shim.exe`→`avrdude.exe`, drop `rud1shim.json`. Restore on
disconnect/exit/uninstall. In the prototype this was verified against the
Arduino IDE's bundled avrdude (`…/tools/avrdude/8.0.0-arduino1/bin/`).

## Prototype status → productization

Prototype talks directly to the Pi (`pi_url`). Production: the shim should post
to the **local desktop app** (localhost), which maps port→device live and
orchestrates the usbip detach→job→attach — removing the direct Pi URL, the
hard-coded port mapping, and the re-attach retry hack from the shim.
