# Bundled Binaries

Place platform-specific binaries here. They are included in the packaged app
via the per-platform `extraResources` blocks in `package.json` (`win` →
`resources/win32/`, `linux` → `resources/linux/`, `mac` → `resources/darwin/`)
and resolved at runtime by `binary-helper.ts`.

The directory naming matches Node's `process.platform`, NOT electron-builder's
`${os}` substitution variable — picking one and keeping it consistent is what
stops resources from silently going un-bundled.

Binaries are NOT committed to git. Run the per-platform fetch scripts to
populate this tree (the `dist:<os>` npm scripts chain them automatically).

## Required binaries

### Windows (`resources/win32/`)

Run `npm run fetch:wg-win` (or invoke `dist:win`, which chains it). The
script downloads the official signed WireGuard for Windows MSI, verifies
SHA256 + Authenticode, extracts via `msiexec /a`, and writes the binaries
plus GPLv2 compliance artefacts. Idempotent — only re-downloads on a
version bump.

| File | Source |
|------|--------|
| `wireguard.exe` | [WireGuard for Windows](https://download.wireguard.com/windows-client/) — bundled by `scripts/fetch-wireguard-win.ps1` |
| `wg.exe` | Included with WireGuard for Windows — same script |
| `COPYING.WireGuard.txt` | GPLv2 text, written by the same script |
| `NOTICE.WireGuard.txt` | Source/version pointer for GPLv2 compliance |
| `wireguard.version` | Pinned version stamp the script reads to skip re-downloads |
| `usbip.exe` | [usbip-win2](https://github.com/vadimgrn/usbip-win2/releases) — fetch manually for now |

### Linux (`resources/linux/`)
| File | Source |
|------|--------|
| `wg` | `apt install wireguard-tools` |
| `wg-quick` | `apt install wireguard-tools` |
| `usbip` | `apt install linux-tools-common linux-tools-generic` |

### macOS (`resources/darwin/`)
| File | Source |
|------|--------|
| `wg` | `brew install wireguard-tools` |
| `wg-quick` | `brew install wireguard-tools` |
| `wireguard-go` | `brew install wireguard-go` |

## Notes

- On Linux, VPN operations require `CAP_NET_ADMIN` or running as root.
  The app requests elevated privileges via `pkexec` or `sudo` if needed.
- On Windows, the app is configured as `requireAdministrator` in the manifest
  (set in electron-builder `requestedExecutionLevel`).
- Binaries are not committed to git. Download them from their official sources
  and place them in the appropriate directory before building the app.
