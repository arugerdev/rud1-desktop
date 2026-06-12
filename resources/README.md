# Bundled Binaries

Place platform-specific binaries here. They are included in the packaged app
via the per-platform `extraResources` blocks in `package.json` (`win` →
`resources/win32/`, `linux` → `resources/linux/`, `mac` → `resources/darwin/`)
and resolved at runtime by `binary-helper.ts`.

The directory naming matches Node's `process.platform`, NOT electron-builder's
`${os}` substitution variable — picking one and keeping it consistent is what
stops resources from silently going un-bundled.

Binaries ARE committed to git so the GitHub Actions release pipeline can
build for win/linux/mac without network fetches. Populate them locally
with the helper scripts below, then `git add resources/<platform>/` and
push — CI uses the committed copies as-is (the workflow sets
`RUD1_SKIP_FETCH=1` to suppress the fetch chain).

## Required binaries

### Windows (`resources/win32/`)

Run `npm run fetch:openvpn-win` (or invoke `dist:win`, which chains it).
The script downloads the official signed OpenVPN Community MSI, verifies
SHA256 + Authenticode, extracts via `msiexec /a`, and writes the portable
runtime (openvpn.exe + tapctl.exe + runtime DLLs + TAP-Windows V9 driver
files) into `resources/win32/openvpn/`. Idempotent — only re-downloads
on a version bump.

| File | Source |
|------|--------|
| `openvpn/openvpn.exe` | [OpenVPN Community](https://openvpn.net/community-downloads/) — bundled by `scripts/fetch-openvpn-win.ps1` |
| `openvpn/tapctl.exe` | Included with OpenVPN Community — same script |
| `openvpn/*.dll` | OpenSSL + helper DLLs, must sit next to openvpn.exe |
| `openvpn/driver/OemVista.inf` | TAP-Windows V9 INF — installed on first run via tapctl |
| `openvpn/driver/tap0901.cat` | TAP-Windows V9 driver catalog |
| `openvpn/driver/tap0901.sys` | TAP-Windows V9 kernel driver |
| `openvpn/COPYING.OpenVPN.txt` | GPLv2 text, written by the fetch script |
| `openvpn/NOTICE.OpenVPN.txt` | Source/version pointer for GPLv2 compliance |
| `openvpn/openvpn.version` | Pinned version stamp the script reads to skip re-downloads |
| `USBip-installer.exe` | [usbip-win2](https://github.com/vadimgrn/usbip-win2/releases) — bundled by `scripts/fetch-usbip-win.ps1` |
| `com0com-installer.exe` | [com0com](https://sourceforge.net/projects/com0com/) — bundled by `scripts/fetch-com0com-win.ps1` |

### Linux (`resources/linux/`)

Run `npm run fetch:virtualhere-linux` to (re)fetch.

| File | Source |
|------|--------|
| `vhclientx86_64` | [VirtualHere](https://www.virtualhere.com/usb_client_software) console client — single statically-linked ELF, the PRIMARY USB transport. Bundled by `scripts/fetch-virtualhere-linux.sh`. |
| `virtualhere.version` | Pinned version stamp the fetch script reads to skip re-downloads. |

`openvpn` (VPN) and `usbip`/`usbipd` (USB fallback) are NOT bundled on Linux —
they come from the distro package manager. The `.deb` declares them via
`deb.recommends` so `apt install ./rud1.deb` pulls them in; AppImage users
need a system `openvpn` on PATH. `binary-helper.ts` resolves both via PATH.

### macOS (`resources/darwin/`)

Run `npm run fetch:virtualhere-mac` (must run on macOS — uses `hdiutil`).

| File | Source |
|------|--------|
| `vhclient-darwin` | [VirtualHere](https://www.virtualhere.com/usb_client_software) client — universal Mach-O (x86_64 + arm64) extracted from the signed/notarised `VirtualHereUniversal.dmg`. Upstream ships no standalone console binary, so `scripts/fetch-virtualhere-mac.sh` mounts the dmg and copies the `.app` binary out. PRIMARY USB transport. |
| `virtualhere.version` | Pinned version stamp. |

`openvpn` is NOT bundled on macOS — install via `brew install openvpn`;
`binary-helper.ts` resolves it via PATH. `usbip` is a Homebrew/source fallback.

## Notes

- On Linux, VPN operations require `CAP_NET_ADMIN` or running as root.
  The app requests elevated privileges via `pkexec` or `sudo` if needed.
- On Windows, the app is configured as `requireAdministrator` in the manifest
  (set in electron-builder `requestedExecutionLevel`). The TAP-Windows V9
  KERNEL DRIVER also needs a one-time install via `tapctl create --hwid
  root\tap0901`. The first time the user clicks Connect, the desktop fires
  an additional UAC prompt for the driver install, then never asks again.
- The Authenticode signature on `openvpn.exe` is preserved end-to-end — we
  never modify the binary, we just copy it from the MSI's `/a`-extracted
  payload.
