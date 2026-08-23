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

### Linux (`resources/linux/`)

`openvpn` (VPN) and `usbip`/`usbipd` (USB transport) are NOT bundled on Linux —
they come from the distro package manager. The `.deb` declares them via
`deb.recommends` so `apt install ./rud1.deb` pulls them in; AppImage users
need a system `openvpn` on PATH. `binary-helper.ts` resolves both via PATH.

### macOS (`resources/darwin/`)

`openvpn` is NOT bundled on macOS — install via `brew install openvpn`;
`binary-helper.ts` resolves it via PATH. `usbip` is a Homebrew/source fallback.

## App icons

| File | Used by | Source in the brand kit |
|------|---------|-------------------------|
| `icon.ico` | Windows EXE + NSIS installer (`win.icon`) | `03-iconos/app-escritorio/rud1-windows.ico` |
| `icon.png` | Linux deb/AppImage (`linux.icon`), 512×512 | `03-iconos/app-escritorio/rud1.iconset/icon_512x512.png` |
| `rud1.iconset/` | macOS, to build the `.icns` | `03-iconos/app-escritorio/rud1.iconset/` |
| `tray/tray-*.png` | System tray (`src/main/tray.ts`) | derived from `icon.png` — see below |

These are committed to git and the build uses them as-is. Nothing is generated
at build time, so an operator without Python or an image toolchain still gets
the right icons.

**To refresh them after a logo change**, copy the two files from the brand kit
and re-derive the tray icons:

```bash
cp brand/03-iconos/app-escritorio/rud1-windows.ico                   resources/icon.ico
cp brand/03-iconos/app-escritorio/rud1.iconset/icon_512x512.png      resources/icon.png
cp -r brand/03-iconos/app-escritorio/rud1.iconset                    resources/
npm run icons:tray
```

`npm run icons:tray` reads `resources/icon.png` and writes the four tray PNGs
(16/32 px, normal and with the amber "attention" badge). It has no
dependencies — it decodes and encodes PNG with `node:zlib` — and it is
deterministic, so re-running it produces byte-identical files.

macOS needs an `.icns`, which can only be built on a Mac:

```bash
iconutil -c icns resources/rud1.iconset -o build/icon.icns
```

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
