# Bundled Binaries

Place platform-specific binaries here. They are included in the packaged app
via `extraResources` in `package.json` and resolved at runtime by `binary-helper.ts`.

## Required binaries

### Windows (`resources/win32/`)
| File | Source |
|------|--------|
| `wireguard.exe` | [WireGuard for Windows](https://www.wireguard.com/install/) |
| `wg.exe` | Included with WireGuard for Windows |
| `usbip.exe` | [usbip-win2](https://github.com/vadimgrn/usbip-win2/releases) |

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
