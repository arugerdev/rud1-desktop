#!/usr/bin/env bash
# Fetches the VirtualHere macOS client into resources/darwin/vhclient-darwin
# so electron-builder bundles it via the `mac` extraResources block.
#
# Upstream only ships the macOS client inside VirtualHereUniversal.dmg
# (a signed + notarised universal app). There is no standalone console
# binary download, so we mount the dmg and copy out the universal Mach-O
# (x86_64 + arm64) from the .app bundle. The binary supports the same
# headless `-n` / `-t "<command>"` interface as the Windows/Linux clients.
#
# Must run on macOS (uses hdiutil). Idempotent: skips when the pinned
# version is already present.
set -euo pipefail

VH_VERSION="5.9.9"
VH_URL="https://www.virtualhere.com/sites/default/files/usbclient/VirtualHereUniversal.dmg"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RES_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/resources/darwin"
OUT_BIN="$RES_DIR/vhclient-darwin"
OUT_VER="$RES_DIR/virtualhere.version"

mkdir -p "$RES_DIR"

if [[ "${1:-}" != "--force" && -f "$OUT_BIN" && -f "$OUT_VER" && "$(cat "$OUT_VER")" == "$VH_VERSION" ]]; then
  echo "VirtualHere macOS client already at $VH_VERSION (use --force to refetch)."
  exit 0
fi

TMP_DMG="$(mktemp -t vhuniversal).dmg"
MNT="$(mktemp -d -t vhmnt)"
cleanup() { hdiutil detach "$MNT" -quiet 2>/dev/null || true; rm -f "$TMP_DMG"; rmdir "$MNT" 2>/dev/null || true; }
trap cleanup EXIT

echo "Downloading VirtualHere macOS client $VH_VERSION ..."
curl -fSL --retry 3 -o "$TMP_DMG" "$VH_URL"

echo "Mounting dmg ..."
hdiutil attach "$TMP_DMG" -nobrowse -readonly -mountpoint "$MNT" >/dev/null

APP_BIN="$(/usr/bin/find "$MNT" -path '*/Contents/MacOS/*' -type f | head -n 1)"
if [[ -z "$APP_BIN" ]]; then
  echo "ERROR: could not locate the app binary inside the dmg." >&2
  exit 1
fi

cp "$APP_BIN" "$OUT_BIN"

# Sanity: must be a Mach-O (universal 0xcafebabe or thin 0xcffaedfe).
if ! /usr/bin/file -b "$OUT_BIN" | grep -qi 'Mach-O'; then
  echo "ERROR: extracted file is not a Mach-O binary." >&2
  exit 1
fi

chmod +x "$OUT_BIN"
printf '%s' "$VH_VERSION" > "$OUT_VER"
echo "VirtualHere macOS client $VH_VERSION bundled at $OUT_BIN."
