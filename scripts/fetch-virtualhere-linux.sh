#!/usr/bin/env bash
# Fetches the VirtualHere Linux console client into resources/linux/ so
# electron-builder bundles it via the `linux` extraResources block.
#
# The x86_64 console client is a single, statically-linked ELF binary
# (no shared-library deps), so it runs as-is on any glibc/musl desktop.
# It is the PRIMARY USB transport on Linux (usbip is only a fallback and
# is expected from the distro package manager). Idempotent: skips when the
# pinned version is already present.
set -euo pipefail

VH_VERSION="5.9.9"
VH_URL="https://www.virtualhere.com/sites/default/files/usbclient/vhclientx86_64"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RES_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/resources/linux"
OUT_BIN="$RES_DIR/vhclientx86_64"
OUT_VER="$RES_DIR/virtualhere.version"

mkdir -p "$RES_DIR"

if [[ "${1:-}" != "--force" && -f "$OUT_BIN" && -f "$OUT_VER" && "$(cat "$OUT_VER")" == "$VH_VERSION" ]]; then
  echo "VirtualHere Linux client already at $VH_VERSION (use --force to refetch)."
  exit 0
fi

echo "Downloading VirtualHere Linux client $VH_VERSION ..."
curl -fSL --retry 3 -o "$OUT_BIN" "$VH_URL"

# Sanity: must be an ELF executable, not an HTML error page.
if ! head -c 4 "$OUT_BIN" | grep -q $'\x7fELF'; then
  echo "ERROR: downloaded file is not an ELF binary." >&2
  exit 1
fi

chmod +x "$OUT_BIN"
printf '%s' "$VH_VERSION" > "$OUT_VER"
echo "VirtualHere Linux client $VH_VERSION bundled at $OUT_BIN."
