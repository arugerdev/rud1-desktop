#!/usr/bin/env python3
"""
Genera los iconos de aplicación a partir de resources/icon.ico.

Salidas:
  resources/icon.ico   — copia tal cual del favicon (Windows EXE + NSIS).
  resources/icon.png   — render a 512x512 PNG con fondo transparente.

NO escribe icon.icns: Pillow no soporta el formato Mac de forma nativa
y añadir una dependencia extra (icnsutil / iconutil) por una build de
macOS que aún no priorizamos no compensa. Cuando llegue el momento se
puede generar a mano con `iconutil` en una macOS o con un servicio
online que acepte el PNG.

Idempotente: ejecutar varias veces produce los mismos bytes.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    sys.stderr.write(
        "ERROR: Pillow no está instalado. Ejecuta:\n"
        "  pip install --user Pillow\n"
    )
    sys.exit(1)

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE = REPO_ROOT / "resources" / "icon.ico"
RESOURCES = REPO_ROOT / "resources"


def main() -> int:
    if not SOURCE.exists():
        sys.stderr.write(f"ERROR: no se encontró el favicon en {SOURCE}\n")
        return 1
    RESOURCES.mkdir(parents=True, exist_ok=True)

    # ── Windows + NSIS installer ────────────────────────────────────────────
    # `electron-builder` para Windows usa el .ico tal cual: el formato
    # contiene varios tamaños (16, 32, 48, 256) que Windows escoge según
    # el contexto (taskbar, bandeja, accesos directos). Copiamos los
    # bytes en lugar de re-empaquetar para no perder esos tamaños.
    dst_ico = RESOURCES / "icon.ico"
    shutil.copyfile(SOURCE, dst_ico)
    print(f"OK  {dst_ico.relative_to(REPO_ROOT)}  ({dst_ico.stat().st_size:,} bytes)")

    # ── Linux ───────────────────────────────────────────────────────────────
    # `electron-builder` exige un PNG explícito para deb/AppImage. Tomamos
    # el frame de mayor resolución del .ico, lo redimensionamos a 512x512
    # (estándar para iconos de escritorio Linux modernos) y lo guardamos
    # en mode RGBA por si el .ico ya viene con canal alfa — sin él el
    # fondo en GNOME y KDE sale negro en vez de transparente.
    with Image.open(SOURCE) as im:
        im = im.convert("RGBA")
        # Si el .ico es menor que 512, lo subimos con LANCZOS para evitar
        # un escalado bilineal feo. Si ya es 256+ generalmente está bien.
        target = 512
        if im.size != (target, target):
            im = im.resize((target, target), Image.Resampling.LANCZOS)
        dst_png = RESOURCES / "icon.png"
        im.save(dst_png, format="PNG", optimize=True)
        print(f"OK  {dst_png.relative_to(REPO_ROOT)}  ({dst_png.stat().st_size:,} bytes)  {target}x{target}")

    print("")
    print("Listo. Recuerda re-ejecutar `npm run dist:win` para que")
    print("electron-builder reempaquete con los iconos nuevos.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
