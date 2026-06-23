# Migración VirtualHere → com0com + rud1-bridge (RFC 2217)

> Rama: `feat/serial-com0com-migration` (en rud1-desktop, rud1-fw, rud1-es).
> Base: `master` de cada repo. **No se toca master** — todo se integra y prueba
> en esta rama antes de cualquier release. develop está muerto (cientos de
> commits por detrás de master), no se usa.

## 1. Por qué

VirtualHere reenvía USB en crudo. Sobre el enlace celular, el jitter
desincroniza el pulso DTR/RESET del bootloader del Arduino: el reset llega
estirado/tarde y los bytes de sync del STK500 caen fuera de la ventana de
~1 s de optiboot → "a veces programa, a veces no". A 115200 además satura el
búfer del chip serie.

La arquitectura RFC 2217 lo resuelve: el pulso de reset se genera **local en
el Pi** (UART real), y por la red solo cruzan el flujo de bytes (bufferizado,
tolera latencia) y el comando de control de línea. avrdude reintenta el sync,
así que la latencia del trigger se absorbe.

## 2. Esto NO se construye de cero — se revive

La arquitectura completa existió y se eliminó al migrar a VirtualHere. Revivir
desde el historial es la vía correcta; reescribir es desperdiciar trabajo ya
probado.

Commits de eliminación a revertir/cherry-pick como punto de partida:

| Repo         | Commit    | Asunto |
|--------------|-----------|--------|
| rud1-fw      | `24859f2` | refactor(usb): elimina serial-bridge, instala VirtualHere server |
| rud1-desktop | `2ef5f0e` | refactor(usb): elimina com0com + serial-bridge, integra cliente VirtualHere |
| rud1-es      | (cadena VirtualHere desde `03b5541` en adelante) sustituye la UI com0com |

Piezas com0com previas a recuperar (rud1-desktop):
- `7648169` serial bridge manager para CDC
- `7bec560` execFileAsync en serial-bridge-manager
- `7c0f4e6` lee ComDB + pickFreePair (salta pares reservados)
- `27baca2` Com0comPairNoEmuBRError + EmuBR option

Piezas com0com previas a recuperar (rud1-es):
- `db79795` instalación com0com + UI del puente USB
- `7d2a5e4` opciones de configuración de pares COM
- `034f221` soporte de pares sin EmuBR
- `17a75c9` botón Reset en sesiones serial-bridge en vivo
- `92c6b47` banner com0com que refresca tras instalar driver
- `4185e75` kill-switch del modo serial-bridge

**rud1-bridge ya está completo en `master`** (no se llegó a borrar): el puente
Go (`cmd/rud1-bridge`, `internal/bridge`, `internal/serialport`) implementa el
dialecto RFC 2217 cliente, abre el lado B de com0com en Windows y reenvía
DTR/RTS por SET-CONTROL. Es el componente clave y ya está listo.

> ⚠️ rud1-bridge NO tiene `.git` en el árbol local. Es módulo Go
> (`github.com/rud1-es/rud1-bridge`). Antes de tocarlo hay que clonar su repo
> real o confirmar cómo se versiona/empaqueta el binario en el build del
> desktop. **Bloqueante menor — resolver al inicio de la fase D.**

## 3. Arquitectura objetivo

```
Arduino USB ──► Pi (/dev/ttyUSB0)
                  │  ser2net (RFC 2217 server)  ── reset/baud LOCAL en el Pi
                  ▼
            TCP RFC 2217  ── solo bytes + SET-CONTROL cruzan la VPN
                  ▼
  Windows: rud1-bridge (cliente RFC 2217) ──► com0com par CNCAx/CNCBx
                                                   ▼
                                          COM virtual ──► Arduino IDE / avrdude
```

- **Pi**: `ser2net` expone `/dev/ttyUSB0` como puerto RFC 2217. (Alternativa a
  evaluar: el servidor RFC 2217 propio que tenía rud1-fw antes de `24859f2` —
  decidir ser2net vs. servidor propio en fase A).
- **Windows**: `rud1-bridge` (ya existe) dialoga RFC 2217 con el Pi y vuelca al
  lado B de com0com; el IDE ve el lado A como COM normal.
- com0com solo aporta el **par de puertos virtuales** (driver kernel). Es la
  única pieza que necesita driver firmado → ver §4.

## 4. Driver firmado (requisito crítico)

Objetivo: el instalador descarga el driver, lo instala y lo gestiona **solo**,
sin que el usuario haga prácticamente nada, y el driver es **100% firmado y
verificado**.

Realidad de la firma de com0com (jun-2026):
- **3.0.0.0** oficial (SourceForge): cert **SHA-1 antiguo**; en Win11 con
  HVCI/Driver Signature Enforcement puede dar **Error Code 52** (no carga).
- **2.2.2.0 x64 signed** (SourceForge): instala en Win10/11 al día, pero viejo
  y con menos features.
- **com0com.com "2026 signed patch"**: sitio de terceros, NO el proyecto
  oficial. Re-empaquetador desconocido → **descartado para "100% comprobado"**.

### Opciones (DECISIÓN PENDIENTE DEL USUARIO)

- **A. Pinear build oficial de SourceForge** (2.2.2.0 ó 3.0.0.0), fijar SHA256,
  verificar Authenticode + signer. Coste 0. Riesgo: HVCI/Code 52 en el Win11
  más nuevo → hay que **verificar en la máquina Win10 real de pruebas**.
- **B. Re-firmar com0com nosotros** vía Microsoft Hardware Dev Portal
  (attestation signing). Requiere cert EV (~200-400 €/año) + cuenta de dev.
  Resultado: driver moderno, HVCI-safe, bajo nuestro control → **única vía que
  garantiza "100% firmado" en Windows actual con Secure Boot**.
- **C. Driver VSP comercial firmado** (HW VSP3 de HW Group habla RFC 2217
  nativo → ahorraría com2tcp; o un VSP comercial). Cierra el "100% firmado"
  pero añade licencia/dependencia de terceros y cambia la arquitectura.

**DECISIÓN (2026-06-22): opción A — com0com 2.2.2.0 x64 signed (oficial).**

Verificado a mano sobre los tres paquetes de SourceForge:

| build   | com0com.cat | com0com.sys | setup.exe | cert firma |
|---------|-------------|-------------|-----------|------------|
| 2.2.2.0 | Valid (Hatchett) | catálogo | NotSigned | ~2010, **pre-2015** |
| 3.0.0.0 | Valid (CyberCircuits) | Valid | Valid | 2017, **post-2015** |

Aunque el 3.0.0.0 parece "más firmado", **es el que da Error Code 52**: Win10
1607+/Win11 con Secure Boot solo aceptan drivers cross-signed **antes del
29-jul-2015** (grandfather); los posteriores exigen attestation de Microsoft.
El driver del 2.2.2.0 (Hatchett, ~2010) entra en el grandfather → **carga**; el
del 3.0.0.0 (2017) → rechazado. Por eso 2.2.2.0 es el correcto.

El `setup.exe` exterior del 2.2.2.0 NO está firmado, pero **no importa**: lo
lanza nuestro proceso elevado (`requireAdministrator`) con `/S`; al no tener
Mark-of-the-Web ni doble clic del usuario, no dispara SmartScreen. Lo que el
kernel valida es el driver, firmado por catálogo (com0com.cat = Valid).

**Estado**: instalador vendorizado en `resources/win32/com0com/` (como vhui64
/ USBip-installer, cf. `9058b63`). SHA256 pineado
`64CF92E5B56F94C1CA14BBBBDCF0CB38B866241C6400E67B5E41C58DAEC39C12` y verificado
por `scripts/fetch-com0com-win.ps1` (fail-closed + chequeo del com0com.cat).

**Riesgo aceptado**: validar carga del driver en Win10 **y** Win11 (incl. 24H2)
en Fase F. Si un Win11 muy reciente lo rechaza pese al grandfather, reabrir
opción B (re-firma propia con attestation). GPL: com0com es GPL; el código
fuente (paquete `com0com-2.2.2.0`) queda disponible para cumplir la oferta.

### Contrato de instalación automática (independiente de la opción)

1. **Build-time**: el instalador firmado está vendorizado en
   `resources/win32/com0com/`; `scripts/fetch-com0com-win.ps1` lo **verifica**
   (SHA256 pineado + com0com.cat = Valid) y **falla en cerrado**. Se empaqueta
   vía electron-builder `extraResources` (igual que VirtualHere/usbip hoy).
2. **Runtime** (proceso main del desktop, ya es `requireAdministrator`):
   - Detecta si com0com está instalado (driver `com0com` + ComDB en registro).
   - Si no: `com0com-2.2.2.0-x64-fre-signed.exe /S` (NSIS silencioso) → instala
     en `C:\Program Files (x86)\com0com\` con `setupc.exe`/`setupg.exe`. Sin UI.
   - Crea/lee el par CNCAx↔CNCBx libre vía `setupc.exe` (revivir `pickFreePair`
     de `7c0f4e6`; manejar el caso sin EmuBR de `27baca2`).
   - Idempotente: si ya está, no reinstala; si el par cambió, lo reconcilia.
   - Sin UAC adicional (la app ya corre elevada) ni SmartScreen (lo lanzamos
     nosotros, sin MOTW).

## 5. Plan de fases

- **Fase A — Pi/ser2net**: decidir ser2net vs servidor RFC 2217 propio; revivir
  el endpoint del Pi; API `/api/serial-bridge/sessions/{busId}` (revertir parte
  de `24859f2`). Empaquetar en install.sh.
- **Fase B — Driver**: implementar §4 (opción A primero). fetch+verify script
  (ya scaffolded) + instalador runtime silencioso.
- **Fase C — Desktop**: revivir serial-bridge-manager + com0com-manager; lanzar
  rud1-bridge como subproceso; parsear `BRIDGE-READY`; mapear errores.
- **Fase D — rud1-bridge**: resolver el tema del `.git`/empaquetado; confirmar
  build del binario en CI del desktop.
- **Fase E — UI (rud1-es)**: revivir UsbSection serial (banner instalación,
  botón Reset, kill-switch). Strings i18n en los 11 idiomas.
- **Fase F — Pruebas**: con Arduino Uno real sobre la VPN celular; verificar
  reset/sync de bootloader y subida a 115200 sin pérdidas; verificar el driver
  firmado carga en Win10 y Win11 (Code 52).

## 5bis. Estado de implementación (2026-06-22)

- **Fase A (rud1-fw) — HECHA y verificada.** serbridge revivido desde
  `24859f2^` (rfc2217.go server, bridge_linux, termios) + handler
  `serial_bridge.go` + API `/api/serial-bridge/{status,sessions,sessions/{busId},open,reset}`.
  Re-wireado config.go (SerialBridgeConfig + Default 7700/8), agent.go
  (manager Start + handler + heartbeat), server.go, cloud/client.go (HBUSB
  fields), setup_test.go, install.sh (bloque `serial_bridge:`). VirtualHere
  server se mantiene como fallback. Build host + linux/arm64 OK, vet OK,
  gofmt OK, tests OK.
- **Fase D (rud1-bridge + packaging) — HECHA y verificada.** Vendorizado en
  `native/rud1-bridge`; build-rud1-bridge.ps1 compila 4 binarios; wireado en
  package.json + build-win.ps1; com0com 2.2.2.0 verificado.
- **Fase C (managers desktop) — HECHA y verificada.** serial-bridge-manager.ts
  + com0com-detector.ts revividos; **auto-instalación silenciosa** añadida
  (`ensureCom0comReady` → `setup.exe /S` + `setupc install` con alias+EmuBR);
  binary-helper (rud1BridgePath + com0comInstallerPath), IPC `serial:*` y
  preload re-wireados JUNTO a VirtualHere; cierre de sesiones en quit. tsc OK,
  834 tests OK.
- **Fase E (rud1-es) — PARCIAL.**
  - HECHO: el backend ya ingiere los campos `serialBridge*` del heartbeat
    (schema zod intacto; migración `usb_class_serial_bridge` no se revirtió).
    Contrato de tipos `window.electronAPI.serial` añadido al connect-panel.
    typecheck OK.
  - PENDIENTE (gated por laboratorio): la **sección visual** del connect-panel
    que enruta los dispositivos CDC/serie por `electronAPI.serial.open()` en
    vez de `virtualhere.use()`, con banner de auto-instalación com0com, botón
    Reset (`serial.reset`) y CTA de fallback (`serial.launchInstaller`).
    Localización: `connect-panel.tsx` — hoy los serie se pintan en la sección
    VirtualHere (`handleVhAttach`, ~L1134) y se filtran con
    `classifyUsb(d) === "serial"` (~L1231). Se deja sin reescribir a ciegas
    porque es la única pieza puramente visual y sin hardware/render no se puede
    garantizar "a la primera"; hacerlo a ciegas arriesga la UI de producción.
    Hacer con la Pi/Arduino del lab: + strings i18n en los 11 idiomas.

## 6. Coexistencia con VirtualHere

VirtualHere se queda como **fallback** durante la transición (patrón actual
VirtualHere-primario/usbip-fallback pasa a serial-bridge-primario/VirtualHere-
fallback para dispositivos CDC/serie). No borrar VirtualHere hasta validar
Fase F en producción.
