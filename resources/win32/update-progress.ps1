# =============================================================================
# rud1-desktop — ventana de progreso de la actualización silenciosa.
#
# rud1 la lanza justo antes de arrancar el setup en silencio y de cerrarse a sí
# mismo, así que esta ventana es lo único que ve el usuario mientras Windows
# reemplaza los ficheros. Además es quien vuelve a abrir rud1 al terminar: se
# hereda el token del rud1 que la lanzó, así que la app vuelve sin que Windows
# pida permiso otra vez (el --force-run del instalador sí lo pide).
#
# Los textos y las rutas llegan en un fichero (-ConfigFile, UTF-8, clave=valor)
# y no por línea de comandos: así ni los acentos ni los símbolos dependen de
# cómo cmd parsee los argumentos.
#
# Se ejecuta desde una copia en C:\ProgramData\rud1 (el setup está
# sobrescribiendo resources\bin) y nunca escribe nada: si algo falla, se cierra
# sin ruido y la actualización sigue igual.
#
# Cierre:
#   - el centinela desaparece            → el rud1 nuevo ya arrancó (normal)
#   - el setup acabó y rud1 no vuelve    → lo abre ella y espera un rato
#   - tope de tiempo                     → nunca se queda colgada
# =============================================================================
param(
  [string] $ConfigFile = '',
  [string] $Sentinel   = '',
  [int]    $WatchPid   = 0,
  # Margen tras acabar el setup antes de abrir rud1 nosotros.
  [int]    $RelaunchAfterSec = 3,
  # Cuánto se espera a que el rud1 nuevo borre el centinela.
  [int]    $PostLaunchSec    = 45,
  [int]    $TimeoutSec       = 900
)

$ErrorActionPreference = 'Stop'

$cfg = @{
  title    = 'Instalando la actualizacion de rud1'
  body     = 'rud1 se cerrara y volvera a abrirse solo cuando termine.'
  hint     = ''
  elapsed  = 'Transcurrido'
  theme    = 'dark'
  relaunch = ''
  pidfile  = ''
  center   = ''
}

if ($ConfigFile -and (Test-Path -LiteralPath $ConfigFile)) {
  try {
    foreach ($line in (Get-Content -LiteralPath $ConfigFile -Encoding UTF8)) {
      $i = $line.IndexOf('=')
      if ($i -lt 1) { continue }
      $key = $line.Substring(0, $i).Trim().ToLowerInvariant()
      $val = $line.Substring($i + 1)
      if ($key -eq 'sentinel') { if (-not $Sentinel) { $Sentinel = $val } }
      elseif ($cfg.ContainsKey($key)) { $cfg[$key] = $val }
    }
  } catch {
    # Config ilegible: seguimos con los textos por defecto.
  }
}

try {
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Rud1Win {
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
}
'@
} catch {
  exit 0
}

# Paleta Liquid Glass de rud1 (pastel + azul claro de acento).
if ($cfg.theme -eq 'light') {
  $card   = [System.Drawing.Color]::FromArgb(255, 255, 255)
  $fg     = [System.Drawing.Color]::FromArgb(26, 32, 48)
  $muted  = [System.Drawing.Color]::FromArgb(107, 117, 136)
  $accent = [System.Drawing.Color]::FromArgb(134, 168, 255)
  $edge   = [System.Drawing.Color]::FromArgb(200, 212, 232)
} else {
  $card   = [System.Drawing.Color]::FromArgb(22, 28, 40)
  $fg     = [System.Drawing.Color]::FromArgb(230, 234, 242)
  $muted  = [System.Drawing.Color]::FromArgb(147, 160, 184)
  $accent = [System.Drawing.Color]::FromArgb(168, 196, 255)
  $edge   = [System.Drawing.Color]::FromArgb(48, 60, 82)
}

$form                 = New-Object System.Windows.Forms.Form
$form.Text            = 'rud1'
$form.FormBorderStyle = 'None'
$form.Size            = New-Object System.Drawing.Size(520, 192)
$form.BackColor       = $card
$form.TopMost         = $true
$form.ShowInTaskbar   = $true
$form.ControlBox      = $false

# Se coloca donde estaba la ventana de rud1 que acaba de cerrarse; si no nos
# la dicen, en la pantalla donde está el ratón. CenterScreen la mandaría a un
# monitor que el usuario no está mirando.
$form.StartPosition = 'Manual'
$anchor = $null
if ($cfg.center -match '^\s*(-?\d+)\s*,\s*(-?\d+)\s*$') {
  $anchor = New-Object System.Drawing.Point([int] $Matches[1], [int] $Matches[2])
}
try {
  if ($null -ne $anchor) {
    $screen = [System.Windows.Forms.Screen]::FromPoint($anchor)
  } else {
    $screen = [System.Windows.Forms.Screen]::FromPoint([System.Windows.Forms.Cursor]::Position)
  }
} catch {
  $screen = [System.Windows.Forms.Screen]::PrimaryScreen
}
$area = $screen.WorkingArea
if ($null -ne $anchor) {
  $x = $anchor.X - [int]($form.Width / 2)
  $y = $anchor.Y - [int]($form.Height / 2)
  # Sin salirse de la pantalla, que es fácil si la ventana estaba en un borde.
  $x = [Math]::Max($area.X, [Math]::Min($x, $area.X + $area.Width - $form.Width))
  $y = [Math]::Max($area.Y, [Math]::Min($y, $area.Y + $area.Height - $form.Height))
} else {
  $x = $area.X + [int](($area.Width - $form.Width) / 2)
  $y = $area.Y + [int](($area.Height - $form.Height) / 2)
}
$form.Location = New-Object System.Drawing.Point($x, $y)

# Borde de 1px: sin marco, la tarjeta se perdería sobre un fondo claro.
$form.add_Paint({
  param($sender, $e)
  $pen = New-Object System.Drawing.Pen($edge, 1)
  $r = $sender.ClientRectangle
  $e.Graphics.DrawRectangle($pen, 0, 0, $r.Width - 1, $r.Height - 1)
  $pen.Dispose()
})

# Franja de acento superior.
$stripe           = New-Object System.Windows.Forms.Panel
$stripe.BackColor = $accent
$stripe.Location  = New-Object System.Drawing.Point(0, 0)
$stripe.Size      = New-Object System.Drawing.Size(520, 4)
$form.Controls.Add($stripe)

$titleLabel           = New-Object System.Windows.Forms.Label
$titleLabel.Text      = $cfg.title
$titleLabel.ForeColor = $fg
$titleLabel.Font      = New-Object System.Drawing.Font('Segoe UI Semibold', 13)
$titleLabel.Location  = New-Object System.Drawing.Point(32, 28)
$titleLabel.Size      = New-Object System.Drawing.Size(456, 28)
$form.Controls.Add($titleLabel)

$bodyLabel           = New-Object System.Windows.Forms.Label
$bodyLabel.Text      = $cfg.body
$bodyLabel.ForeColor = $muted
$bodyLabel.Font      = New-Object System.Drawing.Font('Segoe UI', 9.5)
$bodyLabel.Location  = New-Object System.Drawing.Point(32, 58)
$bodyLabel.Size      = New-Object System.Drawing.Size(456, 36)
$form.Controls.Add($bodyLabel)

# Barra propia en vez de la ProgressBar del sistema: así lleva el azul de
# rud1 y se ve moverse siempre (la marquee nativa depende del tema de Windows).
$track           = New-Object System.Windows.Forms.Panel
$track.BackColor = $edge
$track.Location  = New-Object System.Drawing.Point(32, 100)
$track.Size      = New-Object System.Drawing.Size(456, 6)
$form.Controls.Add($track)

$fill           = New-Object System.Windows.Forms.Panel
$fill.BackColor = $accent
$fill.Location  = New-Object System.Drawing.Point(-160, 0)
$fill.Size      = New-Object System.Drawing.Size(160, 6)
$track.Controls.Add($fill)

$timeLabel           = New-Object System.Windows.Forms.Label
$timeLabel.ForeColor = $muted
$timeLabel.Font      = New-Object System.Drawing.Font('Segoe UI', 8.5)
$timeLabel.Location  = New-Object System.Drawing.Point(32, 116)
$timeLabel.Size      = New-Object System.Drawing.Size(456, 18)
$timeLabel.Text      = "$($cfg.elapsed) 00:00"
$form.Controls.Add($timeLabel)

if ($cfg.hint -and $cfg.hint.Trim().Length -gt 0) {
  $hintLabel           = New-Object System.Windows.Forms.Label
  $hintLabel.Text      = $cfg.hint
  $hintLabel.ForeColor = $muted
  $hintLabel.Font      = New-Object System.Drawing.Font('Segoe UI', 8.5)
  $hintLabel.Location  = New-Object System.Drawing.Point(32, 142)
  $hintLabel.Size      = New-Object System.Drawing.Size(456, 34)
  $form.Controls.Add($hintLabel)
}

# Todo lo que use el temporizador va en ámbito $script:: dentro del manejador
# los parámetros no se ven y una asignación normal se perdería en cada tick.
$script:startedAt       = Get-Date
$script:installerGone   = $null
$script:relaunchedAt    = $null
$script:sentinelPath    = $Sentinel
$script:elapsedText     = $cfg.elapsed
$script:relaunchExe     = $cfg.relaunch
$script:pidFile         = $cfg.pidfile
$script:watchPid        = $WatchPid
$script:relaunchAfter   = $RelaunchAfterSec
$script:postLaunchSec   = $PostLaunchSec
$script:timeoutSec      = $TimeoutSec
$script:timeLabel       = $timeLabel
$script:form            = $form
$script:fill            = $fill
$script:trackWidth      = $track.Width
$script:fillX           = -160

# El pid del setup llega por fichero: la ventana se abre ANTES de arrancarlo
# para que no haya ni un instante sin nada en pantalla.
function Get-InstallerPid {
  if ($script:watchPid -gt 0) { return $script:watchPid }
  if (-not $script:pidFile) { return 0 }
  try {
    if (Test-Path -LiteralPath $script:pidFile) {
      $raw = (Get-Content -LiteralPath $script:pidFile -Raw).Trim()
      $n = 0
      if ([int]::TryParse($raw, [ref] $n) -and $n -gt 0) {
        $script:watchPid = $n
        return $n
      }
    }
  } catch { }
  return 0
}

function Close-Splash {
  $script:timer.Stop()
  $script:form.Close()
}

$script:timer          = New-Object System.Windows.Forms.Timer
$script:timer.Interval = 500
$script:timer.add_Tick({
  $now     = Get-Date
  $elapsed = $now - $script:startedAt
  $script:timeLabel.Text = "{0} {1:00}:{2:00}" -f $script:elapsedText, [int] $elapsed.TotalMinutes, $elapsed.Seconds

  # Caso normal: el rud1 nuevo ya arrancó y borró el centinela.
  if ($script:sentinelPath -and -not (Test-Path -LiteralPath $script:sentinelPath)) {
    Close-Splash
    return
  }

  if ($elapsed.TotalSeconds -ge $script:timeoutSec) {
    Close-Splash
    return
  }

  $ipid = Get-InstallerPid
  if ($ipid -le 0) {
    # Aún no sabemos el pid del setup; si no llega nunca, cierra el centinela
    # (lo borra rud1 al fallar el arranque) o el tope de tiempo.
    return
  }

  if ($null -eq $script:installerGone) {
    $alive = $null
    try { $alive = Get-Process -Id $ipid -ErrorAction SilentlyContinue } catch { $alive = $null }
    if ($null -eq $alive) { $script:installerGone = $now }
    return
  }

  # El setup ya terminó. Si rud1 no ha vuelto por su cuenta, lo abrimos: como
  # heredamos el token del rud1 que nos lanzó, no hay aviso de permisos.
  if ($null -eq $script:relaunchedAt) {
    if (($now - $script:installerGone).TotalSeconds -lt $script:relaunchAfter) { return }
    $script:relaunchedAt = $now
    if ($script:relaunchExe -and (Test-Path -LiteralPath $script:relaunchExe)) {
      try {
        Start-Process -FilePath $script:relaunchExe | Out-Null
      } catch {
        # Si no arranca, el usuario lo abrirá a mano; nada más que hacer.
      }
    }
    return
  }

  # Ya lo hemos abierto: se espera a que borre el centinela y, si no, fuera.
  if (($now - $script:relaunchedAt).TotalSeconds -ge $script:postLaunchSec) {
    Close-Splash
  }
})

# Deslizamiento a velocidad constante: 6 px cada 33 ms.
$script:anim          = New-Object System.Windows.Forms.Timer
$script:anim.Interval = 33
$script:anim.add_Tick({
  $script:fillX += 6
  if ($script:fillX -gt $script:trackWidth) { $script:fillX = -160 }
  $script:fill.Left = $script:fillX
})

$form.add_Shown({
  # SW_SHOW explícito: al lanzarse con la consola oculta, Windows puede
  # aplicar ese estado a la primera ventana del proceso.
  [void] [Rud1Win]::ShowWindow($script:form.Handle, 5)
  [void] [Rud1Win]::SetForegroundWindow($script:form.Handle)
  $script:form.Activate()
  $script:timer.Start()
  $script:anim.Start()
})

try {
  [void] $form.ShowDialog()
} catch {
  exit 0
} finally {
  try { $script:timer.Stop() } catch { }
  try { $script:timer.Dispose() } catch { }
  try { $script:anim.Stop() } catch { }
  try { $script:anim.Dispose() } catch { }
  try { $form.Dispose() } catch { }
}
exit 0
