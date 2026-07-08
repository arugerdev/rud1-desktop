# Cross-compiles native/rud1shim into resources/<platform>/ so electron-builder
# bundles it (extraResources -> resources/bin/).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$src  = Join-Path $root "native\rud1shim\rud1shim.go"
$env:CGO_ENABLED = "0"
$targets = @(
  @{ os="windows"; arch="amd64"; out="resources\win32\rud1shim.exe" },
  @{ os="linux";   arch="amd64"; out="resources\linux\rud1shim" },
  @{ os="darwin";  arch="arm64"; out="resources\darwin\rud1shim" }
)
foreach ($t in $targets) {
  $env:GOOS = $t.os; $env:GOARCH = $t.arch
  $out = Join-Path $root $t.out
  go build -ldflags "-s -w" -o $out $src
  Write-Host "built $($t.os)/$($t.arch) -> $($t.out)"
}
