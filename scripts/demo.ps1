$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
  $env:KDBX_PASSWORD = "K@g=UB#*2_84Z._FUO>|"
  $database = "examples/demo.kdbx"

  Write-Host "== info =="
  moon run cmd/kdbx -- info $database
  if ($LASTEXITCODE -ne 0) { throw "info failed" }

  Write-Host "`n== audit (Markdown) =="
  moon run cmd/kdbx -- audit $database
  if ($LASTEXITCODE -ne 0) { throw "audit failed" }

  Write-Host "`n== audit gate (expected exit 1) =="
  moon run cmd/kdbx -- audit $database --format json --fail-on-findings
  if ($LASTEXITCODE -ne 1) { throw "audit gate did not return exit 1" }
  $global:LASTEXITCODE = 0

  Write-Host "`n== export (passwords redacted) =="
  moon run cmd/kdbx -- export $database --format json
  if ($LASTEXITCODE -ne 0) { throw "export failed" }
}
finally {
  Remove-Item Env:\KDBX_PASSWORD -ErrorAction SilentlyContinue
  Pop-Location
}
