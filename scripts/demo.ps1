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

  $env:KDBX_PASSWORD = "Interop-2026!Strong"
  $cases = @(
    @{File="examples/interop/argon2id-aes.kdbx"; Kdf="Argon2id"; Cipher="AES-256-CBC"; Title="Argon2id AES"},
    @{File="examples/interop/argon2d-chacha20.kdbx"; Kdf="Argon2d"; Cipher="ChaCha20"; Title="ChaCha20"}
  )
  foreach ($case in $cases) {
    Write-Host "`n== interop: $($case.Kdf) + $($case.Cipher) =="
    $info = moon run cmd/kdbx -- info $case.File 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "info failed for $($case.File)" }
    if (-not $info.Contains("KDF: $($case.Kdf)")) { throw "unexpected KDF for $($case.File)" }
    if (-not $info.Contains("Cipher: $($case.Cipher)")) { throw "unexpected cipher for $($case.File)" }
    $shown = moon run cmd/kdbx -- show $case.File $case.Title 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "show failed for $($case.File)" }
    if (-not $shown.Contains("Title: $($case.Title)")) { throw "entry missing from $($case.File)" }
  }
}
finally {
  Remove-Item Env:\KDBX_PASSWORD -ErrorAction SilentlyContinue
  Pop-Location
}
