[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root 'backend\.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    throw 'Expected backend virtual environment launcher is missing.'
}
Push-Location $root
try {
    & $python 'scripts/production_deployment_smoke.py'
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
