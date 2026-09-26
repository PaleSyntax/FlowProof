[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function New-RandomBase64([int]$ByteCount) {
    $bytes = New-Object byte[] $ByteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes)
}

function Save-Environment([string[]]$Names) {
    $saved = @{}
    foreach ($name in $Names) {
        $item = Get-Item "Env:$name" -ErrorAction SilentlyContinue
        $saved[$name] = if ($null -eq $item) { $null } else { $item.Value }
    }
    return $saved
}

function Restore-Environment($Saved) {
    foreach ($name in $Saved.Keys) {
        if ($null -eq $Saved[$name]) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
        else { Set-Item "Env:$name" $Saved[$name] }
    }
}

$project = "flowproof-identity-$([Guid]::NewGuid().ToString('N').Substring(0, 12))"
$names = @(
    'COMPOSE_PROJECT_NAME', 'FLOWPROOF_TOKEN_PEPPER', 'FLOWPROOF_SESSION_COOKIE_SECURE',
    'FLOWPROOF_ENABLE_LEGACY_HEADER_AUTH', 'FLOWPROOF_IDENTITY_SMOKE_ADMIN_NAME',
    'FLOWPROOF_IDENTITY_SMOKE_ADMIN_PASSWORD', 'FLOWPROOF_IDENTITY_SMOKE_OPERATOR_NAME',
    'FLOWPROOF_IDENTITY_SMOKE_OPERATOR_PASSWORD'
)
$saved = Save-Environment $names
$adminName = "identity-smoke-admin"
$operatorName = "identity-smoke-operator"
$adminPassword = New-RandomBase64 32
$operatorPassword = New-RandomBase64 32

try {
    $env:COMPOSE_PROJECT_NAME = $project
    $env:FLOWPROOF_TOKEN_PEPPER = New-RandomBase64 48
    $env:FLOWPROOF_SESSION_COOKIE_SECURE = 'false'
    $env:FLOWPROOF_ENABLE_LEGACY_HEADER_AUTH = 'false'
    $env:FLOWPROOF_IDENTITY_SMOKE_ADMIN_NAME = $adminName
    $env:FLOWPROOF_IDENTITY_SMOKE_ADMIN_PASSWORD = $adminPassword
    $env:FLOWPROOF_IDENTITY_SMOKE_OPERATOR_NAME = $operatorName
    $env:FLOWPROOF_IDENTITY_SMOKE_OPERATOR_PASSWORD = $operatorPassword

    & docker compose up --build --detach postgres mock-accounting api scheduler web
    if ($LASTEXITCODE -ne 0) { throw 'identity smoke Compose startup failed' }
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        $healthy = $false
        try {
            & docker compose exec --no-TTY api python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" 2>$null
            $healthy = $LASTEXITCODE -eq 0
        } catch { $healthy = $false }
        if ($healthy) { break }
        if ($attempt -eq 20) { throw 'identity smoke API did not become ready within 40 seconds' }
        Start-Sleep -Seconds 2
    }
    $adminPassword | & docker compose exec --no-TTY api python -m flowproof.identity bootstrap-admin --name $adminName --password-stdin | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'identity smoke admin bootstrap failed' }
    & "$root\backend\.venv\Scripts\python.exe" "$root\scripts\identity_authorization_smoke.py"
    if ($LASTEXITCODE -ne 0) { throw "identity authorization smoke failed with exit code $LASTEXITCODE" }
}
finally {
    # Keep this unique project's volumes as inspectable evidence; do not touch shared volumes.
    if ($env:COMPOSE_PROJECT_NAME -eq $project) {
        & docker compose down --remove-orphans | Out-Null
    }
    Restore-Environment $saved
}
