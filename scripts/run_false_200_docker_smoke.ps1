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
function Save-Environment([string[]]$Names) { $saved = @{}; foreach ($name in $Names) { $item = Get-Item "Env:$name" -ErrorAction SilentlyContinue; $saved[$name] = if ($null -eq $item) { $null } else { $item.Value } }; return $saved }
function Restore-Environment($Saved) { foreach ($name in $Saved.Keys) { if ($null -eq $Saved[$name]) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue } else { Set-Item "Env:$name" $Saved[$name] } } }
function New-EventToken([string]$Name) {
    $created = @(& docker compose exec --no-TTY api python -m flowproof.identity create-service-account --name $Name --scope events:write)
    if ($LASTEXITCODE -ne 0) { throw 'demo service account creation failed' }
    $principal = ($created | Select-Object -Last 1 | ConvertFrom-Json).principal
    $issued = @(& docker compose exec --no-TTY api python -m flowproof.identity issue-token --principal-id $principal.id --scope events:write --expires-in-seconds 600)
    if ($LASTEXITCODE -ne 0) { throw 'demo credential issue failed' }
    return ($issued | Select-Object -Last 1 | ConvertFrom-Json).token
}

$suffix = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$project = "flowproof-demo-$suffix"
$names = @('COMPOSE_PROJECT_NAME', 'FLOWPROOF_TOKEN_PEPPER', 'FLOWPROOF_ENABLE_LEGACY_HEADER_AUTH', 'FLOWPROOF_DEMO_EVENT_TOKEN', 'FLOWPROOF_DEMO_ADMIN_NAME', 'FLOWPROOF_DEMO_ADMIN_PASSWORD')
$saved = Save-Environment $names
$scenarioPassed = $false
try {
    $env:COMPOSE_PROJECT_NAME = $project
    $env:FLOWPROOF_TOKEN_PEPPER = New-RandomBase64 48
    $env:FLOWPROOF_ENABLE_LEGACY_HEADER_AUTH = 'false'
    $env:FLOWPROOF_DEMO_ADMIN_NAME = 'false-200-demo-admin'
    $env:FLOWPROOF_DEMO_ADMIN_PASSWORD = New-RandomBase64 32
    & docker compose up --build --detach postgres mock-accounting api scheduler
    if ($LASTEXITCODE -ne 0) { throw 'false-200 smoke Compose startup failed' }
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        try { & docker compose exec --no-TTY api python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" 2>$null; if ($LASTEXITCODE -eq 0) { break } } catch {}
        if ($attempt -eq 20) { throw 'false-200 smoke API did not become ready' }
        Start-Sleep -Seconds 2
    }
    $env:FLOWPROOF_DEMO_ADMIN_PASSWORD | & docker compose exec --no-TTY api python -m flowproof.identity bootstrap-admin --name $env:FLOWPROOF_DEMO_ADMIN_NAME --password-stdin | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'false-200 smoke admin bootstrap failed' }
    $env:FLOWPROOF_DEMO_EVENT_TOKEN = New-EventToken "demo-events-$suffix"
    & docker compose --profile demo run --rm demo
    if ($LASTEXITCODE -ne 0) { throw "false-200 demo failed with exit code $LASTEXITCODE" }
    $scenarioPassed = $true
}
catch {
    Write-Warning "false-200 smoke failed; collecting bounded Compose diagnostics for $project"
    & docker compose ps --all
    & docker compose logs --no-color --tail 200 api scheduler
    throw
}
finally {
    if ($env:COMPOSE_PROJECT_NAME -eq $project) {
        if ($scenarioPassed) {
            & docker compose down --volumes --remove-orphans | Out-Null
        }
        else {
            & docker compose down --remove-orphans | Out-Null
        }
    }
    Restore-Environment $saved
}
