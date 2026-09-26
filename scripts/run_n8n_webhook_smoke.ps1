[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$smokePython = $env:FLOWPROOF_SMOKE_PYTHON
if ([string]::IsNullOrWhiteSpace($smokePython)) {
    $smokePython = Join-Path $root 'backend\.venv\Scripts\python.exe'
}
if (-not (Test-Path -LiteralPath $smokePython -PathType Leaf)) {
    throw "FlowProof smoke Python was not found: $smokePython"
}

function New-RandomBase64([int]$ByteCount) {
    $bytes = New-Object byte[] $ByteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return [Convert]::ToBase64String($bytes)
}
function Save-Environment([string[]]$Names) {
    $saved = @{}
    foreach ($name in $Names) { $item = Get-Item "Env:$name" -ErrorAction SilentlyContinue; $saved[$name] = if ($null -eq $item) { $null } else { $item.Value } }
    return $saved
}
function Restore-Environment($Saved) {
    foreach ($name in $Saved.Keys) { if ($null -eq $Saved[$name]) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue } else { Set-Item "Env:$name" $Saved[$name] } }
}
function Invoke-Compose { param([string[]]$ComposeArgs); & docker compose --profile n8n @ComposeArgs; if ($LASTEXITCODE -ne 0) { throw "docker compose $($ComposeArgs -join ' ') failed" } }
function Test-N8nReady {
    & docker compose --profile n8n exec --no-TTY n8n node -e "fetch('http://127.0.0.1:5678/healthz').then((response) => { if (!response.ok) { process.exit(1) } }).catch(() => process.exit(1))" 2>$null
    return $LASTEXITCODE -eq 0
}
function Wait-N8nReady {
    for ($attempt = 1; $attempt -le 45; $attempt++) {
        if (Test-N8nReady) { return }
        if ($attempt -eq 45) { throw 'n8n did not become HTTP-ready within 90 seconds' }
        Start-Sleep -Seconds 2
    }
}
function New-N8nToken([string]$Name) {
    $scopes = @('events:write', 'recovery:execute', 'recovery:verify')
    $create = @('exec', '--no-TTY', 'api', 'python', '-m', 'flowproof.identity', 'create-service-account', '--name', $Name)
    foreach ($scope in $scopes) { $create += @('--scope', $scope) }
    $created = @(& docker compose --profile n8n @create)
    if ($LASTEXITCODE -ne 0) { throw 'n8n service account creation failed' }
    $principal = ($created | Select-Object -Last 1 | ConvertFrom-Json).principal
    $issue = @('exec', '--no-TTY', 'api', 'python', '-m', 'flowproof.identity', 'issue-token', '--principal-id', $principal.id)
    foreach ($scope in $scopes) { $issue += @('--scope', $scope) }
    $issued = @(& docker compose --profile n8n @issue)
    if ($LASTEXITCODE -ne 0) { throw 'n8n credential issue failed' }
    return ($issued | Select-Object -Last 1 | ConvertFrom-Json).token
}
function Install-N8nCredential([string]$Token) {
    $nodeScript = @'
const fs = require('fs');
const token = process.env.FLOWPROOF_PROVISION_TOKEN;
if (!/^[A-Za-z0-9._~-]{24,}$/.test(token || '')) process.exit(2);
fs.writeFileSync('/tmp/flowproof-api-service-account.json', JSON.stringify([{
  id: 'flowproof-api-service-account',
  name: 'FlowProof API service account',
  type: 'httpHeaderAuth',
  data: { name: 'Authorization', value: `Bearer ${token}` }
}]));
'@
    try {
        & docker compose --profile n8n exec --no-TTY -e "FLOWPROOF_PROVISION_TOKEN=$Token" n8n node -e $nodeScript
        if ($LASTEXITCODE -ne 0) { throw 'temporary n8n credential rendering failed' }
        Invoke-Compose @('exec', '--no-TTY', 'n8n', 'n8n', 'import:credentials', '--input=/tmp/flowproof-api-service-account.json')
    }
    finally {
        & docker compose --profile n8n exec --no-TTY n8n rm -f /tmp/flowproof-api-service-account.json 2>$null
    }
}
function Test-N8nMigrationsComplete {
    $logs = @(& docker compose --profile n8n logs --no-color --tail 80 n8n 2>$null)
    if ($LASTEXITCODE -ne 0) { return $false }
    return [bool]($logs -match 'Instance registered')
}
function Wait-N8nMigrationsComplete {
    for ($attempt = 1; $attempt -le 60; $attempt++) {
        if (Test-N8nMigrationsComplete) { return }
        if ($attempt -eq 60) { throw 'n8n did not finish startup migrations within 120 seconds' }
        Start-Sleep -Seconds 2
    }
}

$suffix = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$project = "flowproof-n8n-$suffix"
$adminName = "n8n-smoke-admin"
$operatorName = "n8n-smoke-operator"
$names = @('COMPOSE_PROJECT_NAME', 'FLOWPROOF_TOKEN_PEPPER', 'FLOWPROOF_ENABLE_LEGACY_HEADER_AUTH', 'FLOWPROOF_N8N_SMOKE_TOKEN', 'FLOWPROOF_N8N_SMOKE_ADMIN_NAME', 'FLOWPROOF_N8N_SMOKE_ADMIN_PASSWORD', 'FLOWPROOF_N8N_SMOKE_OPERATOR_NAME', 'FLOWPROOF_N8N_SMOKE_OPERATOR_PASSWORD')
$saved = Save-Environment $names

try {
    $env:COMPOSE_PROJECT_NAME = $project
    $env:FLOWPROOF_TOKEN_PEPPER = New-RandomBase64 48
    $env:FLOWPROOF_ENABLE_LEGACY_HEADER_AUTH = 'false'
    $env:FLOWPROOF_N8N_SMOKE_ADMIN_NAME = $adminName
    $env:FLOWPROOF_N8N_SMOKE_ADMIN_PASSWORD = New-RandomBase64 32
    $env:FLOWPROOF_N8N_SMOKE_OPERATOR_NAME = $operatorName
    $env:FLOWPROOF_N8N_SMOKE_OPERATOR_PASSWORD = New-RandomBase64 32
    Invoke-Compose @('up', '--build', '--detach', 'postgres', 'mock-accounting', 'api', 'scheduler')
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        try { & docker compose --profile n8n exec --no-TTY api python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" 2>$null; if ($LASTEXITCODE -eq 0) { break } } catch {}
        if ($attempt -eq 20) { throw 'FlowProof API did not become ready within 40 seconds' }
        Start-Sleep -Seconds 2
    }
    $env:FLOWPROOF_N8N_SMOKE_ADMIN_PASSWORD | & docker compose --profile n8n exec --no-TTY api python -m flowproof.identity bootstrap-admin --name $adminName --password-stdin | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'n8n smoke admin bootstrap failed' }
    $env:FLOWPROOF_N8N_SMOKE_TOKEN = New-N8nToken "n8n-local-$suffix"
    Invoke-Compose @('up', '--detach', 'n8n')
    Wait-N8nReady
    # n8n 2.30.5 publishes healthz before its fresh SQLite migration run is
    # complete. Its pinned startup command logs this marker only after the
    # migration ledger is durable, so no second CLI process can race it.
    Wait-N8nMigrationsComplete
    Install-N8nCredential $env:FLOWPROOF_N8N_SMOKE_TOKEN
    Invoke-Compose @('exec', '--no-TTY', 'n8n', 'n8n', 'import:workflow', '--separate', '--input=/workflows')
    $workflows = @(& docker compose --profile n8n exec --no-TTY n8n n8n list:workflow)
    foreach ($name in @('FlowProof Invoice Intake', 'FlowProof Invoice Approval', 'FlowProof Approved Invoice Recovery')) {
        $match = @($workflows | Where-Object { $_ -match "^[^|]+\|$([regex]::Escape($name))$" })
        if ($match.Count -ne 1) { throw "Expected one imported workflow named '$name', found $($match.Count)" }
        Invoke-Compose @('exec', '--no-TTY', 'n8n', 'n8n', 'publish:workflow', "--id=$($match[0].Split('|', 2)[0])")
    }
    Invoke-Compose @('restart', 'n8n')
    Wait-N8nReady
    & $smokePython "$root\scripts\n8n_webhook_smoke.py"
    if ($LASTEXITCODE -ne 0) { throw "live n8n bearer smoke failed with exit code $LASTEXITCODE" }
}
finally {
    if ($env:COMPOSE_PROJECT_NAME -eq $project) { & docker compose --profile n8n down --volumes --remove-orphans | Out-Null }
    Restore-Environment $saved
}
