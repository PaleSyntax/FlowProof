[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root 'backend\.venv\Scripts\python.exe'
$composeFiles = @('-f', (Join-Path $root 'docker-compose.yml'), '-f', (Join-Path $root 'docker-compose.scheduler-restart-smoke.yml'))
$runSuffix = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$project = "flowproof-restart-$runSuffix"
$previousEnvironment = @{}
$environmentNames = @(
    'COMPOSE_PROJECT_NAME',
    'POSTGRES_DB',
    'POSTGRES_USER',
    'POSTGRES_PASSWORD',
    'FLOWPROOF_SCHEDULER_SMOKE_TOKEN',
    'FLOWPROOF_TOKEN_PEPPER',
    'FLOWPROOF_ENABLE_LEGACY_HEADER_AUTH',
    'FLOWPROOF_SCHEDULER_POLL_SECONDS',
    'FLOWPROOF_SCHEDULER_LEASE_SECONDS',
    'FLOWPROOF_SCHEDULER_MAX_ATTEMPTS',
    'FLOWPROOF_SCHEDULER_RETRY_BASE_SECONDS',
    'FLOWPROOF_SMOKE_CORRELATION_ID',
    'FLOWPROOF_SMOKE_INVOICE_ID'
)

function Invoke-Compose {
    param([string[]]$ComposeArgs)
    & docker compose @composeFiles @ComposeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose $($ComposeArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Assert-FreePort {
    param([int]$Port)
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Start()
    }
    catch {
        throw "required local port $Port is unavailable"
    }
    finally {
        $listener.Stop()
    }
}

function Wait-Healthy {
    param([string]$Url, [string]$Name)
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2
            if ($response.StatusCode -eq 200) { return }
        }
        catch {
            if ($attempt -eq 30) { throw "$Name did not become healthy" }
        }
        Start-Sleep -Seconds 1
    }
}

function Scheduler-Inspect {
    param([string]$Format)
    $containerId = ((@(& docker compose @composeFiles ps --all --quiet scheduler) -join '')).Trim()
    if (-not $containerId) { throw 'scheduler container ID was not found' }
    $value = (& docker inspect --format $Format $containerId).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'docker inspect scheduler failed' }
    return $value
}

function Wait-SchedulerRunning {
    param([int]$MinimumRestartCount)
    for ($attempt = 1; $attempt -le 20; $attempt++) {
        $parts = (Scheduler-Inspect '{{.State.Running}} {{.RestartCount}} {{.HostConfig.RestartPolicy.Name}}') -split '\s+'
        if ($parts.Count -eq 3 -and $parts[0] -eq 'true' -and [int]$parts[1] -gt $MinimumRestartCount -and $parts[2] -eq 'unless-stopped') {
            return [int]$parts[1]
        }
        Start-Sleep -Seconds 1
    }
    throw 'scheduler did not restart after a process crash'
}

function Restore-Environment {
    foreach ($name in $environmentNames) {
        if ($previousEnvironment.ContainsKey($name) -and $null -ne $previousEnvironment[$name]) {
            Set-Item -Path "Env:$name" -Value $previousEnvironment[$name]
        }
        else {
            Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
        }
    }
}

function New-ServiceToken {
    $name = "scheduler-smoke-$runSuffix"
    $scopes = @('events:write', 'read:operations', 'chaos:write')
    $createArgs = @('exec', '--no-TTY', 'api', 'python', '-m', 'flowproof.identity', 'create-service-account', '--name', $name)
    foreach ($scope in $scopes) { $createArgs += @('--scope', $scope) }
    $created = @(& docker compose @composeFiles @createArgs)
    if ($LASTEXITCODE -ne 0) { throw 'scheduler smoke service account creation failed' }
    $principal = ($created | Select-Object -Last 1 | ConvertFrom-Json).principal
    $issueArgs = @('exec', '--no-TTY', 'api', 'python', '-m', 'flowproof.identity', 'issue-token', '--principal-id', $principal.id)
    foreach ($scope in $scopes) { $issueArgs += @('--scope', $scope) }
    $issued = @(& docker compose @composeFiles @issueArgs)
    if ($LASTEXITCODE -ne 0) { throw 'scheduler smoke credential issue failed' }
    return ($issued | Select-Object -Last 1 | ConvertFrom-Json).token
}

Set-Location $root
foreach ($name in $environmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

try {
    & docker info --format '{{.ServerVersion}}' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Docker daemon is unavailable' }
    if (-not (Test-Path -LiteralPath $python)) { throw 'backend virtual environment is missing' }
    foreach ($port in @(8000, 8001)) { Assert-FreePort $port }

    $env:COMPOSE_PROJECT_NAME = $project
    $env:POSTGRES_DB = "flowproof_$runSuffix"
    $env:POSTGRES_USER = "flowproof_$runSuffix"
    $env:POSTGRES_PASSWORD = [Guid]::NewGuid().ToString('N')
    $pepperBytes = New-Object byte[] 48
    $pepperRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $pepperRng.GetBytes($pepperBytes) } finally { $pepperRng.Dispose() }
    $env:FLOWPROOF_TOKEN_PEPPER = [Convert]::ToBase64String($pepperBytes)
    $env:FLOWPROOF_ENABLE_LEGACY_HEADER_AUTH = 'false'
    $env:FLOWPROOF_SCHEDULER_POLL_SECONDS = '0.2'
    $env:FLOWPROOF_SCHEDULER_LEASE_SECONDS = '10'
    $env:FLOWPROOF_SCHEDULER_MAX_ATTEMPTS = '3'
    $env:FLOWPROOF_SCHEDULER_RETRY_BASE_SECONDS = '1'
    $env:FLOWPROOF_SMOKE_CORRELATION_ID = "scheduler-restart-$runSuffix"
    $env:FLOWPROOF_SMOKE_INVOICE_ID = "INV-RESTART-$($runSuffix.ToUpperInvariant())"

    Invoke-Compose @('up', '--build', '--detach', 'postgres', 'mock-accounting', 'api', 'scheduler') | Out-Null
    Wait-Healthy 'http://127.0.0.1:8001/health' 'Mock Accounting'
    Wait-Healthy 'http://127.0.0.1:8000/health' 'FlowProof API'
    $env:FLOWPROOF_SCHEDULER_SMOKE_TOKEN = New-ServiceToken

    $supervision = Scheduler-Inspect '{{.State.Running}} {{.RestartCount}} {{.HostConfig.RestartPolicy.Name}}'
    $parts = $supervision -split '\s+'
    if ($parts.Count -ne 3 -or $parts[0] -ne 'true' -or $parts[2] -ne 'unless-stopped') {
        throw 'scheduler Compose supervision policy is not active'
    }
    $restartCount = [int]$parts[1]
    $restartCount = Wait-SchedulerRunning $restartCount

    Invoke-Compose @('stop', 'scheduler') | Out-Null
    Start-Sleep -Seconds 1
    $stopped = Scheduler-Inspect '{{.State.Running}} {{.RestartCount}}'
    if ($stopped -ne "false $restartCount") {
        throw 'explicit docker compose stop did not remain an operator-controlled scheduler stop'
    }

    & $python (Join-Path $root 'scripts\scheduler_restart_smoke.py') --phase seed | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'restart smoke seeding failed' }

    Invoke-Compose @('stop', 'scheduler') | Out-Null
    Start-Sleep -Seconds 1
    $contentionSchedulerRunning = Scheduler-Inspect '{{.State.Running}}'
    if ($contentionSchedulerRunning -ne 'false') {
        throw 'scheduler must be stopped before the isolated PostgreSQL contention proof'
    }

    $contentionRaw = @(& docker compose @composeFiles exec --no-TTY api python /app/scripts/scheduler_restart_smoke.py --phase postgres-contention)
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL scheduler contention proof failed' }
    $contention = ($contentionRaw -join "`n") | ConvertFrom-Json
    if ($contention.worker_count -ne 2) {
        throw 'PostgreSQL scheduler contention proof did not run exactly two workers'
    }

    Start-Sleep -Seconds 31
    Invoke-Compose @('start', 'scheduler') | Out-Null
    $contentionSchedulerRestarted = Scheduler-Inspect '{{.State.Running}}'
    if ($contentionSchedulerRestarted -ne 'true') {
        throw 'scheduler did not restart after the isolated PostgreSQL contention proof'
    }

    & $python (Join-Path $root 'scripts\scheduler_restart_smoke.py') --phase restarted | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'restart smoke did not process its persisted due job' }

    Invoke-Compose @('restart', 'scheduler') | Out-Null
    $restartRaw = @(& $python (Join-Path $root 'scripts\scheduler_restart_smoke.py') --phase stable)
    if ($LASTEXITCODE -ne 0) { throw 'second scheduler restart duplicated work' }
    $restart = ($restartRaw -join "`n") | ConvertFrom-Json

    [ordered]@{
        runner = 'passed'
        compose_project = "$($project.Substring(0, [Math]::Min($project.Length, 24)))..."
        restart_policy = 'unless-stopped'
        crash_restart_count = $restartCount
        explicit_stop = 'remained_stopped'
        restart_proof = $restart
        contention_compose_scheduler_state = 'stopped'
        contention_worker_count = $contention.worker_count
        contention_claims = $contention.worker_claims
        postgres_contention = $contention
        cleanup = 'containers_and_network_only; isolated_volumes_retained'
    } | ConvertTo-Json -Depth 6
}
finally {
    if ($env:COMPOSE_PROJECT_NAME -eq $project) {
        & docker compose @composeFiles down --remove-orphans | Out-Null
    }
    Restore-Environment
}
