Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:ModuleRoot = Split-Path -Parent $PSCommandPath
$script:ComposeFile = Join-Path $script:ModuleRoot "docker-compose.appliance.yml"
$script:ManifestFile = Join-Path $script:ModuleRoot "appliance-manifest.json"
$script:ProjectName = "flowproof-appliance"
$script:DashboardUrl = "http://127.0.0.1:8080"
$script:ReadyUrl = "http://127.0.0.1:8000/health/ready"

function Resolve-FlowProofDataRoot {
    [CmdletBinding()]
    param([string]$DataRoot)

    if ([string]::IsNullOrWhiteSpace($DataRoot)) {
        $DataRoot = Join-Path $env:LOCALAPPDATA "FlowProof"
    }
    if (-not [IO.Path]::IsPathRooted($DataRoot)) {
        throw "The FlowProof data folder must be an absolute Windows path."
    }
    $full = [IO.Path]::GetFullPath($DataRoot).TrimEnd('\')
    $volumeRoot = [IO.Path]::GetPathRoot($full).TrimEnd('\')
    if ($full -eq $volumeRoot -or $full.Length -le $volumeRoot.Length + 2) {
        throw "The FlowProof data folder cannot be a drive root or a broad system path."
    }
    return $full
}

function Get-FlowProofLayout {
    [CmdletBinding()]
    param([string]$DataRoot)

    $root = Resolve-FlowProofDataRoot $DataRoot
    return [pscustomobject]@{
        Root = $root
        Secrets = Join-Path $root "secrets"
        Postgres = Join-Path $root "postgres"
        Backups = Join-Path $root "backups"
        Diagnostics = Join-Path $root "diagnostics"
        State = Join-Path $root "appliance-state.json"
        Environment = Join-Path $root "appliance.env"
    }
}

function New-FlowProofRandomSecret {
    [CmdletBinding()]
    param([ValidateRange(32, 128)][int]$ByteCount = 48)

    $bytes = New-Object byte[] $ByteCount
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
        return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
    finally {
        $rng.Dispose()
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
}

function Write-FlowProofUtf8Text {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Value)
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Value, $encoding)
}

function Set-FlowProofPrivateDirectoryAcl {
    param([Parameter(Mandatory)][string]$Path)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $grants = @(("*{0}:(OI)(CI)F" -f $sid), "*S-1-5-18:(OI)(CI)F")
    $output = & icacls.exe $Path /inheritance:r /grant:r $grants /Q 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "FlowProof could not protect the local secret folder ACL: $($output -join ' ')"
    }
}

function Get-FlowProofManifest {
    return Get-Content -Raw -Encoding UTF8 $script:ManifestFile | ConvertFrom-Json
}

function Import-FlowProofBundledImages {
    [CmdletBinding()]
    param()

    $manifest = Get-FlowProofManifest
    $missing = @()
    foreach ($image in @($manifest.images.PSObject.Properties.Value)) {
        $result = Invoke-FlowProofNativeDocker @("image", "inspect", $image)
        if ($result.ExitCode -ne 0) { $missing += $image }
    }
    if ($missing.Count -eq 0) {
        return [pscustomobject]@{ Loaded = $false; MissingBeforeLoad = @() }
    }
    if ($null -eq $manifest.image_bundle -or
        [string]::IsNullOrWhiteSpace($manifest.image_bundle.filename)) {
        throw "Required FlowProof images are missing and this development directory has no bundled image archive."
    }
    $archive = Join-Path $script:ModuleRoot $manifest.image_bundle.filename
    if (-not [IO.File]::Exists($archive)) {
        throw "The bundled FlowProof image archive is missing. Download the complete Windows asset again."
    }
    $actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    if ($actualSha256 -cne $manifest.image_bundle.sha256) {
        throw "The bundled FlowProof image archive checksum is invalid. Download the asset again."
    }
    Invoke-FlowProofDocker @("image", "load", "--input", $archive) | Out-Null
    foreach ($image in @($manifest.images.PSObject.Properties.Value)) {
        $result = Invoke-FlowProofNativeDocker @("image", "inspect", $image)
        if ($result.ExitCode -ne 0) {
            throw "The bundled image load completed without the required image $image."
        }
    }
    return [pscustomobject]@{ Loaded = $true; MissingBeforeLoad = $missing }
}

function New-FlowProofApplianceConfiguration {
    [CmdletBinding()]
    param(
        [string]$DataRoot,
        [switch]$SkipAcl
    )

    $layout = Get-FlowProofLayout $DataRoot
    foreach ($directory in @(
        $layout.Root, $layout.Secrets, $layout.Postgres, $layout.Backups, $layout.Diagnostics
    )) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
    }
    if (-not $SkipAcl) {
        Set-FlowProofPrivateDirectoryAcl $layout.Secrets
    }

    $secretFiles = @{
        token_pepper = Join-Path $layout.Secrets "token_pepper"
        postgres_password = Join-Path $layout.Secrets "postgres_password"
    }
    foreach ($entry in $secretFiles.GetEnumerator()) {
        if (-not [IO.File]::Exists($entry.Value)) {
            $secret = New-FlowProofRandomSecret
            try {
                Write-FlowProofUtf8Text $entry.Value ($secret + [Environment]::NewLine)
            }
            finally {
                $secret = $null
            }
        }
        $length = ([IO.File]::ReadAllText($entry.Value)).Trim().Length
        if ($length -lt 32) {
            throw "The local $($entry.Key) secret is missing or shorter than 32 characters."
        }
    }

    $manifest = Get-FlowProofManifest
    $forwardSecrets = $layout.Secrets.Replace('\', '/')
    $forwardPostgres = $layout.Postgres.Replace('\', '/')
    $environmentLines = @(
        "FLOWPROOF_API_IMAGE=$($manifest.images.api)",
        "FLOWPROOF_WEB_IMAGE=$($manifest.images.web)",
        "FLOWPROOF_MOCK_IMAGE=$($manifest.images.mock_accounting)",
        "FLOWPROOF_POSTGRES_IMAGE=$($manifest.images.postgres)",
        "FLOWPROOF_SECRETS_DIR=$forwardSecrets",
        "FLOWPROOF_POSTGRES_DATA_DIR=$forwardPostgres"
    )
    Write-FlowProofUtf8Text $layout.Environment (($environmentLines -join "`n") + "`n")
    return $layout
}

function Get-FlowProofDockerPath {
    $candidate = Join-Path $env:ProgramFiles "Docker\Docker\resources\bin\docker.exe"
    if ([IO.File]::Exists($candidate)) {
        return $candidate
    }
    $command = Get-Command docker.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }
    return $null
}

function ConvertTo-FlowProofSafeMessage {
    param([object[]]$Lines)
    $text = ($Lines | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
    return $text -replace '(?i)(password|token|authorization|secret)\s*[:=]\s*\S+', '$1=[redacted]'
}

function Invoke-FlowProofNativeDocker {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $docker = Get-FlowProofDockerPath
    if ([string]::IsNullOrWhiteSpace($docker)) {
        return [pscustomobject]@{
            ExitCode = 127
            Output = @("Docker Desktop is not installed.")
        }
    }
    $previousPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 wraps native stderr lines as non-terminating
        # ErrorRecord objects. Docker writes normal progress there, so success
        # must be decided from the native exit code instead of the stream.
        $ErrorActionPreference = "Continue"
        $output = @(& $docker @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = $output
    }
}

function Invoke-FlowProofDocker {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$Arguments)

    $result = Invoke-FlowProofNativeDocker $Arguments
    if ($result.ExitCode -eq 127) {
        throw "Docker Desktop is not installed. Install Docker Desktop, then reopen FlowProof."
    }
    if ($result.ExitCode -ne 0) {
        $tail = @($result.Output | Select-Object -Last 20)
        throw ("Docker operation failed. " + (ConvertTo-FlowProofSafeMessage $tail))
    }
    return $result.Output
}

function Invoke-FlowProofCompose {
    [CmdletBinding()]
    param(
        [string]$DataRoot,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $layout = Get-FlowProofLayout $DataRoot
    if (-not [IO.File]::Exists($layout.Environment)) {
        throw "FlowProof is not configured in the selected data folder."
    }
    $composeArguments = @(
        "compose", "--project-name", $script:ProjectName,
        "--env-file", $layout.Environment,
        "--file", $script:ComposeFile
    ) + $Arguments
    return Invoke-FlowProofDocker $composeArguments
}

function Test-FlowProofPrerequisites {
    [CmdletBinding()]
    param()

    $docker = Get-FlowProofDockerPath
    if ([string]::IsNullOrWhiteSpace($docker)) {
        return [pscustomobject]@{
            Ready = $false
            Code = "DOCKER_DESKTOP_MISSING"
            Message = "Docker Desktop is required for this FlowProof delivery model."
            NextAction = "Install Docker Desktop for Windows, restart Windows if requested, then reopen FlowProof."
        }
    }
    $statusResult = Invoke-FlowProofNativeDocker @("desktop", "status")
    if ($statusResult.ExitCode -ne 0 -or (($statusResult.Output -join ' ') -notmatch 'running')) {
        return [pscustomobject]@{
            Ready = $false
            Code = "DOCKER_DESKTOP_NOT_RUNNING"
            Message = "Docker Desktop is installed but its Linux engine is not ready."
            NextAction = "Start Docker Desktop, wait until it reports Running, then choose Refresh."
        }
    }
    $composeResult = Invoke-FlowProofNativeDocker @("compose", "version", "--short")
    if ($composeResult.ExitCode -ne 0) {
        return [pscustomobject]@{
            Ready = $false
            Code = "DOCKER_COMPOSE_MISSING"
            Message = "Docker Compose is unavailable."
            NextAction = "Update Docker Desktop, then reopen FlowProof."
        }
    }
    return [pscustomobject]@{
        Ready = $true
        Code = "READY"
        Message = "Docker Desktop and Compose are ready."
        NextAction = "Continue with FlowProof setup."
        ComposeVersion = ($composeResult.Output -join '').Trim()
    }
}

function Invoke-FlowProofAdminBootstrap {
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [Parameter(Mandatory)][string]$AdminName,
        [Parameter(Mandatory)][Security.SecureString]$AdminPassword
    )
    if ([string]::IsNullOrWhiteSpace($AdminName) -or $AdminName.Trim().Length -gt 128) {
        throw "Administrator name must contain between 1 and 128 characters."
    }
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        if ($plain.Length -lt 12 -or $plain.Length -gt 1024 -or $plain.Contains("`n")) {
            throw "Administrator password must contain between 12 and 1024 characters."
        }
        $layout = Get-FlowProofLayout $DataRoot
        $docker = Get-FlowProofDockerPath
        $arguments = @(
            "compose", "--project-name", $script:ProjectName,
            "--env-file", $layout.Environment,
            "--file", $script:ComposeFile,
            "exec", "-T", "api", "python", "-m", "flowproof.identity",
            "bootstrap-admin", "--name", $AdminName.Trim(), "--password-stdin"
        )
        $previousPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $output = @($plain | & $docker @arguments 2>&1)
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $previousPreference
        }
        if ($exitCode -ne 0) {
            throw ("Administrator setup failed. " + (ConvertTo-FlowProofSafeMessage $output))
        }
    }
    finally {
        $plain = $null
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Write-FlowProofState {
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [string]$PreviousApplicationVersion,
        [string]$UpdateBackup
    )
    $layout = Get-FlowProofLayout $DataRoot
    $manifest = Get-FlowProofManifest
    $installedAt = (Get-Date).ToUniversalTime().ToString('o')
    if ([IO.File]::Exists($layout.State)) {
        try {
            $existingState = Get-Content -Raw -Encoding UTF8 $layout.State | ConvertFrom-Json
            if (-not [string]::IsNullOrWhiteSpace($existingState.installed_at)) {
                $installedAt = $existingState.installed_at
            }
        }
        catch { }
    }
    $state = [ordered]@{
        schema_version = "1.0"
        project_name = $script:ProjectName
        application_version = $manifest.application_version
        artifact_status = $manifest.artifact_status
        git_commit = $manifest.git_commit
        git_tree = $manifest.git_tree
        evidence_classification = $manifest.evidence_classification
        data_root = $layout.Root.Replace('\', '/')
        installed_at = $installedAt
    }
    if (-not [string]::IsNullOrWhiteSpace($PreviousApplicationVersion)) {
        $state.previous_application_version = $PreviousApplicationVersion
        $state.updated_at = (Get-Date).ToUniversalTime().ToString('o')
        $state.update_backup = $UpdateBackup.Replace('\', '/')
    }
    Write-FlowProofUtf8Text $layout.State (($state | ConvertTo-Json -Depth 4) + "`n")
}

function Wait-FlowProofReady {
    [CmdletBinding()]
    param([ValidateRange(10, 300)][int]$TimeoutSeconds = 120)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $script:ReadyUrl -TimeoutSec 5
            if ($response.StatusCode -eq 200) { return }
        }
        catch { }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "FlowProof did not become ready within $TimeoutSeconds seconds. Export diagnostics for details."
}

function Invoke-FlowProofMigration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DataRoot,
        [ValidateRange(1, 30)][int]$MaxAttempts = 12,
        [ValidateRange(1, 10)][int]$RetryDelaySeconds = 2
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Invoke-FlowProofCompose $DataRoot @("run", "--rm", "migrate") | Out-Null
            return
        }
        catch {
            $message = $_.Exception.Message
            $transientConnectionFailure = $message -match (
                '(?i)(connection refused|connection failed|could not connect|' +
                'server closed the connection unexpectedly)'
            )
            if (-not $transientConnectionFailure -or $attempt -eq $MaxAttempts) {
                throw
            }
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}

function Initialize-FlowProofAppliance {
    [CmdletBinding()]
    param(
        [string]$DataRoot,
        [Parameter(Mandatory)][string]$AdminName,
        [Parameter(Mandatory)][Security.SecureString]$AdminPassword
    )
    $prerequisite = Test-FlowProofPrerequisites
    if (-not $prerequisite.Ready) {
        throw "$($prerequisite.Message) $($prerequisite.NextAction)"
    }
    Import-FlowProofBundledImages | Out-Null
    $layout = New-FlowProofApplianceConfiguration $DataRoot
    Invoke-FlowProofCompose $layout.Root @("config", "--quiet") | Out-Null
    Invoke-FlowProofCompose $layout.Root @("up", "-d", "--wait", "postgres", "mock-accounting") | Out-Null
    Invoke-FlowProofMigration -DataRoot $layout.Root
    Invoke-FlowProofCompose $layout.Root @(
        "up", "-d", "--wait", "api", "scheduler", "alert-worker", "ops-watcher", "web"
    ) | Out-Null
    Wait-FlowProofReady
    Invoke-FlowProofAdminBootstrap $layout.Root $AdminName $AdminPassword
    Write-FlowProofState $layout.Root
    return Get-FlowProofStatus $layout.Root
}

function Get-FlowProofStatus {
    [CmdletBinding()]
    param([string]$DataRoot)
    $layout = Get-FlowProofLayout $DataRoot
    $prerequisite = Test-FlowProofPrerequisites
    if (-not $prerequisite.Ready -or -not [IO.File]::Exists($layout.Environment)) {
        return [pscustomobject]@{
            Installed = [IO.File]::Exists($layout.State)
            ServiceHealth = "NOT_READY"
            Prerequisite = $prerequisite
            OutcomeTruth = "OPEN_FLOWPROOF_FOR_EVIDENCE"
        }
    }
    try {
        $services = @(Invoke-FlowProofCompose $layout.Root @("ps", "--format", "json"))
        $ready = $false
        try {
            $ready = (Invoke-WebRequest -UseBasicParsing -Uri $script:ReadyUrl -TimeoutSec 3).StatusCode -eq 200
        }
        catch { }
        return [pscustomobject]@{
            Installed = [IO.File]::Exists($layout.State)
            ServiceHealth = $(if ($ready) { "READY" } else { "NOT_READY" })
            Prerequisite = $prerequisite
            Services = $services
            OutcomeTruth = "OPEN_FLOWPROOF_FOR_EVIDENCE"
        }
    }
    catch {
        return [pscustomobject]@{
            Installed = [IO.File]::Exists($layout.State)
            ServiceHealth = "NOT_READY"
            Prerequisite = $prerequisite
            Error = $_.Exception.Message
            OutcomeTruth = "OPEN_FLOWPROOF_FOR_EVIDENCE"
        }
    }
}

function Start-FlowProofAppliance {
    [CmdletBinding()]
    param([string]$DataRoot)
    Invoke-FlowProofCompose $DataRoot @(
        "up", "-d", "--wait", "api", "scheduler", "alert-worker", "ops-watcher", "web"
    ) | Out-Null
    Wait-FlowProofReady
    return Get-FlowProofStatus $DataRoot
}

function Stop-FlowProofAppliance {
    [CmdletBinding()]
    param([string]$DataRoot)
    Invoke-FlowProofCompose $DataRoot @("stop") | Out-Null
    return Get-FlowProofStatus $DataRoot
}

function Restart-FlowProofAppliance {
    [CmdletBinding()]
    param([string]$DataRoot)
    $longRunningServices = @("api", "scheduler", "alert-worker", "ops-watcher", "web")
    Invoke-FlowProofCompose $DataRoot (@("restart") + $longRunningServices) | Out-Null
    Invoke-FlowProofCompose $DataRoot (@("up", "-d", "--wait") + $longRunningServices) | Out-Null
    Wait-FlowProofReady
    return Get-FlowProofStatus $DataRoot
}

function Open-FlowProofDashboard {
    Start-Process $script:DashboardUrl
}

Export-ModuleMember -Function @(
    "Resolve-FlowProofDataRoot",
    "Get-FlowProofLayout",
    "New-FlowProofRandomSecret",
    "New-FlowProofApplianceConfiguration",
    "Get-FlowProofDockerPath",
    "Invoke-FlowProofDocker",
    "Invoke-FlowProofCompose",
    "Test-FlowProofPrerequisites",
    "Import-FlowProofBundledImages",
    "Write-FlowProofState",
    "Wait-FlowProofReady",
    "Invoke-FlowProofMigration",
    "Initialize-FlowProofAppliance",
    "Get-FlowProofStatus",
    "Start-FlowProofAppliance",
    "Stop-FlowProofAppliance",
    "Restart-FlowProofAppliance",
    "Open-FlowProofDashboard"
)
